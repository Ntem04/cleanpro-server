import { Request, Response, NextFunction } from 'express';
import prisma from '../config/prisma.js';
import { extractClientIp } from './securityLogger.js';

// Cache anti-saturation pour les erreurs répétitives (ex: panne réseau de base de données)
let lastErrorLoggedTime = 0;
let suppressedErrorCount = 0;
const ERROR_LOG_INTERVAL_MS = 2000; // Max 1 écriture de bug toutes les 2 secondes

/**
 * Middleware Global de Gestion des Erreurs Express (OWASP A09 & CWE-209 / CWE-755)
 * Capture tous les bugs applicatifs non interceptés, les journalise en base,
 * et renvoie un message aseptisé au client (zéro fuite de stack trace).
 */
export function globalErrorHandler(
  err: Error & { status?: number; statusCode?: number; type?: string },
  req: Request,
  res: Response,
  _next: NextFunction
): void {
  const ip = extractClientIp(req);
  const now = Date.now();
  const errorMessage = err.message || 'Erreur interne non spécifiée';

  // 1. Gestion spécifique des erreurs de taille de charge utile (CWE-400 / HTTP 413)
  if (err.type === 'entity.too.large' || err.status === 413 || err.statusCode === 413) {
    console.warn(`⚠️ [Payload Too Large] ${req.method} ${req.originalUrl} - IP: ${ip} (Limite 10 Mo dépassée)`);
    res.status(413).json({
      success: false,
      message: 'Le fichier ou l’image transmis est trop volumineux. La taille maximale autorisée est de 10 Mo.',
      timestamp: new Date().toISOString(),
    });
    return;
  }

  // 2. Gestion des erreurs de syntaxe JSON du client (HTTP 400)
  if (err.status === 400 || err.statusCode === 400) {
    res.status(400).json({
      success: false,
      message: 'Requête mal formée (JSON syntaxe invalide).',
      timestamp: new Date().toISOString(),
    });
    return;
  }

  console.error(`💥 [Unhandled Error] ${req.method} ${req.originalUrl} - IP: ${ip} :`, err);

  // Journalisation en base de données avec protection anti-saturation (OWASP A09)
  if (now - lastErrorLoggedTime > ERROR_LOG_INTERVAL_MS) {
    lastErrorLoggedTime = now;
    const count = suppressedErrorCount;
    suppressedErrorCount = 0;

    const details = count > 0
      ? `${errorMessage} (+ ${count} erreurs similaires condensées)`
      : errorMessage;

    void prisma.log.create({
      data: {
        type: 'technical',
        level: 'error',
        user: 'Serveur Express',
        action: 'Crash applicatif non géré (Erreur 500)',
        target: `${req.method} ${req.originalUrl}`.slice(0, 200),
        ipAddress: ip.slice(0, 50),
        result: 'failure',
        details: details.slice(0, 1000),
        metadata: {
          errorName: err.name,
          // Ne conserver que les 3 premières lignes de la stack trace pour éviter d'encombrer la base
          stackSnippet: err.stack ? err.stack.split('\n').slice(0, 3).join(' | ') : undefined,
          owaspCategory: 'A09:2021-Security-Logging-and-Monitoring-Failures',
        },
      },
    }).catch((dbErr) => {
      console.error('⚠️ Impossible d’enregistrer le crash dans PostgreSQL :', (dbErr as Error).message);
    });
  } else {
    suppressedErrorCount += 1;
  }

  // Réponse sécurisée sans divulgation de détails techniques internes (CWE-209)
  res.status(500).json({
    success: false,
    message: 'Une erreur interne est survenue sur nos serveurs. L’incident a été consigné dans les journaux de sécurité.',
    timestamp: new Date().toISOString(),
  });
}

