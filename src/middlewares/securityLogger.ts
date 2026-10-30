import { Request, Response, NextFunction } from 'express';
import prisma from '../config/prisma.js';

// Cache mémoire glissant pour la protection contre la saturation des logs (Anti Log-Flooding CWE-400)
// Clé: `${ip}:${category}`, Valeur: { lastLoggedAt: number, occurrences: number }
interface ThrottleEntry {
  lastLoggedAt: number;
  occurrences: number;
}

const logThrottleMap = new Map<string, ThrottleEntry>();
const THROTTLE_WINDOW_MS = 5 * 60 * 1000; // 5 minutes entre chaque écriture en base pour la même IP/attaque
const MAX_CACHE_SIZE = 10000; // Protection mémoire Node.js

/**
 * Nettoie le cache mémoire périodiquement pour éviter toute fuite de mémoire
 */
function cleanThrottleCache(): void {
  const now = Date.now();
  for (const [key, entry] of logThrottleMap.entries()) {
    if (now - entry.lastLoggedAt > THROTTLE_WINDOW_MS * 2) {
      logThrottleMap.delete(key);
    }
  }
}

setInterval(cleanThrottleCache, 10 * 60 * 1000); // Toutes les 10 minutes

/**
 * Enregistre un incident de sécurité en base avec protection anti-saturation (Log Flooding Shield)
 */
export async function logSecurityIncident(params: {
  category: string;
  level: 'warning' | 'error' | 'critical';
  action: string;
  target: string;
  ipAddress: string;
  details: string;
  metadata?: Record<string, unknown>;
}): Promise<boolean> {
  const now = Date.now();
  const cacheKey = `${params.ipAddress}:${params.category}`;
  const existing = logThrottleMap.get(cacheKey);

  if (existing) {
    existing.occurrences += 1;
    // Si la fenêtre de 5 min n'est pas encore écoulée, on ne sature pas la base PostgreSQL
    if (now - existing.lastLoggedAt < THROTTLE_WINDOW_MS) {
      return false;
    }
    // La fenêtre est passée : on met à jour et on consignera avec le cumul d'occurrences
    existing.lastLoggedAt = now;
  } else {
    // Évite la saturation du cache mémoire
    if (logThrottleMap.size >= MAX_CACHE_SIZE) {
      logThrottleMap.clear();
    }
    logThrottleMap.set(cacheKey, { lastLoggedAt: now, occurrences: 1 });
  }

  const occurrences = existing ? existing.occurrences : 1;
  const enrichedDetails = occurrences > 1
    ? `${params.details} [${occurrences} tentatives similaires bloquées depuis cette IP]`
    : params.details;

  try {
    await prisma.log.create({
      data: {
        type: 'technical',
        level: params.level,
        user: 'Attaquant présumé (Bot/Scanner)',
        action: params.action,
        target: params.target.slice(0, 200),
        ipAddress: params.ipAddress.slice(0, 50),
        result: 'failure',
        details: enrichedDetails.slice(0, 1000),
        metadata: {
          ...params.metadata,
          category: params.category,
          blockedAttempts: occurrences,
          owaspCategory: 'A09:2021-Security-Logging-and-Monitoring-Failures',
        },
      },
    });
    return true;
  } catch (error) {
    console.error('⚠️ [Security Logger] Échec d’écriture du log de sécurité :', (error as Error).message);
    return false;
  }
}

/**
 * Patterns d'URLs et sondes typiques des scanners malveillants d'attaquants (CWE-200 / OWASP Top 10)
 */
export const SUSPICIOUS_PATH_PATTERNS: RegExp[] = [
  /\/\.env/i,
  /\/\.git/i,
  /\/\.svn/i,
  /\/\.aws/i,
  /\/wp-admin/i,
  /\/wp-login\.php/i,
  /\/xmlrpc\.php/i,
  /\/phpmyadmin/i,
  /\/pma/i,
  /\/actuator/i,
  /\/swagger/i,
  /\/api-docs/i,
  /\/cgi-bin/i,
  /\/vendor\/phpunit/i,
  /\/eval-stdin/i,
  /\/console/i,
  /\/config\.(json|yml|yaml|ini)/i,
  /\/database\.sqlite/i,
  /\/dump\.sql/i,
  /\/\.ds_store/i,
];

export const SUSPICIOUS_PAYLOAD_PATTERNS: RegExp[] = [
  /\.\.\//, // Path traversal classique ../
  /\.\.%2f/i, // Path traversal encodé
  /%00/i, // Null byte injection
  /<script\b/i, // XSS direct dans URL
  /union(\s+all)?\s+select/i, // SQL Injection basique
  /;(\s*)?(exec|system|passthru)/i, // RCE tentative
];

/**
 * Extrait l'adresse IP cliente de manière fiable
 */
export function extractClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }
  return req.ip || req.socket.remoteAddress || '127.0.0.1';
}

/**
 * Middleware Express : Détecteur d'intrusions et de sondes malveillantes (WAF léger applicatif)
 */
export function securityProbeDetector(req: Request, res: Response, next: NextFunction): void {
  const url = req.originalUrl || req.url;
  const ip = extractClientIp(req);

  // 1. Détection de sondes de chemins sensibles
  for (const pattern of SUSPICIOUS_PATH_PATTERNS) {
    if (pattern.test(url)) {
      void logSecurityIncident({
        category: 'probe_sensitive_file',
        level: 'critical',
        action: 'Sonde malveillante de fichier sensible bloquée',
        target: `${req.method} ${url}`,
        ipAddress: ip,
        details: `Tentative d'accès non autorisée à un chemin sensible (${pattern.source}) bloquée par le bouclier CleanPro.`,
        metadata: {
          userAgent: req.headers['user-agent'] || 'Inconnu',
        },
      });

      // Enregistrement immédiat dans 'page_visits' pour alimenter le compteur d'attaques réelles
      void prisma.pageVisit.create({
        data: {
          path: url.slice(0, 200),
          ipAddress: ip.slice(0, 50),
          visitorType: 'attaquant',
          label: 'Attaquant (Bot / Sonde)',
          userAgent: req.headers['user-agent'] ? String(req.headers['user-agent']).slice(0, 100) : 'Scanner / Bot',
          location: ip.startsWith('127.') || ip === '::1' ? 'Poste local (Dev)' : 'International / VPN',
          status: 403,
          details: `Tentative d'accès non autorisée à ${url.slice(0, 100)} bloquée par le WAF CleanPro.`,
        },
      }).catch((err) => {
        console.error('Erreur enregistrement page_visit attaquant :', err);
      });

      // Réponse 403 Forbidden neutre (ne divulgue aucune information interne CWE-200)
      res.status(403).json({
        success: false,
        message: 'Accès refusé par la politique de sécurité CleanPro.',
      });
      return;
    }
  }

  // 2. Détection d'injections malveillantes dans l'URL ou la requête
  for (const pattern of SUSPICIOUS_PAYLOAD_PATTERNS) {
    if (pattern.test(url)) {
      void logSecurityIncident({
        category: 'injection_attempt',
        level: 'critical',
        action: 'Tentative d’injection malveillante interceptée',
        target: `${req.method} ${url}`,
        ipAddress: ip,
        details: `Signature d'attaque détectée dans l'URL (${pattern.source}) et rejetée.`,
        metadata: {
          userAgent: req.headers['user-agent'] || 'Inconnu',
        },
      });

      // Enregistrement dans 'page_visits'
      void prisma.pageVisit.create({
        data: {
          path: url.slice(0, 200),
          ipAddress: ip.slice(0, 50),
          visitorType: 'attaquant',
          label: 'Attaquant (Injection détectée)',
          userAgent: req.headers['user-agent'] ? String(req.headers['user-agent']).slice(0, 100) : 'Script d\'attaque',
          location: ip.startsWith('127.') || ip === '::1' ? 'Poste local (Dev)' : 'International / VPN',
          status: 403,
          details: `Tentative d'injection (${pattern.source}) neutralisée.`,
        },
      }).catch((err) => {
        console.error('Erreur enregistrement page_visit injection :', err);
      });

      res.status(400).json({
        success: false,
        message: 'Requête suspecte rejetée.',
      });
      return;
    }
  }

  next();
}

