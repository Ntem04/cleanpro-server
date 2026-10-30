import rateLimit from 'express-rate-limit';
import { sendResponse } from '../utils/apiResponse.js';
import { logSecurityIncident, extractClientIp } from './securityLogger.js';

/**
 * Limiteur de débit pour le formulaire de contact public (Protection anti-spam / anti-DoS CWE-400 / CWE-307)
 * Limite chaque adresse IP à 5 soumissions par fenêtre de 15 minutes.
 * Tout dépassement déclenche un log de sécurité avec dédoublonnage automatique.
 */
export const contactRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requêtes par IP maximum
  standardHeaders: true, // Renvoie les en-têtes standard RateLimit-*
  legacyHeaders: false, // Désactive les en-têtes X-RateLimit-*
  message: sendResponse(
    false,
    'Trop de messages envoyés depuis cette adresse IP. Veuillez patienter 15 minutes avant de réessayer.'
  ),
  handler: (req, res, _next, options) => {
    const ip = extractClientIp(req);

    void logSecurityIncident({
      category: 'ratelimit_contact',
      level: 'warning',
      action: 'Dépassement du Rate Limit (Suspicion de Spam/DoS)',
      target: 'POST /api/v1/contact',
      ipAddress: ip,
      details: 'L’adresse IP a dépassé le quota autorisé de 5 requêtes par 15 minutes sur le formulaire de contact.',
    });

    res.status(429).json(options.message);
  },
});

/**
 * Limiteur de débit pour l'envoi de réponses par les administrateurs
 * Permet jusqu'à 30 envois d'e-mails par tranche de 15 minutes
 */
export const replyRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: sendResponse(
    false,
    'Limite d’envoi d’e-mails atteinte. Veuillez patienter quelques instants.'
  ),
  handler: (req, res, _next, options) => {
    const ip = extractClientIp(req);

    void logSecurityIncident({
      category: 'ratelimit_reply',
      level: 'warning',
      action: 'Dépassement du Rate Limit (Envoi de réponses)',
      target: req.originalUrl || 'POST /api/v1/messages/:id/reply',
      ipAddress: ip,
      details: 'Quota maximal de 30 réponses par 15 minutes atteint pour cette session.',
    });

    res.status(429).json(options.message);
  },
});

/**
 * Limiteur de débit pour l'authentification (Anti Brute-Force réseau CWE-307)
 * Permet jusqu'à 10 tentatives de connexion par 15 minutes par adresse IP
 */
export const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: sendResponse(
    false,
    'Trop de tentatives de connexion depuis cette adresse IP. Veuillez patienter 15 minutes avant de réessayer.'
  ),
  handler: (req, res, _next, options) => {
    const ip = extractClientIp(req);

    void logSecurityIncident({
      category: 'ratelimit_login',
      level: 'warning',
      action: 'Dépassement du Rate Limit de Connexion',
      target: 'POST /api/v1/auth/login',
      ipAddress: ip,
      details: 'Quota maximal de 10 tentatives de connexion par 15 minutes atteint pour cette adresse IP.',
    });

    res.status(429).json(options.message);
  },
});
