import crypto from 'node:crypto';
import { Request, Response, NextFunction } from 'express';
import { sendResponse } from '../utils/apiResponse.js';

const CSRF_COOKIE_NAME = 'XSRF-TOKEN';
const CSRF_HEADER_NAME = 'x-xsrf-token';

/**
 * Génère un jeton CSRF aléatoire cryptographique
 */
export function generateCsrfToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Middleware qui garantit la présence du cookie CSRF lisible par le client (Double Submit Cookie Pattern - OWASP)
 */
export function csrfProtection(req: Request, res: Response, next: NextFunction): void {
  let token = req.cookies?.[CSRF_COOKIE_NAME];

  if (!token) {
    token = generateCsrfToken();
    res.cookie(CSRF_COOKIE_NAME, token, {
      httpOnly: false, // Doit être lisible par le script frontend pour l'injecter dans X-XSRF-TOKEN
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      maxAge: 24 * 60 * 60 * 1000, // 24 heures
    });
  }

  // Pour les requêtes de mutation (POST, PUT, DELETE, PATCH), validation stricte du jeton CSRF
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  if (safeMethods.includes(req.method)) {
    return next();
  }

  // Exemptions ciblées et contrôlées (ex: formulaire de contact public de visiteurs externes, routes auth et balise télémétrique anonyme)
  const isPublicContact = req.path === '/contact' || req.path === '/api/v1/contact' || req.path === '/api/contact';
  const isAuthRoute = req.path.endsWith('/auth/login') || req.path.endsWith('/auth/logout');
  const isTelemetryTrack =
    req.path.endsWith('/telemetry/track') ||
    (typeof req.originalUrl === 'string' && req.originalUrl.includes('/telemetry/track'));

  if (isPublicContact || isAuthRoute || isTelemetryTrack) {
    return next();
  }

  const clientToken = req.headers[CSRF_HEADER_NAME] || req.headers['x-csrf-token'];

  if (!clientToken || clientToken !== token) {
    res.status(403).json(
      sendResponse(false, 'Validation CSRF échouée. Requête non autorisée par la politique de sécurité.')
    );
    return;
  }

  next();
}
