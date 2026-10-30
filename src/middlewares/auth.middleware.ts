import { Request, Response, NextFunction } from 'express';
import { authService, TokenPayload } from '../services/auth.service.js';
import { sendResponse } from '../utils/apiResponse.js';

// Extension de l'interface Request Express pour injecter l'utilisateur authentifié
declare global {
  namespace Express {
    interface Request {
      user?: TokenPayload;
    }
  }
}

/**
 * Middleware d'Authentification Sécurisée (OWASP A01 & A07)
 * Vérifie la présence et la validité du JWT dans l'en-tête Authorization ou dans le cookie HttpOnly
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  let token: string | undefined;

  // 1. Récupération depuis l'en-tête Authorization: Bearer <token>
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  }

  // 2. Fallback sécurisé : Cookie HttpOnly
  if (!token && req.cookies?.cleanpro_jwt) {
    token = req.cookies.cleanpro_jwt;
  }

  if (!token) {
    res.status(401).json(
      sendResponse(false, 'Accès non autorisé. Authentification requise.')
    );
    return;
  }

  const payload = authService.verifyToken(token);
  if (!payload) {
    res.status(401).json(
      sendResponse(false, 'Session expirée ou jeton d’accès invalide. Veuillez vous reconnecter.')
    );
    return;
  }

  // Injection des données de l'utilisateur authentifié dans l'objet requête
  req.user = payload;
  next();
}

/**
 * Middleware de Contrôle d'Accès basé sur les rôles (RBAC - Role-Based Access Control)
 */
export function requireRole(...allowedRoles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json(sendResponse(false, 'Authentification requise.'));
      return;
    }

    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json(
        sendResponse(false, 'Droits insuffisants pour effectuer cette opération administrative.')
      );
      return;
    }

    next();
  };
}

