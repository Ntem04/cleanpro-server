import { Request, Response, NextFunction } from 'express';
import { settingsService, UpdateSettingsDTO } from '../services/settings.service.js';
import { sendResponse } from '../utils/apiResponse.js';

/**
 * Extrait l'adresse IP cliente de manière sécurisée
 */
function getClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }
  return req.ip || req.socket.remoteAddress || '127.0.0.1';
}

/**
 * Contrôleur HTTP pour les Paramètres Entreprise & Profil
 */
export const settingsController = {
  /**
   * GET /api/v1/settings ou /api/v1/dashboard/settings
   */
  async get(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const settings = await settingsService.getSettings(req.user?.userId);
      res.status(200).json(
        sendResponse(true, 'Paramètres récupérés avec succès depuis PostgreSQL', settings)
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * PUT /api/v1/settings ou /api/v1/dashboard/settings
   */
  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const payload = req.body as UpdateSettingsDTO;
      if (!payload || typeof payload !== 'object') {
        res.status(400).json(sendResponse(false, 'Données de mise à jour invalides.'));
        return;
      }

      const ipAddress = getClientIp(req);
      const updated = await settingsService.updateSettings(
        payload,
        {
          userName: req.user?.email || 'Administrateur',
          userEmail: req.user?.email,
          ipAddress,
        },
        req.user?.userId
      );

      res.status(200).json(
        sendResponse(true, 'Paramètres mis à jour avec succès dans PostgreSQL', updated)
      );
    } catch (error) {
      next(error);
    }
  },
};

