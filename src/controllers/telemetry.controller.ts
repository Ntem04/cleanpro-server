import { Request, Response, NextFunction } from 'express';
import { telemetryService } from '../services/telemetry.service.js';
import { sendResponse } from '../utils/apiResponse.js';
import { extractClientIp } from '../middlewares/securityLogger.js';

export const telemetryController = {
  /**
   * POST /api/v1/telemetry/track
   * Enregistre un événement de consultation de page ou d'accès
   */
  async trackVisit(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { path, referrer, visitorId } = req.body;
      const ip = extractClientIp(req);
      const userAgent = req.headers['user-agent'];

      const recorded = await telemetryService.recordVisit({
        path: typeof path === 'string' ? path : '/',
        ip,
        userAgent,
        referrer: typeof referrer === 'string' ? referrer : undefined,
        visitorId: typeof visitorId === 'string' ? visitorId : undefined,
      });

      res.status(200).json(
        sendResponse(true, 'Visite enregistrée avec succès', recorded)
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * GET /api/v1/telemetry/stats
   * Récupère les métriques globales de fréquentation et d'intrusions bloquées
   */
  async getStats(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const stats = await telemetryService.getStats();
      res.status(200).json(
        sendResponse(true, 'Statistiques de télémétrie récupérées', stats)
      );
    } catch (error) {
      next(error);
    }
  },
};

