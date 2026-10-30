import { Request, Response, NextFunction } from 'express';
import { logsService, LogType, LogLevel, LogResult } from '../services/logs.service.js';
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
 * Contrôleur HTTP pour les Journaux d'Audit & Journaux Techniques
 */
export const logsController = {
  /**
   * GET /api/v1/logs ou /api/v1/dashboard/logs
   * Récupère les logs avec filtrage et statistiques globales
   */
  async getAll(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { type, level, result, q, limit, offset } = req.query;

      const [logsData, stats] = await Promise.all([
        logsService.getLogs({
          type: typeof type === 'string' ? type : undefined,
          level: typeof level === 'string' ? level : undefined,
          result: typeof result === 'string' ? result : undefined,
          q: typeof q === 'string' ? q : undefined,
          limit: limit ? Math.min(Number(limit), 200) : 100,
          offset: offset ? Number(offset) : 0,
        }),
        logsService.getStats(),
      ]);

      res.status(200).json(
        sendResponse(true, 'Journaux récupérés avec succès depuis PostgreSQL', {
          total: logsData.total,
          data: logsData.logs,
          stats,
        })
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * POST /api/v1/logs ou /api/v1/dashboard/logs
   * Enregistre un événement dans le journal
   */
  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { type, level, user, userEmail, action, target, result, details, metadata } = req.body;

      if (!action || typeof action !== 'string') {
        res.status(400).json(sendResponse(false, 'Le champ "action" est obligatoire.'));
        return;
      }

      const clientIp = getClientIp(req);

      const newLog = await logsService.createLog({
        type: type === 'technical' ? ('technical' as LogType) : ('audit' as LogType),
        level: level as LogLevel | undefined,
        user: typeof user === 'string' ? user : undefined,
        userEmail: typeof userEmail === 'string' ? userEmail : undefined,
        action,
        target: typeof target === 'string' ? target : undefined,
        ipAddress: clientIp,
        result: result as LogResult | undefined,
        details: typeof details === 'string' ? details : undefined,
        metadata: metadata && typeof metadata === 'object' ? (metadata as Record<string, unknown>) : undefined,
      });

      res.status(201).json(
        sendResponse(true, 'Événement consigné avec succès dans PostgreSQL', {
          log: newLog,
        })
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * DELETE /api/v1/logs/purge ou /api/v1/dashboard/logs/purge
   * Purge les logs anciens selon la politique de conservation RGPD
   */
  async purge(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const days = req.query.days ? Number(req.query.days) : 90;
      const purgeResult = await logsService.purgeOldLogs(days);

      res.status(200).json(
        sendResponse(
          true,
          `Purge automatique des logs exécutée : ${purgeResult.purgedCount} entrées supprimées (conservation ${days} jours)`,
          purgeResult
        )
      );
    } catch (error) {
      next(error);
    }
  },
};

