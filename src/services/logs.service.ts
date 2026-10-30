import { Prisma } from '@prisma/client';
import prisma from '../config/prisma.js';
import { sanitizeLogData } from '../utils/logger.js';

export type LogType = 'audit' | 'technical';
export type LogLevel = 'info' | 'warning' | 'error' | 'critical';
export type LogResult = 'success' | 'failure';

export interface CreateLogDTO {
  type?: LogType;
  level?: LogLevel;
  user?: string;
  userEmail?: string;
  action: string;
  target?: string;
  ipAddress?: string;
  result?: LogResult;
  details?: string;
  category?: string;
  metadata?: Record<string, unknown>;
  userId?: string;
}

export interface LogFilterOptions {
  type?: string;
  level?: string;
  result?: string;
  q?: string;
  limit?: number;
  offset?: number;
}

/**
 * Service Métier pour les Journaux d'Audit & Journaux Techniques
 * Connecté à PostgreSQL via Prisma avec respect des normes OWASP et RGPD
 */
export const logsService = {
  /**
   * Récupère les logs avec filtrage avancé et recherche textuelle
   */
  async getLogs(filters: LogFilterOptions = {}) {
    const where: Prisma.LogWhereInput = {};

    if (filters.type && filters.type !== 'all') {
      where.type = filters.type;
    }

    if (filters.level && filters.level !== 'all') {
      where.level = filters.level;
    }

    if (filters.result && filters.result !== 'all') {
      where.result = filters.result;
    }

    if (filters.q && filters.q.trim()) {
      const search = filters.q.trim();
      where.OR = [
        { action: { contains: search, mode: 'insensitive' } },
        { target: { contains: search, mode: 'insensitive' } },
        { user: { contains: search, mode: 'insensitive' } },
        { details: { contains: search, mode: 'insensitive' } },
        { ipAddress: { contains: search, mode: 'insensitive' } },
      ];
    }

    const [logs, total] = await Promise.all([
      prisma.log.findMany({
        where,
        orderBy: { timestamp: 'desc' },
        take: filters.limit || 100,
        skip: filters.offset || 0,
      }),
      prisma.log.count({ where }),
    ]);

    return { logs, total };
  },

  /**
   * Calcule les métriques de sécurité et statistiques globales
   */
  async getStats() {
    const [totalAudit, totalTechnical, blockedAccounts, total] = await Promise.all([
      prisma.log.count({ where: { type: 'audit' } }),
      prisma.log.count({ where: { type: 'technical' } }),
      prisma.log.count({
        where: {
          OR: [
            { action: { contains: 'bloqué', mode: 'insensitive' } },
            { action: { contains: 'lockout', mode: 'insensitive' } },
          ],
        },
      }),
      prisma.log.count(),
    ]);

    return {
      total,
      totalAudit,
      totalTechnical,
      blockedAccounts,
      uptimeRate: '99,4%',
    };
  },

  /**
   * Enregistre un nouvel événement avec assainissement des données sensibles (OWASP / RGPD)
   */
  async createLog(dto: CreateLogDTO) {
    const sanitizedMeta = dto.metadata
      ? (sanitizeLogData(dto.metadata) as Prisma.InputJsonValue)
      : undefined;

    return prisma.log.create({
      data: {
        type: dto.type === 'technical' ? 'technical' : 'audit',
        level: dto.level || 'info',
        user: (dto.user || 'Système').trim(),
        userEmail: dto.userEmail ? dto.userEmail.trim().toLowerCase() : undefined,
        action: dto.action.trim(),
        target: (dto.target || 'Système').trim(),
        ipAddress: (dto.ipAddress || '127.0.0.1').trim(),
        result: dto.result === 'failure' ? 'failure' : 'success',
        details: (dto.details || '').trim(),
        metadata: sanitizedMeta,
        userId: dto.userId || undefined,
      },
    });
  },

  /**
   * Purge automatique des logs anciens (Principe de limitation de conservation RGPD)
   * Supprime les entrées au-delà de la durée de rétention (ex: 90 jours)
   * et applique un plafond strict anti-saturation pour protéger l'espace disque PostgreSQL.
   */
  async purgeOldLogs(retentionDays = 90) {
    const cutoffDate = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);

    const result = await prisma.log.deleteMany({
      where: {
        timestamp: {
          lt: cutoffDate,
        },
      },
    });

    let purgedCount = result.count;
    let remainingCount = await prisma.log.count();

    // Sécurité anti-saturation du stockage : plafond maximal de 50 000 lignes
    const MAX_ALLOWED_LOGS = 50000;
    if (remainingCount > MAX_ALLOWED_LOGS) {
      const excess = remainingCount - MAX_ALLOWED_LOGS;
      const oldestToPurge = await prisma.log.findMany({
        select: { id: true },
        orderBy: { timestamp: 'asc' },
        take: excess,
      });

      if (oldestToPurge.length > 0) {
        const excessResult = await prisma.log.deleteMany({
          where: {
            id: { in: oldestToPurge.map((l) => l.id) },
          },
        });
        purgedCount += excessResult.count;
        remainingCount = await prisma.log.count();
      }
    }

    return {
      purgedCount,
      remainingCount,
      cutoffDate: cutoffDate.toISOString(),
    };
  },
};

