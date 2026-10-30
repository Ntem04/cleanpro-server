import prisma from '../config/prisma.js';

export type PlanningCategory = 'bureau' | 'residence' | 'industrie' | 'evenement';
export type PlanningColorTheme = 'emerald' | 'sky' | 'amber' | 'indigo';

export interface CreatePlanningSlotDTO {
  day: string;
  dateFormatted?: string;
  title: string;
  location: string;
  startTime: string;
  endTime: string;
  team?: string;
  category: PlanningCategory;
  colorTheme?: PlanningColorTheme;
}

export interface UpdatePlanningSlotDTO {
  day?: string;
  dateFormatted?: string;
  title?: string;
  location?: string;
  startTime?: string;
  endTime?: string;
  team?: string;
  category?: PlanningCategory;
  colorTheme?: PlanningColorTheme;
}

export interface AuditContext {
  userName?: string;
  userEmail?: string;
  ipAddress?: string;
}

/**
 * Service Métier pour le Planning d'Interventions
 * Connecté à PostgreSQL via Prisma avec traçabilité d'audit automatique
 */
export const planningService = {
  /**
   * Récupère tous les créneaux planifiés triés par date et heure de début
   */
  async getAllSlots() {
    return prisma.planningSlot.findMany({
      orderBy: [
        { dateFormatted: 'asc' },
        { startTime: 'asc' },
      ],
    });
  },

  /**
   * Récupère un créneau par son identifiant unique
   */
  async getSlotById(id: string) {
    return prisma.planningSlot.findUnique({
      where: { id },
    });
  },

  /**
   * Enregistre un nouveau créneau d'intervention en base
   */
  async createSlot(dto: CreatePlanningSlotDTO, audit?: AuditContext) {
    const newSlot = await prisma.planningSlot.create({
      data: {
        day: dto.day.trim(),
        dateFormatted: (dto.dateFormatted || '').trim(),
        title: dto.title.trim(),
        location: dto.location.trim(),
        startTime: dto.startTime.trim(),
        endTime: dto.endTime.trim(),
        team: (dto.team || 'Équipe CleanPro').trim(),
        category: dto.category,
        colorTheme: dto.colorTheme || 'emerald',
      },
    });

    // Journal d'audit de la planification
    try {
      await prisma.log.create({
        data: {
          type: 'audit',
          level: 'info',
          user: audit?.userName || 'Administrateur',
          userEmail: audit?.userEmail,
          action: 'Planification d’une intervention',
          target: newSlot.title,
          ipAddress: audit?.ipAddress || '127.0.0.1',
          result: 'success',
          details: `Intervention "${newSlot.title}" planifiée pour le ${newSlot.day} à ${newSlot.location} (${newSlot.startTime}–${newSlot.endTime}).`,
        },
      });
    } catch {
      // Ignorer
    }

    return newSlot;
  },

  /**
   * Met à jour un créneau existant avec filtrage strict (CWE-915)
   */
  async updateSlot(id: string, dto: UpdatePlanningSlotDTO, audit?: AuditContext) {
    const existing = await prisma.planningSlot.findUnique({ where: { id } });
    if (!existing) {
      return null;
    }

    const updateData: {
      day?: string;
      dateFormatted?: string;
      title?: string;
      location?: string;
      startTime?: string;
      endTime?: string;
      team?: string;
      category?: string;
      colorTheme?: string;
    } = {};

    if (dto.day !== undefined) updateData.day = dto.day.trim();
    if (dto.dateFormatted !== undefined) updateData.dateFormatted = dto.dateFormatted.trim();
    if (dto.title !== undefined) updateData.title = dto.title.trim();
    if (dto.location !== undefined) updateData.location = dto.location.trim();
    if (dto.startTime !== undefined) updateData.startTime = dto.startTime.trim();
    if (dto.endTime !== undefined) updateData.endTime = dto.endTime.trim();
    if (dto.team !== undefined) updateData.team = dto.team.trim();
    if (dto.category !== undefined) updateData.category = dto.category;
    if (dto.colorTheme !== undefined) updateData.colorTheme = dto.colorTheme;

    const updated = await prisma.planningSlot.update({
      where: { id },
      data: updateData,
    });

    try {
      await prisma.log.create({
        data: {
          type: 'audit',
          level: 'info',
          user: audit?.userName || 'Administrateur',
          userEmail: audit?.userEmail,
          action: 'Modification d’une intervention',
          target: updated.title,
          ipAddress: audit?.ipAddress || '127.0.0.1',
          result: 'success',
          details: `Créneau "${updated.title}" mis à jour (${updated.day} à ${updated.location}).`,
        },
      });
    } catch {
      // Ignorer
    }

    return updated;
  },

  /**
   * Supprime / annule un créneau d'intervention
   */
  async deleteSlot(id: string, audit?: AuditContext) {
    const existing = await prisma.planningSlot.findUnique({ where: { id } });
    if (!existing) {
      return null;
    }

    await prisma.planningSlot.delete({ where: { id } });

    try {
      await prisma.log.create({
        data: {
          type: 'audit',
          level: 'warning',
          user: audit?.userName || 'Administrateur',
          userEmail: audit?.userEmail,
          action: 'Annulation d’une intervention',
          target: existing.title,
          ipAddress: audit?.ipAddress || '127.0.0.1',
          result: 'success',
          details: `Intervention "${existing.title}" annulée et retirée du planning.`,
        },
      });
    } catch {
      // Ignorer
    }

    return existing;
  },
};

