import { Prisma } from '@prisma/client';
import prisma from '../config/prisma.js';

export interface UpdateSettingsDTO {
  company?: {
    name?: string;
    signature?: string;
    logoUrl?: string;
  };
  contact?: {
    phone?: string;
    whatsapp?: string;
    email?: string;
    address?: string;
    officeNote?: string;
  };
  openingHours?: {
    weekdays?: string;
    saturday?: string;
    sunday?: string;
    visitors?: string;
  };
  notifications?: {
    newMessages?: boolean;
    planningAlerts?: boolean;
    securityAlerts?: boolean;
    reports?: string;
  };
  profile?: {
    name?: string;
    email?: string;
    avatarUrl?: string;
  };
}

export interface AuditContext {
  userName?: string;
  userEmail?: string;
  ipAddress?: string;
}

/**
 * Service Métier pour les Paramètres Entreprise & Profil
 * Connecté à PostgreSQL via Prisma
 */
export const settingsService = {
  /**
   * Récupère les paramètres complets de CleanPro (Singleton)
   */
  async getSettings(userId?: string) {
    let settings = await prisma.settings.findUnique({
      where: { id: 'singleton' },
    });

    if (!settings) {
      settings = await prisma.settings.create({
        data: {
          id: 'singleton',
          companyName: 'CleanPro SARL',
          companySignature: 'CleanPro – Votre partenaire propreté et hygiène.',
          phone: '+237 600 000 000',
          whatsapp: '+237 600 000 000',
          email: 'contact@cleanpro.cm',
          address: 'Boulevard de la Liberté, Douala, Cameroun',
          officeNote: 'Accueil visiteurs et standard téléphonique.',
          weekdaysHours: '07:30 – 18:30',
          saturdayHours: '08:00 – 16:00',
          sundayHours: 'Urgences sur demande',
          visitorsHours: '08:30 – 17:30',
          notifications: {
            newMessages: true,
            planningAlerts: true,
            securityAlerts: true,
            reports: 'Hebdomadaire',
          },
        },
      });
    }

    // Récupération du profil admin par défaut ou authentifié pour la section profil
    let defaultUser = null;
    if (userId) {
      defaultUser = await prisma.user.findUnique({ where: { id: userId } });
    }
    if (!defaultUser) {
      defaultUser = (await prisma.user.findFirst({
        where: { isCurrentUser: true },
      })) || (await prisma.user.findFirst({
        orderBy: { createdAt: 'asc' },
      }));
    }

    return {
      profile: {
        name: defaultUser?.name || 'Jean Dupont',
        role: defaultUser?.role || 'Super Administrateur',
        email: defaultUser?.email || 'admin@cleanpro.cm',
        avatarUrl: defaultUser?.avatarUrl || '',
      },
      company: {
        name: settings.companyName,
        signature: settings.companySignature,
        logoUrl: settings.logoUrl || '',
      },
      contact: {
        phone: settings.phone,
        whatsapp: settings.whatsapp,
        email: settings.email,
        address: settings.address,
        officeNote: settings.officeNote || '',
      },
      openingHours: {
        weekdays: settings.weekdaysHours,
        saturday: settings.saturdayHours,
        sunday: settings.sundayHours,
        visitors: settings.visitorsHours,
      },
      notifications: settings.notifications || {
        newMessages: true,
        planningAlerts: true,
        securityAlerts: true,
        reports: 'Hebdomadaire',
      },
    };
  },

  /**
   * Met à jour les paramètres de l'entreprise avec filtrage strict (CWE-915)
   */
  async updateSettings(dto: UpdateSettingsDTO, audit?: AuditContext, userId?: string) {
    const updateData: {
      companyName?: string;
      companySignature?: string;
      logoUrl?: string;
      phone?: string;
      whatsapp?: string;
      email?: string;
      address?: string;
      officeNote?: string;
      weekdaysHours?: string;
      saturdayHours?: string;
      sundayHours?: string;
      visitorsHours?: string;
      notifications?: Prisma.InputJsonValue;
    } = {};

    if (dto.company) {
      if (dto.company.name !== undefined) updateData.companyName = dto.company.name.trim();
      if (dto.company.signature !== undefined) updateData.companySignature = dto.company.signature.trim();
      if (dto.company.logoUrl !== undefined) updateData.logoUrl = dto.company.logoUrl.trim();
    }

    if (dto.contact) {
      if (dto.contact.phone !== undefined) updateData.phone = dto.contact.phone.trim();
      if (dto.contact.whatsapp !== undefined) updateData.whatsapp = dto.contact.whatsapp.trim();
      if (dto.contact.email !== undefined) updateData.email = dto.contact.email.trim().toLowerCase();
      if (dto.contact.address !== undefined) updateData.address = dto.contact.address.trim();
      if (dto.contact.officeNote !== undefined) updateData.officeNote = dto.contact.officeNote.trim();
    }

    if (dto.openingHours) {
      if (dto.openingHours.weekdays !== undefined) updateData.weekdaysHours = dto.openingHours.weekdays.trim();
      if (dto.openingHours.saturday !== undefined) updateData.saturdayHours = dto.openingHours.saturday.trim();
      if (dto.openingHours.sunday !== undefined) updateData.sundayHours = dto.openingHours.sunday.trim();
      if (dto.openingHours.visitors !== undefined) updateData.visitorsHours = dto.openingHours.visitors.trim();
    }

    if (dto.notifications) {
      updateData.notifications = dto.notifications as Prisma.InputJsonValue;
    }

    // Mise à jour du profil utilisateur authentifié
    if (dto.profile) {
      const targetUser = userId
        ? await prisma.user.findUnique({ where: { id: userId } })
        : (await prisma.user.findFirst({ where: { isCurrentUser: true } })) ||
          (await prisma.user.findFirst({ orderBy: { createdAt: 'asc' } }));

      if (targetUser) {
        await prisma.user.update({
          where: { id: targetUser.id },
          data: {
            name: dto.profile.name ? dto.profile.name.trim() : undefined,
            avatarUrl: dto.profile.avatarUrl !== undefined ? dto.profile.avatarUrl.trim() : undefined,
          },
        });
      }
    }

    await prisma.settings.upsert({
      where: { id: 'singleton' },
      create: {
        id: 'singleton',
        ...updateData,
      },
      update: updateData,
    });

    // Journalisation d'audit
    try {
      await prisma.log.create({
        data: {
          type: 'audit',
          level: 'info',
          user: audit?.userName || 'Administrateur',
          userEmail: audit?.userEmail,
          action: 'Mise à jour des paramètres entreprise',
          target: updateData.companyName || 'Paramètres CleanPro',
          ipAddress: audit?.ipAddress || '127.0.0.1',
          result: 'success',
          details: 'Mise à jour des coordonnées et paramètres entreprise dans PostgreSQL.',
        },
      });
    } catch {
      // Ignorer
    }

    return this.getSettings(userId);
  },
};

