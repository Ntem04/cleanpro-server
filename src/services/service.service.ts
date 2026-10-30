import prisma from '../config/prisma.js';

export type ServiceAvailabilityStatus = 'disponible' | 'indisponible' | 'desactive';

export interface CreateServiceDTO {
  title: string;
  description?: string;
  image?: string;
  prestations?: string[];
  status?: ServiceAvailabilityStatus;
}

export interface UpdateServiceDTO {
  title?: string;
  description?: string;
  image?: string;
  prestations?: string[];
  status?: ServiceAvailabilityStatus;
}

export interface AuditContext {
  userName?: string;
  userEmail?: string;
  ipAddress?: string;
}

/**
 * Génère un identifiant slug sécurisé et nettoyé pour les URLs et clés primaires.
 * Prévient les injections de caractères spéciaux et normalise les accents.
 */
function generateSafeSlug(title: string): string {
  const normalized = title
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '') // Suppression des diacritiques (accents)
    .replace(/[^a-z0-9]/g, '-') // Remplacement de tout caractère non alphanumérique par un tiret
    .replace(/-+/g, '-') // Suppression des tirets consécutifs
    .replace(/^-|-$/g, ''); // Suppression des tirets en début et fin

  return normalized || `service-${Date.now()}`;
}

/**
 * Calcule le libellé visuel du badge selon le statut officiel CleanPro
 */
function getBadgeLabel(status: ServiceAvailabilityStatus): string {
  switch (status) {
    case 'indisponible':
      return 'Indisponible';
    case 'desactive':
      return 'Désactivé';
    case 'disponible':
    default:
      return 'Disponible';
  }
}

/**
 * Couche Service Métier pour le Catalogue des Services
 * Interagit directement avec PostgreSQL via Prisma et enregistre les logs d'audit.
 */
export const serviceService = {
  /**
   * Récupère la totalité des prestations du catalogue triées par date de création
   */
  async getAllServices() {
    return prisma.service.findMany({
      orderBy: { createdAt: 'asc' },
    });
  },

  /**
   * Récupère une prestation spécifique par son identifiant unique
   */
  async getServiceById(id: string) {
    return prisma.service.findUnique({
      where: { id },
    });
  },

  /**
   * Crée un nouveau service en base et émet un log d'audit (OWASP / RGPD)
   */
  async createService(dto: CreateServiceDTO, audit?: AuditContext) {
    const baseSlug = generateSafeSlug(dto.title);

    // Vérification de l'unicité du slug pour éviter les collisions de clé primaire
    let finalId = baseSlug;
    const existing = await prisma.service.findUnique({ where: { id: finalId } });
    if (existing) {
      finalId = `${baseSlug}-${Date.now().toString(36)}`;
    }

    const status: ServiceAvailabilityStatus = dto.status || 'disponible';
    const badgeLabel = getBadgeLabel(status);

    const newService = await prisma.service.create({
      data: {
        id: finalId,
        title: dto.title.trim(),
        description: (dto.description || '').trim(),
        image: dto.image || 'services-bureaux0',
        prestations: Array.isArray(dto.prestations)
          ? dto.prestations.map((p) => String(p).trim()).filter(Boolean)
          : [],
        status,
        badgeLabel,
      },
    });

    // Journalisation d'audit automatique de la création
    try {
      await prisma.log.create({
        data: {
          type: 'audit',
          level: 'info',
          user: audit?.userName || 'Administrateur',
          userEmail: audit?.userEmail,
          action: 'Création d’un service',
          target: newService.title,
          ipAddress: audit?.ipAddress || '127.0.0.1',
          result: 'success',
          details: `Prestation "${newService.title}" (${newService.id}) ajoutée au catalogue.`,
        },
      });
    } catch {
      // Échec silencieux du log pour ne pas bloquer l'action métier principale
    }

    return newService;
  },

  /**
   * Met à jour une prestation existante avec liste blanche stricte anti-Mass Assignment (CWE-915)
   */
  async updateService(id: string, dto: UpdateServiceDTO, audit?: AuditContext) {
    const existing = await prisma.service.findUnique({ where: { id } });
    if (!existing) {
      return null;
    }

    // Filtrage strict : seuls les champs explicitement autorisés sont injectés
    const updateData: {
      title?: string;
      description?: string;
      image?: string;
      prestations?: string[];
      status?: string;
      badgeLabel?: string;
    } = {};

    if (dto.title !== undefined) {
      updateData.title = dto.title.trim();
    }
    if (dto.description !== undefined) {
      updateData.description = dto.description.trim();
    }
    if (dto.image !== undefined) {
      updateData.image = dto.image.trim();
    }
    if (dto.prestations !== undefined && Array.isArray(dto.prestations)) {
      updateData.prestations = dto.prestations.map((p) => String(p).trim()).filter(Boolean);
    }
    if (dto.status !== undefined) {
      updateData.status = dto.status;
      updateData.badgeLabel = getBadgeLabel(dto.status);
    }

    const updated = await prisma.service.update({
      where: { id },
      data: updateData,
    });

    // Journalisation d'audit automatique de la modification
    try {
      await prisma.log.create({
        data: {
          type: 'audit',
          level: 'info',
          user: audit?.userName || 'Administrateur',
          userEmail: audit?.userEmail,
          action: 'Modification d’un service',
          target: updated.title,
          ipAddress: audit?.ipAddress || '127.0.0.1',
          result: 'success',
          details: `Prestation "${updated.title}" mise à jour (statut: ${updated.status}).`,
        },
      });
    } catch {
      // Ignorer pour résilience
    }

    return updated;
  },

  /**
   * Supprime une prestation du catalogue et consigne l'action dans le journal d'audit
   */
  async deleteService(id: string, audit?: AuditContext) {
    const existing = await prisma.service.findUnique({ where: { id } });
    if (!existing) {
      return null;
    }

    await prisma.service.delete({
      where: { id },
    });

    try {
      await prisma.log.create({
        data: {
          type: 'audit',
          level: 'warning',
          user: audit?.userName || 'Administrateur',
          userEmail: audit?.userEmail,
          action: 'Suppression d’un service',
          target: existing.title,
          ipAddress: audit?.ipAddress || '127.0.0.1',
          result: 'success',
          details: `Prestation "${existing.title}" (${id}) supprimée du catalogue.`,
        },
      });
    } catch {
      // Ignorer
    }

    return existing;
  },
};

