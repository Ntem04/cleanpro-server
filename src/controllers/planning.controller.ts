import { Request, Response, NextFunction } from 'express';
import {
  planningService,
  PlanningCategory,
  PlanningColorTheme,
  CreatePlanningSlotDTO,
  UpdatePlanningSlotDTO,
} from '../services/planning.service.js';
import { sendResponse } from '../utils/apiResponse.js';

const ALLOWED_CATEGORIES: PlanningCategory[] = ['bureau', 'residence', 'industrie', 'evenement'];
const ALLOWED_COLORS: PlanningColorTheme[] = ['emerald', 'sky', 'amber', 'indigo'];
const TIME_REGEX = /^([01]\d|2[0-3]):([0-5]\d)$/; // Format strict HH:mm de 00:00 à 23:59

/**
 * Valide les données de création d'un créneau d'intervention (CWE-20)
 */
function validateCreateInput(body: unknown): {
  error?: string;
  value?: CreatePlanningSlotDTO;
} {
  if (!body || typeof body !== 'object') {
    return { error: 'Corps de requête invalide.' };
  }

  const payload = body as Record<string, unknown>;

  // Validation du titre (obligatoire, 2 à 100 caractères)
  if (!payload.title || typeof payload.title !== 'string') {
    return { error: 'L’intitulé de l’intervention est obligatoire.' };
  }
  const title = payload.title.trim();
  if (title.length < 2 || title.length > 100) {
    return { error: 'L’intitulé doit comporter entre 2 et 100 caractères.' };
  }

  // Validation du lieu (obligatoire, 2 à 150 caractères)
  if (!payload.location || typeof payload.location !== 'string') {
    return { error: 'Le lieu de l’intervention est obligatoire.' };
  }
  const location = payload.location.trim();
  if (location.length < 2 || location.length > 150) {
    return { error: 'Le lieu doit comporter entre 2 et 150 caractères.' };
  }

  // Validation du jour
  const day = typeof payload.day === 'string' && payload.day.trim().length > 0
    ? payload.day.trim()
    : 'Jour à définir';

  // Validation de la date formatée
  const dateFormatted = typeof payload.dateFormatted === 'string'
    ? payload.dateFormatted.trim()
    : '';

  // Validation des horaires (format HH:mm et cohérence temporelle)
  const startTime = typeof payload.startTime === 'string' && TIME_REGEX.test(payload.startTime.trim())
    ? payload.startTime.trim()
    : '08:00';

  const endTime = typeof payload.endTime === 'string' && TIME_REGEX.test(payload.endTime.trim())
    ? payload.endTime.trim()
    : '12:00';

  if (startTime >= endTime) {
    return { error: 'L’heure de début doit être strictement antérieure à l’heure de fin.' };
  }

  // Validation de l'équipe
  const team = typeof payload.team === 'string' && payload.team.trim().length > 0
    ? payload.team.trim()
    : 'Équipe générale';

  // Validation de la catégorie (whitelist)
  let category: PlanningCategory = 'bureau';
  if (payload.category !== undefined) {
    if (typeof payload.category !== 'string' || !ALLOWED_CATEGORIES.includes(payload.category as PlanningCategory)) {
      return { error: `Catégorie invalide. Choix autorisés : ${ALLOWED_CATEGORIES.join(', ')}.` };
    }
    category = payload.category as PlanningCategory;
  }

  // Validation du thème de couleur (whitelist)
  let colorTheme: PlanningColorTheme = 'emerald';
  if (payload.colorTheme !== undefined) {
    if (typeof payload.colorTheme !== 'string' || !ALLOWED_COLORS.includes(payload.colorTheme as PlanningColorTheme)) {
      return { error: `Couleur invalide. Choix autorisés : ${ALLOWED_COLORS.join(', ')}.` };
    }
    colorTheme = payload.colorTheme as PlanningColorTheme;
  }

  return {
    value: {
      day,
      dateFormatted,
      title,
      location,
      startTime,
      endTime,
      team,
      category,
      colorTheme,
    },
  };
}

/**
 * Valide les données de mise à jour d'un créneau (CWE-915 Mass Assignment protection)
 */
function validateUpdateInput(body: unknown): {
  error?: string;
  value?: UpdatePlanningSlotDTO;
} {
  if (!body || typeof body !== 'object') {
    return { error: 'Corps de requête invalide.' };
  }

  const payload = body as Record<string, unknown>;
  const result: UpdatePlanningSlotDTO = {};

  if (payload.title !== undefined) {
    if (typeof payload.title !== 'string' || payload.title.trim().length < 2 || payload.title.trim().length > 100) {
      return { error: 'Le titre doit comporter entre 2 et 100 caractères.' };
    }
    result.title = payload.title.trim();
  }

  if (payload.location !== undefined) {
    if (typeof payload.location !== 'string' || payload.location.trim().length < 2 || payload.location.trim().length > 150) {
      return { error: 'Le lieu doit comporter entre 2 et 150 caractères.' };
    }
    result.location = payload.location.trim();
  }

  if (payload.day !== undefined) {
    result.day = String(payload.day).trim();
  }

  if (payload.dateFormatted !== undefined) {
    result.dateFormatted = String(payload.dateFormatted).trim();
  }

  if (payload.startTime !== undefined) {
    const s = String(payload.startTime).trim();
    if (!TIME_REGEX.test(s)) {
      return { error: 'Format d’heure de début invalide (attendu HH:mm).' };
    }
    result.startTime = s;
  }

  if (payload.endTime !== undefined) {
    const e = String(payload.endTime).trim();
    if (!TIME_REGEX.test(e)) {
      return { error: 'Format d’heure de fin invalide (attendu HH:mm).' };
    }
    result.endTime = e;
  }

  if (result.startTime && result.endTime && result.startTime >= result.endTime) {
    return { error: 'L’heure de début doit être antérieure à l’heure de fin.' };
  }

  if (payload.team !== undefined) {
    result.team = String(payload.team).trim();
  }

  if (payload.category !== undefined) {
    if (!ALLOWED_CATEGORIES.includes(payload.category as PlanningCategory)) {
      return { error: `Catégorie invalide : ${ALLOWED_CATEGORIES.join(', ')}.` };
    }
    result.category = payload.category as PlanningCategory;
  }

  if (payload.colorTheme !== undefined) {
    if (!ALLOWED_COLORS.includes(payload.colorTheme as PlanningColorTheme)) {
      return { error: `Couleur invalide : ${ALLOWED_COLORS.join(', ')}.` };
    }
    result.colorTheme = payload.colorTheme as PlanningColorTheme;
  }

  return { value: result };
}

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
 * Contrôleur HTTP pour le Planning d'Interventions
 */
export const planningController = {
  /**
   * GET /api/v1/planning ou /api/v1/dashboard/planning
   */
  async getAll(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const slots = await planningService.getAllSlots();
      res.status(200).json(
        sendResponse(true, 'Planning récupéré avec succès depuis PostgreSQL', {
          periodLabel: 'Semaine en cours',
          badgeLabel: `${slots.length} intervention${slots.length > 1 ? 's' : ''}`,
          slots,
        })
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * GET /api/v1/planning/:id
   */
  async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = String(req.params.id);
      const slot = await planningService.getSlotById(id);

      if (!slot) {
        res.status(404).json(sendResponse(false, 'Créneau d’intervention introuvable.'));
        return;
      }

      res.status(200).json(
        sendResponse(true, 'Détails du créneau récupérés', slot)
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * POST /api/v1/planning ou /api/v1/dashboard/planning
   */
  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const validation = validateCreateInput(req.body);
      if (validation.error || !validation.value) {
        res.status(400).json(sendResponse(false, validation.error || 'Données invalides.'));
        return;
      }

      const ipAddress = getClientIp(req);
      const newSlot = await planningService.createSlot(validation.value, {
        userName: 'Administrateur',
        ipAddress,
      });

      res.status(201).json(
        sendResponse(true, 'Intervention planifiée avec succès dans PostgreSQL', newSlot)
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * PUT /api/v1/planning/:id ou PATCH /api/v1/planning/:id
   */
  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = String(req.params.id);
      const validation = validateUpdateInput(req.body);

      if (validation.error || !validation.value) {
        res.status(400).json(sendResponse(false, validation.error || 'Données invalides.'));
        return;
      }

      const ipAddress = getClientIp(req);
      const updated = await planningService.updateSlot(id, validation.value, {
        userName: 'Administrateur',
        ipAddress,
      });

      if (!updated) {
        res.status(404).json(sendResponse(false, 'Créneau d’intervention introuvable pour mise à jour.'));
        return;
      }

      res.status(200).json(
        sendResponse(true, 'Intervention mise à jour avec succès dans PostgreSQL', updated)
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * DELETE /api/v1/planning/:id
   */
  async delete(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = String(req.params.id);
      const ipAddress = getClientIp(req);

      const deleted = await planningService.deleteSlot(id, {
        userName: 'Administrateur',
        ipAddress,
      });

      if (!deleted) {
        res.status(404).json(sendResponse(false, 'Créneau d’intervention introuvable pour suppression.'));
        return;
      }

      res.status(200).json(
        sendResponse(true, 'Intervention annulée et retirée de la base de données', { id: deleted.id })
      );
    } catch (error) {
      next(error);
    }
  },
};

