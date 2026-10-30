import { Request, Response, NextFunction } from 'express';
import { serviceService, ServiceAvailabilityStatus } from '../services/service.service.js';
import { sendResponse } from '../utils/apiResponse.js';

const ALLOWED_STATUSES: ServiceAvailabilityStatus[] = ['disponible', 'indisponible', 'desactive'];

/**
 * Valide et assainit le payload de création d'un service (CWE-20 & CWE-400)
 */
function validateCreateInput(body: unknown): { error?: string; value?: {
  title: string;
  description?: string;
  image?: string;
  prestations?: string[];
  status?: ServiceAvailabilityStatus;
} } {
  if (!body || typeof body !== 'object') {
    return { error: 'Corps de requête invalide (objet JSON attendu).' };
  }

  const payload = body as Record<string, unknown>;

  // Validation du titre (obligatoire, 2 à 100 caractères)
  if (!payload.title || typeof payload.title !== 'string') {
    return { error: 'Le champ "title" est obligatoire et doit être une chaîne de caractères.' };
  }
  const title = payload.title.trim();
  if (title.length < 2 || title.length > 100) {
    return { error: 'Le titre doit comporter entre 2 et 100 caractères.' };
  }

  // Validation de la description (optionnelle, max 3000 caractères)
  let description: string | undefined;
  if (payload.description !== undefined) {
    if (typeof payload.description !== 'string') {
      return { error: 'La description doit être une chaîne de caractères.' };
    }
    if (payload.description.length > 3000) {
      return { error: 'La description ne peut pas dépasser 3000 caractères.' };
    }
    description = payload.description.trim();
  }

  // Validation de l'image (optionnelle, max 300 caractères)
  let image: string | undefined;
  if (payload.image !== undefined) {
    if (typeof payload.image !== 'string') {
      return { error: 'L’image doit être une chaîne de caractères.' };
    }
    if (payload.image.length > 300) {
      return { error: 'Le nom ou l’URL de l’image ne peut pas dépasser 300 caractères.' };
    }
    image = payload.image.trim();
  }

  // Validation des prestations (optionnelles, max 50 éléments, 200 car. chacun)
  let prestations: string[] | undefined;
  if (payload.prestations !== undefined) {
    if (!Array.isArray(payload.prestations)) {
      return { error: 'Les prestations doivent être un tableau de chaînes.' };
    }
    if (payload.prestations.length > 50) {
      return { error: 'Un service ne peut pas comporter plus de 50 prestations.' };
    }
    for (const item of payload.prestations) {
      if (typeof item !== 'string' || item.trim().length > 200) {
        return { error: 'Chaque prestation doit être une chaîne de 200 caractères maximum.' };
      }
    }
    prestations = payload.prestations.map((p) => String(p).trim()).filter(Boolean);
  }

  // Validation du statut (whitelist stricte)
  let status: ServiceAvailabilityStatus | undefined;
  if (payload.status !== undefined) {
    if (typeof payload.status !== 'string' || !ALLOWED_STATUSES.includes(payload.status as ServiceAvailabilityStatus)) {
      return { error: `Le statut doit être l'un des suivants : ${ALLOWED_STATUSES.join(', ')}.` };
    }
    status = payload.status as ServiceAvailabilityStatus;
  }

  return {
    value: {
      title,
      description,
      image,
      prestations,
      status,
    },
  };
}

/**
 * Valide et assainit le payload de mise à jour (CWE-915 Mass Assignment protection)
 */
function validateUpdateInput(body: unknown): { error?: string; value?: {
  title?: string;
  description?: string;
  image?: string;
  prestations?: string[];
  status?: ServiceAvailabilityStatus;
} } {
  if (!body || typeof body !== 'object') {
    return { error: 'Corps de requête invalide.' };
  }

  const payload = body as Record<string, unknown>;
  const result: {
    title?: string;
    description?: string;
    image?: string;
    prestations?: string[];
    status?: ServiceAvailabilityStatus;
  } = {};

  if (payload.title !== undefined) {
    if (typeof payload.title !== 'string' || payload.title.trim().length < 2 || payload.title.trim().length > 100) {
      return { error: 'Le titre doit comporter entre 2 et 100 caractères.' };
    }
    result.title = payload.title.trim();
  }

  if (payload.description !== undefined) {
    if (typeof payload.description !== 'string' || payload.description.length > 3000) {
      return { error: 'La description ne peut pas dépasser 3000 caractères.' };
    }
    result.description = payload.description.trim();
  }

  if (payload.image !== undefined) {
    if (typeof payload.image !== 'string' || payload.image.length > 300) {
      return { error: 'L’image ne peut pas dépasser 300 caractères.' };
    }
    result.image = payload.image.trim();
  }

  if (payload.prestations !== undefined) {
    if (!Array.isArray(payload.prestations) || payload.prestations.length > 50) {
      return { error: 'Le tableau de prestations est invalide (max 50 éléments).' };
    }
    result.prestations = payload.prestations.map((p) => String(p).trim()).filter(Boolean);
  }

  if (payload.status !== undefined) {
    if (!ALLOWED_STATUSES.includes(payload.status as ServiceAvailabilityStatus)) {
      return { error: `Statut invalide. Attendu : ${ALLOWED_STATUSES.join(', ')}.` };
    }
    result.status = payload.status as ServiceAvailabilityStatus;
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
 * Contrôleur HTTP pour le Catalogue des Services
 */
export const serviceController = {
  /**
   * GET /api/v1/services ou /api/v1/dashboard/services/catalog
   */
  async getAll(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const services = await serviceService.getAllServices();
      res.status(200).json(
        sendResponse(true, 'Catalogue des services récupéré avec succès depuis PostgreSQL', {
          total: services.length,
          data: services,
        })
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * GET /api/v1/services/:id
   */
  async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = String(req.params.id);
      const service = await serviceService.getServiceById(id);

      if (!service) {
        res.status(404).json(sendResponse(false, 'Service introuvable.'));
        return;
      }

      res.status(200).json(
        sendResponse(true, 'Détails du service récupérés', service)
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * POST /api/v1/services
   */
  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const validation = validateCreateInput(req.body);
      if (validation.error || !validation.value) {
        res.status(400).json(sendResponse(false, validation.error || 'Données invalides.'));
        return;
      }

      const ipAddress = getClientIp(req);
      const newService = await serviceService.createService(validation.value, {
        userName: 'Administrateur',
        ipAddress,
      });

      res.status(201).json(
        sendResponse(true, 'Service créé avec succès dans la base de données', newService)
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * PUT /api/v1/services/:id ou PATCH /api/v1/services/:id
   */
  async update(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = String(req.params.id);
      const validation = validateUpdateInput(req.body);

      if (validation.error || !validation.value) {
        res.status(400).json(sendResponse(false, validation.error || 'Données de mise à jour invalides.'));
        return;
      }

      const ipAddress = getClientIp(req);
      const updated = await serviceService.updateService(id, validation.value, {
        userName: 'Administrateur',
        ipAddress,
      });

      if (!updated) {
        res.status(404).json(sendResponse(false, 'Prestation introuvable pour mise à jour.'));
        return;
      }

      res.status(200).json(
        sendResponse(true, 'Service mis à jour avec succès dans PostgreSQL', updated)
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * DELETE /api/v1/services/:id
   */
  async delete(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = String(req.params.id);
      const ipAddress = getClientIp(req);

      const deleted = await serviceService.deleteService(id, {
        userName: 'Administrateur',
        ipAddress,
      });

      if (!deleted) {
        res.status(404).json(sendResponse(false, 'Prestation introuvable pour suppression.'));
        return;
      }

      res.status(200).json(
        sendResponse(true, 'Service supprimé avec succès de la base de données', { id: deleted.id })
      );
    } catch (error) {
      next(error);
    }
  },
};
