import { Router } from 'express';
import { planningController } from '../controllers/planning.controller.js';
import { requireRole } from '../middlewares/auth.middleware.js';
import { DASHBOARD_ROLES, WRITE_ROLES } from '../config/roles.js';

const router: Router = Router();

/**
 * Routes pour le Planning des Interventions CleanPro — RBAC appliqué (OWASP A01)
 * Lecture : DASHBOARD_ROLES (admin + responsable d'agence)
 * Écriture / Suppression : WRITE_ROLES (admin uniquement)
 */

// Consultation du planning (lecture — tous les rôles dashboard)
router.get('/', requireRole(...DASHBOARD_ROLES), planningController.getAll);
router.get('/:id', requireRole(...DASHBOARD_ROLES), planningController.getById);

// Planification d'une nouvelle intervention (écriture — admin uniquement)
router.post('/', requireRole(...WRITE_ROLES), planningController.create);

// Mise à jour d'un créneau (écriture — admin uniquement)
router.put('/:id', requireRole(...WRITE_ROLES), planningController.update);
router.patch('/:id', requireRole(...WRITE_ROLES), planningController.update);

// Annulation / suppression d'une intervention (écriture — admin uniquement)
router.delete('/:id', requireRole(...WRITE_ROLES), planningController.delete);

export default router;
