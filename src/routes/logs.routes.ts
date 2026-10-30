import { Router } from 'express';
import { logsController } from '../controllers/logs.controller.js';
import { requireRole } from '../middlewares/auth.middleware.js';
import { DASHBOARD_ROLES, WRITE_ROLES } from '../config/roles.js';

const router: Router = Router();

/**
 * Routes pour les Journaux d'Audit & Techniques CleanPro — RBAC appliqué (OWASP A01)
 * Lecture : DASHBOARD_ROLES
 * Écriture / Purge : WRITE_ROLES (admin uniquement)
 *
 * ⚠️ La purge est placée avant les routes génériques pour éviter
 * qu'Express interprète "purge" comme un :id.
 */

// Purge des logs (mutation sensible — admin uniquement)
router.delete('/purge', requireRole(...WRITE_ROLES), logsController.purge);

// Consultation et filtrage des logs (lecture — tous les rôles dashboard)
router.get('/', requireRole(...DASHBOARD_ROLES), logsController.getAll);

// Consignation d'un nouvel événement (écriture — admin uniquement)
router.post('/', requireRole(...WRITE_ROLES), logsController.create);

export default router;
