import { Router } from 'express';
import { settingsController } from '../controllers/settings.controller.js';
import { requireRole } from '../middlewares/auth.middleware.js';
import { DASHBOARD_ROLES, WRITE_ROLES } from '../config/roles.js';

const router: Router = Router();

/**
 * Routes pour les Paramètres Entreprise & Profil CleanPro — RBAC appliqué (OWASP A01)
 * Lecture : DASHBOARD_ROLES (admin + responsable d'agence)
 * Écriture : WRITE_ROLES (admin uniquement)
 */

// Lecture des paramètres (tous les rôles dashboard)
router.get('/', requireRole(...DASHBOARD_ROLES), settingsController.get);

// Mise à jour des paramètres (admin uniquement)
router.put('/', requireRole(...WRITE_ROLES), settingsController.update);
router.patch('/', requireRole(...WRITE_ROLES), settingsController.update);

export default router;
