import { Router } from 'express';
import { contactController } from '../controllers/contact.controller.js';
import { replyRateLimiter } from '../middlewares/rateLimiter.js';
import { requireRole } from '../middlewares/auth.middleware.js';
import { DASHBOARD_ROLES, WRITE_ROLES } from '../config/roles.js';

const router: Router = Router();

/**
 * Routes pour la Messagerie Admin CleanPro — RBAC appliqué (OWASP A01)
 * Lecture : DASHBOARD_ROLES (admin + responsable d'agence)
 * Écriture/Suppression : WRITE_ROLES (admin uniquement)
 */

// Consultation des messages (lecture — tous les rôles dashboard)
router.get('/', requireRole(...DASHBOARD_ROLES), contactController.getAll);
router.get('/unread-count', requireRole(...DASHBOARD_ROLES), contactController.getUnreadCount);
router.get('/:id', requireRole(...DASHBOARD_ROLES), contactController.getById);

// Création manuelle d'un message (écriture — admin uniquement)
router.post('/', requireRole(...WRITE_ROLES), contactController.create);

// Réponse par e-mail au visiteur (écriture — admin uniquement)
router.post('/:id/reply', replyRateLimiter, requireRole(...WRITE_ROLES), contactController.reply);

// Actions d'administration sur les messages (écriture — admin uniquement)
router.patch('/:id/read', requireRole(...WRITE_ROLES), contactController.toggleRead);
router.patch('/:id/archive', requireRole(...WRITE_ROLES), contactController.archive);
router.delete('/:id', requireRole(...WRITE_ROLES), contactController.delete);

export default router;
