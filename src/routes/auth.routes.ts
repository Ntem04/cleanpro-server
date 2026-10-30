import { Router } from 'express';
import { authController } from '../controllers/auth.controller.js';
import { requireAuth, requireRole } from '../middlewares/auth.middleware.js';
import { loginRateLimiter } from '../middlewares/rateLimiter.js';
import { ADMIN_MANAGEMENT_ROLES } from '../config/roles.js';

const router: Router = Router();

// ─── Routes publiques d'authentification (sécurisées par Rate Limiting) ───────
router.post('/login', loginRateLimiter, authController.login);
router.post('/logout', authController.logout);

// ─── Routes de profil personnel (tout utilisateur authentifié) ────────────────
router.get('/me', requireAuth, authController.getProfile);
router.patch('/profile', requireAuth, authController.updateProfile);
router.put('/profile', requireAuth, authController.updateProfile);
router.patch('/avatar', requireAuth, authController.updateAvatar);

// ─── Gestion administrative des comptes (RBAC — OWASP A01) ───────────────────
// Seuls les rôles ADMIN_MANAGEMENT_ROLES peuvent lister, créer ou supprimer des comptes.
// Un simple utilisateur authentifié sans rôle adéquat reçoit HTTP 403.
router.get(
  '/admins',
  requireAuth,
  requireRole(...ADMIN_MANAGEMENT_ROLES),
  authController.listAdmins
);
router.post(
  '/admins',
  requireAuth,
  requireRole(...ADMIN_MANAGEMENT_ROLES),
  authController.createAdmin
);
router.delete(
  '/admins/:id',
  requireAuth,
  requireRole(...ADMIN_MANAGEMENT_ROLES),
  authController.deleteAdmin
);

export default router;
