import { Router } from 'express';
import { serviceController } from '../controllers/service.controller.js';
import { requireRole } from '../middlewares/auth.middleware.js';
import { WRITE_ROLES } from '../config/roles.js';

const router: Router = Router();

/**
 * Routes pour le Catalogue des Services CleanPro — RBAC appliqué (OWASP A01)
 *
 * Les routes GET sont publiques (montées sans auth dans index.ts pour /services).
 * Les routes POST/PUT/PATCH/DELETE requièrent requireAuth + requireRole (montées
 * dans index.ts pour /dashboard/services).
 *
 * Ce routeur est utilisé dans deux contextes :
 *   - PUBLIC  : router.get('/services') → pas d'auth, pas de rôle
 *   - PRIVÉ   : router.use('/dashboard/services', requireAuth, servicesRouter)
 *
 * Les middlewares requireRole ci-dessous forment une défense en profondeur
 * (double vérification) même si le check requireAuth est déjà effectué en amont.
 */

// Consultation du catalogue (lecture publique — pas de restriction de rôle)
router.get('/', serviceController.getAll);
router.get('/catalog', serviceController.getAll);
router.get('/:id', serviceController.getById);

// Création d'un service (admin uniquement)
router.post('/', requireRole(...WRITE_ROLES), serviceController.create);
router.post('/catalog', requireRole(...WRITE_ROLES), serviceController.create);

// Mise à jour d'un service (admin uniquement)
router.put('/:id', requireRole(...WRITE_ROLES), serviceController.update);
router.patch('/:id', requireRole(...WRITE_ROLES), serviceController.update);

// Suppression d'un service (admin uniquement)
router.delete('/:id', requireRole(...WRITE_ROLES), serviceController.delete);

export default router;
