import { Router } from 'express';
import { contactController } from '../controllers/contact.controller.js';
import { contactRateLimiter } from '../middlewares/rateLimiter.js';

const router: Router = Router();

/**
 * Route publique pour le Formulaire de Contact
 * Protection anti-spam / anti-bruteforce (express-rate-limit)
 * Enregistre la demande en base PostgreSQL, émet une alerte email Gmail & un log d'audit
 */
router.post('/', contactRateLimiter, contactController.submitPublicContact);

export default router;
