// Importation du routeur Express
import { Router, Request, Response } from 'express';
// Importation de l'utilitaire de réponse standardisée
import { sendResponse } from '../utils/apiResponse.js';
// Importation des middlewares d'authentification et de contrôle d'accès (OWASP A01)
import { requireAuth, requireRole } from '../middlewares/auth.middleware.js';
import { DASHBOARD_ROLES } from '../config/roles.js';
// Importation des routeurs
import messagesRouter from './messages.routes.js';
import logsRouter from './logs.routes.js';
import planningRouter from './planning.routes.js';
import servicesRouter from './service.routes.js';
import contactRouter from './contact.routes.js';
import authRouter from './auth.routes.js';
import settingsRouter from './settings.routes.js';
import telemetryRouter from './telemetry.routes.js';

// Instanciation du routeur principal
const router: Router = Router();

// ─── 1. Routes Publiques (Accessibles sans authentification) ──────────────────

// Diagnostic et santé de l'API (Health Check)
router.get('/health', (_req: Request, res: Response) => {
  res.status(200).json(
    sendResponse(true, 'API CleanPro opérationnelle', {
      uptime: process.uptime(),
      environment: process.env.NODE_ENV || 'development'
    })
  );
});

// Authentification (login / logout / profil)
router.use('/auth', authRouter);

// Formulaire de contact public (avec protection Rate Limit & Honeypot)
router.use('/contact', contactRouter);

// Consultation publique du catalogue des services (site vitrine — lecture seule)
router.get('/services', (req, res, next) => servicesRouter(req, res, next));
router.get('/services/:id', (req, res, next) => servicesRouter(req, res, next));

// Télémétrie du trafic & monitoring de sécurité (visiteurs vs attaquants)
router.use('/telemetry', telemetryRouter);

// ─── 2. Routes Privées Sécurisées (Dashboard & Administration) ────────────────
// OWASP A01 : Double protection — requireAuth vérifie le JWT,
// requireRole(...DASHBOARD_ROLES) vérifie le niveau d'accès.
// Les routeurs feuilles appliquent ensuite un contrôle granulaire (lecture vs écriture).

// Gestion des messages et réponses e-mails
router.use('/dashboard/messages', requireAuth, requireRole(...DASHBOARD_ROLES), messagesRouter);
router.use('/messages', requireAuth, requireRole(...DASHBOARD_ROLES), messagesRouter);

// Journaux d'audit et de sécurité
router.use('/dashboard/logs', requireAuth, requireRole(...DASHBOARD_ROLES), logsRouter);
router.use('/logs', requireAuth, requireRole(...DASHBOARD_ROLES), logsRouter);

// Planning d'interventions
router.use('/dashboard/planning', requireAuth, requireRole(...DASHBOARD_ROLES), planningRouter);
router.use('/planning', requireAuth, requireRole(...DASHBOARD_ROLES), planningRouter);

// Gestion administrative du catalogue (lecture publique, mutations admin uniquement)
router.use('/dashboard/services', requireAuth, requireRole(...DASHBOARD_ROLES), servicesRouter);
// Verrouillage des mutations directes sur /services (défense en profondeur)
router.post('/services', requireAuth, requireRole(...DASHBOARD_ROLES), (req, res, next) => servicesRouter(req, res, next));
router.put('/services/:id', requireAuth, requireRole(...DASHBOARD_ROLES), (req, res, next) => servicesRouter(req, res, next));
router.delete('/services/:id', requireAuth, requireRole(...DASHBOARD_ROLES), (req, res, next) => servicesRouter(req, res, next));

// Paramètres entreprise et configuration
router.use('/dashboard/settings', requireAuth, requireRole(...DASHBOARD_ROLES), settingsRouter);
router.use('/settings', requireAuth, requireRole(...DASHBOARD_ROLES), settingsRouter);

// Exportation par défaut du routeur
export default router;
