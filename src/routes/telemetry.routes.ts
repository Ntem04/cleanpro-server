import { Router } from 'express';
import { telemetryController } from '../controllers/telemetry.controller.js';

const router: Router = Router();

// Enregistrement anonyme d'une visite de page
router.post('/track', telemetryController.trackVisit);

// Consultation des statistiques de fréquentation et attaques
router.get('/stats', telemetryController.getStats);

export default router;

