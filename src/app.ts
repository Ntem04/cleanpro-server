// Importation du framework Express
import express, { Application, Request, Response } from 'express';
// Importation du middleware CORS pour la gestion des origines autorisées
import cors from 'cors';
// Parser de cookies sécurisés
import cookieParser from 'cookie-parser';
// Helmet : En-têtes HTTP de sécurité (HSTS, No-Sniff, XSS-Filter, Frameguard)
import helmet from 'helmet';
// Importation des routes principales de l'API
import routes from './routes/index.js';
// Bouclier OWASP A09 : Détecteur de sondes et scanners d'attaquants
import { securityProbeDetector } from './middlewares/securityLogger.js';
// Protection CSRF (Double Submit Cookie Pattern conforme OWASP)
import { csrfProtection } from './middlewares/csrf.middleware.js';
// Gestionnaire d'erreurs global (Capture des crashs 500 sans fuite de stack trace CWE-209)
import { globalErrorHandler } from './middlewares/errorHandler.js';

// Création de l'instance de l'application Express
const app: Application = express();

// ─── 1. En-têtes de Sécurité HTTP & HSTS (Helmet) ───────────────────────────
// Conforme OWASP & ANSSI : HSTS forcé sur 1 an avec sous-domaines, no-sniff, deny iframe
app.use(
  helmet({
    contentSecurityPolicy: false, // Laisse la flexibilité pour Vite & assets statiques en dev
    hsts: {
      maxAge: 31536000, // 1 an en secondes
      includeSubDomains: true,
      preload: true,
    },
    xContentTypeOptions: true, // X-Content-Type-Options: nosniff
    xFrameOptions: { action: 'deny' }, // X-Frame-Options: DENY (anti-Clickjacking)
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    hidePoweredBy: true, // Masque la signature X-Powered-By
  })
);

// Optimisation payload & sécurité : masquage strict de la signature serveur (CWE-200)
app.disable('x-powered-by');

const rawClientUrl = process.env.CLIENT_URL?.trim();
const allowedOrigins = [
  rawClientUrl,
  rawClientUrl?.replace(/\/$/, ''),
  'http://localhost:5173',
  'http://localhost:3000',
].filter(Boolean) as string[];

// ─── 2. Configuration CORS Stricte ───────────────────────────────────────────
app.use(
  cors({
    origin: (origin, callback) => {
      // Autorise les requêtes sans origine (ex: curl, mobile) ou les origines autorisées
      if (
        !origin ||
        allowedOrigins.includes(origin) ||
        origin.endsWith('.vercel.app') ||
        origin.includes('localhost') ||
        origin.includes('127.0.0.1') ||
        process.env.NODE_ENV === 'development'
      ) {
        callback(null, true);
      } else {
        callback(new Error(`Origine non autorisée par la politique CORS : ${origin}`));
      }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    credentials: true, // Autorise l'échange sécurisé des cookies HttpOnly et CSRF
  })
);

// ─── 3. Parsers de Corps & Cookies ────────────────────────────────────────────
app.use(cookieParser());
app.use(express.json({ limit: '10mb' })); // Limitation 10 Mo pour supporter les avatars d'administration
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ─── 4. Boucliers de Sécurité Applicative ──────────────────────────────────────
// Interception active des sondes malveillantes (chemins sensibles, injections d'URLs)
app.use(securityProbeDetector);

// Protection CSRF avec émission et validation des jetons
app.use(csrfProtection);

// ─── 5. Montage des Routes Versionnées (/api/v1 et alias /api) ────────────────
app.use('/api/v1', routes);
app.use('/api', routes);

// Route d'accueil racine pour vérifier la disponibilité générale
app.get('/', (_req: Request, res: Response) => {
  res.json({
    name: 'CleanPro Backend API',
    status: 'Running',
    version: '1.0.0',
    documentation: '/api/v1/health',
  });
});

// ─── 6. Gestion des Routes Inexistantes (404 Not Found) ───────────────────────
app.use((req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    message: `Ressource introuvable : ${req.method} ${req.originalUrl}`,
  });
});

// ─── 7. Middleware Global de Gestion des Erreurs (Dernier middleware) ─────────
app.use(globalErrorHandler);

// Exportation de l'application Express configurée
export default app;
