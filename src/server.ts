// Chargement des variables d'environnement depuis le fichier .env
import 'dotenv/config';
// Importation de l'application Express
import app from './app.js';
// Vérification SMTP au démarrage
import { verifyMailerConnection } from './utils/mailer.js';
// Purge automatique des journaux (Anti-Saturation & RGPD)
import { logsService } from './services/logs.service.js';

// Récupération du port d'écoute (par défaut 5000)
const PORT = process.env.PORT || 5000;
const RETENTION_DAYS = parseInt(process.env.LOG_RETENTION_DAYS || '90', 10);

// Démarrage du serveur HTTP et écoute sur le port configuré
const server = app.listen(PORT, async () => {
  // Affichage du log de succès avec les informations d'exécution
  console.log(`🚀 Serveur CleanPro actif sur http://localhost:${PORT}`);
  console.log(`🏥 Route de santé : http://localhost:${PORT}/api/v1/health`);

  // Test de connexion SMTP au démarrage (spécification transporter.verify)
  await verifyMailerConnection();

  // Purge initiale et programmation du nettoyage quotidien (Anti-saturation de la base)
  try {
    const purgeResult = await logsService.purgeOldLogs(RETENTION_DAYS);
    if (purgeResult.purgedCount > 0) {
      console.log(`🧹 [RGPD Purge] ${purgeResult.purgedCount} anciens logs supprimés au démarrage.`);
    }
  } catch (err) {
    console.warn('⚠️ [RGPD Purge] Avertissement lors de la purge initiale :', (err as Error).message);
  }

  // Planification récurrente toutes les 24 heures (86 400 000 ms)
  setInterval(async () => {
    try {
      await logsService.purgeOldLogs(RETENTION_DAYS);
    } catch {
      // Ignorer silencieusement
    }
  }, 24 * 60 * 60 * 1000);
});

// Interception des erreurs de promesses non gérées pour éviter un arrêt brutal imprévu (CWE-755)
process.on('unhandledRejection', (reason: Error) => {
  console.error('❌ Erreur critique non gérée :', reason.message);
  // Fermeture propre du serveur avant arrêt du processus
  server.close(() => process.exit(1));
});
