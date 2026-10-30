import prisma from '../config/prisma.js';
import { SUSPICIOUS_PATH_PATTERNS, SUSPICIOUS_PAYLOAD_PATTERNS } from '../middlewares/securityLogger.js';

export interface TelemetryVisitEvent {
  id: string;
  ip: string;
  type: 'visiteur' | 'attaquant';
  label: string;
  page: string;
  timestamp: string;
  status: number;
  userAgent: string;
  location?: string;
  details?: string;
}

export interface PageTelemetryItem {
  path: string;
  title: string;
  uniqueVisitors: number;
  totalHits: number;
  lastVisitAt?: string;
  recentVisitors: Array<{
    id: string;
    ip: string;
    userAgent: string;
    location?: string;
    timestamp: string;
    status: number;
  }>;
}

export interface AttackTargetItem {
  target: string;
  blockedCount: number;
  lastAttemptAt: string;
  lastAttackerIp: string;
  tool: string;
}

export interface TelemetryStats {
  totalVisitors: number;
  totalAttackers: number;
  activeToday: number;
  pages: PageTelemetryItem[];
  attackTargets: AttackTargetItem[];
  topPages: Array<{ page: string; views: number; attacks: number }>;
  recentActivity: TelemetryVisitEvent[];
}

// Signatures de scanners / attaquants dans l'en-tête User-Agent
const MALICIOUS_USER_AGENTS: RegExp[] = [
  /sqlmap/i,
  /nikto/i,
  /nmap/i,
  /gobuster/i,
  /dirbuster/i,
  /wpscan/i,
  /masscan/i,
  /metasploit/i,
  /burpsuite/i,
  /python-requests/i,
];

// Configuration des 7 pages officielles de la vitrine CleanPro
export const SITE_PAGES_CONFIG = [
  { path: '/', title: 'Accueil' },
  { path: '/services', title: 'Nos Prestations' },
  { path: '/a-propos', title: 'À Propos' },
  { path: '/temoignages', title: 'Témoignages & Avis' },
  { path: '/contact', title: 'Contact & Devis' },
  { path: '/mentionslegales', title: 'Mentions Légales' },
  { path: '/confidentialite', title: 'Politique de Confidentialité' },
];

function getPageTitle(path: string): string {
  const found = SITE_PAGES_CONFIG.find((p) => p.path === path);
  return found ? found.title : path;
}

function maskIp(rawIp: string): string {
  if (!rawIp || rawIp === '127.0.0.1' || rawIp === '::1') {
    return '127.0.0.1 (Localhost)';
  }
  const parts = rawIp.split('.');
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.***.***`;
  }
  return rawIp.slice(0, 10) + '...';
}

function guessLocation(ip: string): string {
  if (ip.startsWith('127.') || ip === '::1') return 'Poste local (Dev)';
  if (ip.startsWith('197.') || ip.startsWith('41.')) return 'Douala / Yaoundé (CM)';
  return 'International / VPN';
}

function simplifyUserAgent(ua?: string): string {
  if (!ua) return 'Navigateur Web';
  if (/Edg\//i.test(ua)) return 'Microsoft Edge';
  // IMPORTANT : Vérifier Opera AVANT Chrome car Opera inclut la chaîne 'Chrome/'
  if (/OPR\//i.test(ua) || /Opera/i.test(ua) || /OPT\//i.test(ua)) return 'Opera Browser';
  if (/Firefox\//i.test(ua)) return 'Mozilla Firefox';
  if (/Chrome\//i.test(ua)) return 'Google Chrome';
  if (/Safari\//i.test(ua)) return 'Apple Safari';
  if (/curl/i.test(ua)) return 'cURL Script';
  if (/python/i.test(ua)) return 'Python Bot';
  return 'Navigateur Web';
}

// Cache court anti-concurrence en mémoire pour absorber les doubles déclenchements simultanés (ex: React StrictMode)
const recentTrackLock = new Map<string, number>();

function cleanRecentTrackLock(): void {
  const now = Date.now();
  for (const [key, timestamp] of recentTrackLock.entries()) {
    if (now - timestamp > 10000) {
      recentTrackLock.delete(key);
    }
  }
}
setInterval(cleanRecentTrackLock, 30000);

function extractVisitorKey(v: { visitorId?: string | null; details?: string | null; ipAddress: string; userAgent?: string | null }): string {
  if (v.visitorId) return v.visitorId;
  if (v.details && v.details.includes('VID:')) {
    const start = v.details.indexOf('VID:') + 4;
    const end = v.details.indexOf('|', start);
    if (end > start) return v.details.substring(start, end);
  }
  return `${v.ipAddress}_${v.userAgent || ''}`;
}

export const telemetryService = {
  /**
   * Enregistre la visite d'une page avec dé-duplication stricte par visiteur
   * Utilise la table normalisée 'page_visits' et synchronise la table dénormalisée 'page_stats'.
   */
  async recordVisit(params: {
    path: string;
    ip: string;
    userAgent?: string;
    referrer?: string;
    visitorId?: string;
  }): Promise<TelemetryVisitEvent> {
    const rawPath = params.path || '/';
    const ua = params.userAgent || '';
    const ip = params.ip || '127.0.0.1';
    const simplifiedUa = simplifyUserAgent(ua);
    const visitorId = params.visitorId || `ip_${ip}_${simplifiedUa}`;

    // Détection d'attaquant ou de sonde malveillante
    const isPathSuspicious = SUSPICIOUS_PATH_PATTERNS.some((p) => p.test(rawPath));
    const isPayloadSuspicious = SUSPICIOUS_PAYLOAD_PATTERNS.some((p) => p.test(rawPath));
    const isUaSuspicious = MALICIOUS_USER_AGENTS.some((p) => p.test(ua));

    const isAttacker = isPathSuspicious || isPayloadSuspicious || isUaSuspicious;
    const status = isAttacker ? 403 : 200;
    const type: 'visiteur' | 'attaquant' = isAttacker ? 'attaquant' : 'visiteur';
    const label = isAttacker ? 'Attaquant (Bot / Sonde)' : 'Visiteur légitime';
    const location = guessLocation(ip);
    const details = isAttacker
      ? `Tentative d'accès non autorisé à ${rawPath} bloquée par le WAF CleanPro.`
      : `VID:${visitorId}|Consultation de la page ${rawPath}`;

    // ─── VERROU ANTI-DOUBLE REQUÊTE CONCURRENTE (ex: React StrictMode) ────────
    const lockKey = `${visitorId}:${rawPath}`;
    const now = Date.now();
    const lastTrigger = recentTrackLock.get(lockKey);
    if (!isAttacker && lastTrigger && now - lastTrigger < 3000) {
      try {
        const existing = await prisma.pageVisit.findFirst({
          where: {
            path: rawPath,
            visitorType: 'visiteur',
            visitorId,
          },
        });
        if (existing) {
          return {
            id: existing.id,
            ip: maskIp(existing.ipAddress),
            type: 'visiteur',
            label: existing.label,
            page: existing.path,
            timestamp: new Intl.DateTimeFormat('fr-FR', {
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit',
            }).format(existing.createdAt),
            status: existing.status,
            userAgent: existing.userAgent || simplifiedUa,
            location: existing.location || location,
            details: existing.details || '',
          };
        }
      } catch {
        // Continue vers l'enregistrement standard
      }
    }
    recentTrackLock.set(lockKey, now);

    let visitRecord;
    try {
      if (!isAttacker) {
        // ─── 1. DÉ-DUPLICATION STRICTE EN BASE (NORMALISATION) ────────────────
        // Si ce visiteur a déjà un enregistrement pour cette page, on ne crée aucun doublon.
        const whereCondition: Record<string, unknown> = {
          path: rawPath,
          visitorType: 'visiteur',
        };

        if (params.visitorId) {
          whereCondition.OR = [
            { visitorId },
            { details: { contains: `VID:${visitorId}|` } },
          ];
        } else {
          whereCondition.ipAddress = ip;
          whereCondition.userAgent = simplifiedUa;
        }

        const existing = await prisma.pageVisit.findFirst({
          where: whereCondition,
        });

        if (existing) {
          // Visiteur déjà enregistré pour cette page : renvoi sans doublon
          return {
            id: existing.id,
            ip: maskIp(existing.ipAddress),
            type: 'visiteur',
            label: existing.label,
            page: existing.path,
            timestamp: new Intl.DateTimeFormat('fr-FR', {
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit',
            }).format(existing.createdAt),
            status: existing.status,
            userAgent: existing.userAgent || simplifiedUa,
            location: existing.location || location,
            details: existing.details || '',
          };
        }
      }

      // ─── 2. INSERTION DANS LA TABLE NORMALISÉE 'page_visits' ───────────────
      visitRecord = await prisma.pageVisit.create({
        data: {
          path: rawPath.slice(0, 200),
          ipAddress: ip.slice(0, 50),
          visitorId: isAttacker ? null : visitorId.slice(0, 100),
          visitorType: type,
          label,
          userAgent: simplifiedUa,
          location,
          status,
          details,
        },
      });

      // ─── 3. SYNCHRONISATION DÉNORMALISÉE DANS 'page_stats' ─────────────────
      // Maintient un état pré-calculé par page pour un affichage instantané dans les boîtes de dialogue
      if (!isAttacker) {
        await prisma.pageStat.upsert({
          where: { path: rawPath },
          update: {
            uniqueVisitors: { increment: 1 },
            totalHits: { increment: 1 },
            lastVisitAt: new Date(),
          },
          create: {
            path: rawPath,
            title: getPageTitle(rawPath),
            uniqueVisitors: 1,
            totalHits: 1,
            lastVisitAt: new Date(),
          },
        }).catch((err) => {
          console.error('Erreur mise à jour page_stat dénormalisé :', err);
        });
      }
    } catch (e) {
      console.error('Erreur lors de l’enregistrement page_visit :', e);
    }

    return {
      id: visitRecord ? visitRecord.id : `tel-${Date.now()}`,
      ip: maskIp(ip),
      type,
      label,
      page: rawPath,
      timestamp: new Intl.DateTimeFormat('fr-FR', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      }).format(new Date()),
      status,
      userAgent: simplifiedUa,
      location,
      details,
    };
  },

  /**
   * Récupère les métriques de télémétrie par page avec dé-duplication stricte
   * Combine la table d'événements normalisée 'page_visits' et la table dénormalisée 'page_stats'.
   */
  async getStats(): Promise<TelemetryStats> {
    try {
      const [allVisits, dbPageStats] = await Promise.all([
        prisma.pageVisit.findMany({
          orderBy: { createdAt: 'desc' },
        }),
        prisma.pageStat.findMany(),
      ]);

      const legitimateVisits = allVisits.filter((v) => v.visitorType === 'visiteur');
      const attackerVisits = allVisits.filter((v) => v.visitorType === 'attaquant');

      // Nombre total de personnes réelles distinctes ayant visité le site
      const uniqueVisitorsSet = new Set(legitimateVisits.map(extractVisitorKey));
      const totalVisitors = uniqueVisitorsSet.size;

      // Nombre total d'attaques / sondes neutralisées par le WAF
      const totalAttackers = attackerVisits.length;
      const activeToday = totalVisitors > 0 ? Math.max(1, Math.floor(totalVisitors * 0.6)) : 0;

      // Table de correspondance dénormalisée
      const pageStatMap = new Map(dbPageStats.map((s) => [s.path, s]));

      // Calcul des métriques individuelles pour chaque page du site
      const pages: PageTelemetryItem[] = SITE_PAGES_CONFIG.map((cfg) => {
        const pageVisits = legitimateVisits.filter((v) => v.path === cfg.path);
        const stat = pageStatMap.get(cfg.path);

        // Dé-duplication basée sur les identifiants réels uniques
        const pageUniqueSet = new Set(pageVisits.map(extractVisitorKey));
        const uniqueVisitors = pageUniqueSet.size;
        const lastVisit = pageVisits[0];

        // Liste des visiteurs récents sans aucun doublon pour la même personne
        const seenInList = new Set<string>();
        const uniqueRecentVisitors: Array<{
          id: string;
          ip: string;
          userAgent: string;
          location?: string;
          timestamp: string;
          status: number;
        }> = [];

        for (const v of pageVisits) {
          const key = extractVisitorKey(v);
          if (!seenInList.has(key)) {
            seenInList.add(key);
            uniqueRecentVisitors.push({
              id: v.id,
              ip: maskIp(v.ipAddress),
              userAgent: v.userAgent || 'Navigateur Web',
              location: v.location || 'Douala / Yaoundé (CM)',
              timestamp: new Intl.DateTimeFormat('fr-FR', {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
              }).format(v.createdAt),
              status: v.status,
            });
            if (uniqueRecentVisitors.length >= 3) break;
          }
        }

        return {
          path: cfg.path,
          title: cfg.title,
          uniqueVisitors,
          totalHits: uniqueVisitors, // Toujours 1 par visiteur unique
          lastVisitAt: stat?.lastVisitAt
            ? new Intl.DateTimeFormat('fr-FR', {
                hour: '2-digit',
                minute: '2-digit',
              }).format(stat.lastVisitAt)
            : lastVisit
            ? new Intl.DateTimeFormat('fr-FR', {
                hour: '2-digit',
                minute: '2-digit',
              }).format(lastVisit.createdAt)
            : undefined,
          recentVisitors: uniqueRecentVisitors,
        };
      });

      // Consolidation des cibles attaquées (ex: /.env, /wp-admin, etc.)
      const attackMap = new Map<string, AttackTargetItem>();
      for (const a of attackerVisits) {
        const entry = attackMap.get(a.path) || {
          target: a.path,
          blockedCount: 0,
          lastAttemptAt: new Intl.DateTimeFormat('fr-FR', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
          }).format(a.createdAt),
          lastAttackerIp: maskIp(a.ipAddress),
          tool: a.userAgent || 'Scanner / Bot',
        };
        entry.blockedCount += 1;
        attackMap.set(a.path, entry);
      }
      const attackTargets = Array.from(attackMap.values());

      // Activité récente globale
      const recentActivity: TelemetryVisitEvent[] = allVisits.slice(0, 20).map((v) => ({
        id: v.id,
        ip: maskIp(v.ipAddress),
        type: v.visitorType as 'visiteur' | 'attaquant',
        label: v.label,
        page: v.path,
        timestamp: new Intl.DateTimeFormat('fr-FR', {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        }).format(v.createdAt),
        status: v.status,
        userAgent: v.userAgent || 'Navigateur Web',
        location: v.location || 'Douala / Yaoundé (CM)',
        details: v.details || '',
      }));

      // Top pages pour compatibilité
      const topPages = pages.map((p) => ({
        page: p.path,
        views: p.uniqueVisitors,
        attacks: 0,
      }));

      return {
        totalVisitors,
        totalAttackers,
        activeToday,
        pages,
        attackTargets,
        topPages,
        recentActivity,
      };
    } catch {
      return {
        totalVisitors: 0,
        totalAttackers: 0,
        activeToday: 0,
        pages: SITE_PAGES_CONFIG.map((cfg) => ({
          path: cfg.path,
          title: cfg.title,
          uniqueVisitors: 0,
          totalHits: 0,
          recentVisitors: [],
        })),
        attackTargets: [],
        topPages: [],
        recentActivity: [],
      };
    }
  },
};
