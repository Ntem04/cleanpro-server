/**
 * Module de Logging Centralisé CleanPro (Normes OWASP & RGPD)
 * - Journal d'Audit : Traçabilité des actions (« Qui a fait quoi »)
 * - Journal Technique : Détection et diagnostic des pannes (« Ce qui a planté »)
 */

export type LogLevel = 'info' | 'warning' | 'error' | 'critical';
export type LogResult = 'success' | 'failure';
export type LogType = 'audit' | 'technical';

export interface LogEntry {
  timestamp: string;
  type: LogType;
  level: LogLevel;
  user: string;
  userEmail?: string;
  action: string;
  target: string;
  ipAddress: string;
  result: LogResult;
  details: string;
  metadata?: Record<string, unknown>;
}

// Clés strictement interdites dans les logs (Sécurité OWASP / RGPD / Non-divulgation)
export function isSensitiveField(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[^a-z]/g, '');
  return (
    normalized.includes('password') ||
    normalized.includes('motdepasse') ||
    normalized.includes('secret') ||
    normalized.includes('token') ||
    normalized.includes('jwt') ||
    normalized.includes('bearer') ||
    normalized.includes('session') ||
    normalized.includes('cookie') ||
    normalized.includes('authorization') ||
    normalized.includes('messagecontent') ||
    normalized === 'message' ||
    normalized.includes('visitormessage') ||
    normalized.includes('contactmessage')
  );
}

/**
 * Nettoie récursivement un objet de métadonnées pour exclure toute donnée sensible
 * (Ne jamais enregistrer mots de passe, tokens, ni contenu complet de message)
 */
export function sanitizeLogData(data: unknown): unknown {
  if (data === null || typeof data !== 'object') {
    return data;
  }

  if (Array.isArray(data)) {
    return data.map(sanitizeLogData);
  }

  const sanitized: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(data as Record<string, unknown>)) {
    if (isSensitiveField(key)) {
      sanitized[key] = '[CONFIDENTIEL - MASQUÉ - SÉCURITÉ OWASP]';
    } else {
      sanitized[key] = sanitizeLogData(val);
    }
  }
  return sanitized;
}

/**
 * Journalise une action d'audit (Traçabilité administrative)
 */
export function logAudit(entry: Omit<LogEntry, 'type' | 'timestamp'>): LogEntry {
  const fullEntry: LogEntry = {
    ...entry,
    type: 'audit',
    timestamp: new Date().toISOString(),
    metadata: entry.metadata ? (sanitizeLogData(entry.metadata) as Record<string, unknown>) : undefined,
  };

  const line = `[AUDIT] [${fullEntry.timestamp}] [${fullEntry.level.toUpperCase()}] [User: ${fullEntry.user}] [Action: ${fullEntry.action}] [Target: ${fullEntry.target}] [IP: ${fullEntry.ipAddress}] [Result: ${fullEntry.result.toUpperCase()}]`;

  if (fullEntry.level === 'critical' || fullEntry.level === 'warning') {
    console.warn(line, fullEntry.details);
  } else {
    console.log(line, fullEntry.details);
  }

  return fullEntry;
}

/**
 * Journalise une erreur ou un incident technique (Monitoring système)
 */
export function logTechnical(entry: Omit<LogEntry, 'type' | 'timestamp'>): LogEntry {
  const fullEntry: LogEntry = {
    ...entry,
    type: 'technical',
    timestamp: new Date().toISOString(),
    metadata: entry.metadata ? (sanitizeLogData(entry.metadata) as Record<string, unknown>) : undefined,
  };

  const line = `[TECH] [${fullEntry.timestamp}] [${fullEntry.level.toUpperCase()}] [Action: ${fullEntry.action}] [Target: ${fullEntry.target}] [IP: ${fullEntry.ipAddress}] [Result: ${fullEntry.result.toUpperCase()}]`;

  if (fullEntry.level === 'error' || fullEntry.level === 'critical') {
    console.error(line, fullEntry.details, fullEntry.metadata);
  } else {
    console.warn(line, fullEntry.details);
  }

  return fullEntry;
}

export default {
  logAudit,
  logTechnical,
  sanitizeLogData,
};

