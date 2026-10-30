/**
 * Définition centralisée des rôles CleanPro
 * OWASP A01 : Broken Access Control — Contrôle d'accès basé sur les rôles (RBAC)
 * Référence : OWASP ASVS 4.0 §4.1 — Politique de contrôle d'accès
 *
 * Hiérarchie des rôles (du plus au moins privilégié) :
 *   SUPER_ADMIN > ADMIN > RESPONSABLE
 *
 * Toute modification de cette hiérarchie doit être tracée dans le journal d'audit.
 */

export const ROLES = {
  /** Super administrateur — accès total, gestion des comptes et des secrets */
  SUPER_ADMIN: 'Super Administrateur',

  /** Administrateur standard — accès complet au dashboard opérationnel */
  ADMIN: 'admin',

  /** Responsable d'agence — accès limité (planning et messages uniquement) */
  RESPONSABLE: "Responsable d'agence",
} as const;

export type AppRole = (typeof ROLES)[keyof typeof ROLES];

/**
 * Rôles autorisant la gestion des comptes administrateurs (création / suppression)
 * Uniquement le Super Administrateur peut créer ou supprimer d'autres comptes.
 */
export const ADMIN_MANAGEMENT_ROLES: AppRole[] = [ROLES.SUPER_ADMIN, ROLES.ADMIN];

/**
 * Rôles autorisant l'accès complet au dashboard opérationnel
 * (messages, planning, services, paramètres, logs)
 */
export const DASHBOARD_ROLES: AppRole[] = [
  ROLES.SUPER_ADMIN,
  ROLES.ADMIN,
  ROLES.RESPONSABLE,
];

/**
 * Rôles autorisant les mutations sensibles (écriture, suppression)
 * Responsable d'agence : lecture seule
 */
export const WRITE_ROLES: AppRole[] = [ROLES.SUPER_ADMIN, ROLES.ADMIN];

