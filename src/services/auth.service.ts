import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import prisma from "../config/prisma.js";
import { logSecurityIncident } from "../middlewares/securityLogger.js";

/**
 * Exige un secret JWT robuste au démarrage.
 * Conforme OWASP ASVS 4.0 §2.10.4 et recommandations ANSSI.
 * L'application refuse de démarrer sans un secret d'au moins 64 caractères.
 */
function requireJwtSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.trim().length < 64) {
    console.error("");
    console.error("💥 [SÉCURITÉ CRITIQUE] JWT_SECRET absent ou trop court.");
    console.error("   Longueur minimale requise : 64 caractères aléatoires.");
    console.error("   Générez un secret sécurisé avec la commande :");
    console.error(
      "   node -e \"const c=require('crypto');console.log(c.randomBytes(64).toString('base64'))\"",
    );
    console.error("   Puis ajoutez-le dans backend/.env : JWT_SECRET=<valeur>");
    console.error("");
    process.exit(1);
  }
  return secret.trim();
}

const JWT_SECRET = requireJwtSecret();
const JWT_EXPIRES_IN = "8h";
const SALT_ROUNDS = 12; // Recommandation stricte ANSSI / OWASP

// ─── Verrouillage mémoire temporaire anti brute-force borné avec TTL & auto-purge (CWE-400) ───
interface FailedAttempt {
  count: number;
  lockedUntil?: number;
  updatedAt: number;
}

const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes
const MAX_TRACKED_ENTRIES = 5000; // Capacité maximale bornée (Protection contre l'épuisement mémoire)
const ENTRY_TTL_MS = 60 * 60 * 1000; // Durée de rétention maximale : 1 heure

/**
 * Cache mémoire borné avec politique d'éviction FIFO/LRU et nettoyage périodique.
 * Évite les attaques par déni de service mémoire (CWE-400 / OWASP ASVS §2.2.1).
 */
class BoundedAttemptTracker {
  private readonly store = new Map<string, FailedAttempt>();

  constructor() {
    // Nettoyage automatique des clés expirées toutes les 5 minutes
    const interval = setInterval(() => this.cleanup(), 5 * 60 * 1000);
    if (interval.unref) {
      interval.unref(); // N'empêche pas l'arrêt propre du processus Node.js
    }
  }

  get(key: string): FailedAttempt | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;

    const now = Date.now();
    // Expiration TTL si la clé n'est plus verrouillée
    if (
      now - entry.updatedAt > ENTRY_TTL_MS &&
      (!entry.lockedUntil || entry.lockedUntil < now)
    ) {
      this.store.delete(key);
      return undefined;
    }

    return entry;
  }

  set(key: string, entry: FailedAttempt): void {
    entry.updatedAt = Date.now();

    // Si la capacité maximale est atteinte pour une nouvelle clé, purge proactive
    if (this.store.size >= MAX_TRACKED_ENTRIES && !this.store.has(key)) {
      this.cleanup();
      // Si toujours saturé après nettoyage des expirés, éviction du plus ancien élément (FIFO)
      if (this.store.size >= MAX_TRACKED_ENTRIES) {
        const oldestKey = this.store.keys().next().value;
        if (oldestKey) {
          this.store.delete(oldestKey);
        }
      }
    }

    this.store.set(key, entry);
  }

  delete(key: string): boolean {
    return this.store.delete(key);
  }

  cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.store.entries()) {
      if (
        now - entry.updatedAt > ENTRY_TTL_MS &&
        (!entry.lockedUntil || entry.lockedUntil < now)
      ) {
        this.store.delete(key);
      }
    }
  }

  get size(): number {
    return this.store.size;
  }
}

const loginAttemptsTracker = new BoundedAttemptTracker();

export interface TokenPayload {
  userId: string;
  email: string;
  role: string;
}

export const authService = {
  /**
   * Hache un mot de passe avec un sel bcrypt robuste (12 tours)
   */
  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, SALT_ROUNDS);
  },

  /**
   * Vérifie un mot de passe en clair contre un hachage stocké
   */
  async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  },

  /**
   * Génère un jeton JWT signé avec expiration
   */
  generateToken(payload: TokenPayload): string {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
  },

  /**
   * Vérifie et décode un jeton JWT
   */
  verifyToken(token: string): TokenPayload | null {
    try {
      return jwt.verify(token, JWT_SECRET) as TokenPayload;
    } catch {
      return null;
    }
  },

  /**
   * Authentifie un utilisateur avec protection anti brute-force et audit OWASP
   */
  async login(identifier: string, rawPassword: string, ipAddress: string) {
    const trimmedIdentifier = identifier.trim().toLowerCase();
    const now = Date.now();
    const attemptKey = `${ipAddress}:${trimmedIdentifier}`;
    const attempt = loginAttemptsTracker.get(attemptKey);

    // Vérification du verrouillage temporaire (Anti Brute-Force CWE-307)
    if (attempt && attempt.lockedUntil && attempt.lockedUntil > now) {
      const remainingMinutes = Math.ceil((attempt.lockedUntil - now) / 60000);
      void logSecurityIncident({
        category: "bruteforce_lockout",
        level: "warning",
        action: "Tentative de connexion sur compte verrouillé",
        target: trimmedIdentifier,
        ipAddress,
        details: `Compte temporairement verrouillé suite à de multiples échecs (${remainingMinutes} min restantes).`,
      });
      return {
        locked: true,
        message: `Trop d'échecs de connexion. Votre accès est temporairement suspendu pour ${remainingMinutes} minute(s).`,
      };
    }

    // Recherche de l'utilisateur dans PostgreSQL (supporte l'identifiant brut ou l'adresse e-mail)
    const normalizedAlias = trimmedIdentifier.includes("@")
      ? trimmedIdentifier.split("@")[0]
      : `${trimmedIdentifier}@cleanpro.cm`;

    const user = await prisma.user.findFirst({
      where: {
        OR: [
          { email: trimmedIdentifier },
          { email: normalizedAlias },
        ],
      },
    });

    // Échec : utilisateur introuvable
    if (!user) {
      this.recordFailedAttempt(attemptKey, ipAddress, trimmedIdentifier);
      return {
        error: "Identifiant ou mot de passe incorrect.", // Message neutre anti-énumération CWE-209
      };
    }

    // Vérification cryptographique du mot de passe
    const isValid = await this.verifyPassword(rawPassword, user.password);
    if (!isValid) {
      this.recordFailedAttempt(attemptKey, ipAddress, trimmedIdentifier);
      return {
        error: "Identifiant ou mot de passe incorrect.",
      };
    }

    // Succès : réinitialisation des tentatives
    loginAttemptsTracker.delete(attemptKey);

    // Génération du token JWT
    const token = this.generateToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    });

    // Journalisation d'audit de connexion réussie
    try {
      await prisma.log.create({
        data: {
          type: "audit",
          level: "info",
          user: user.name,
          userEmail: user.email,
          action: "Connexion administrateur réussie",
          target: "Espace sécurisé Dashboard",
          ipAddress,
          result: "success",
          details: `Connexion authentifiée avec succès pour ${user.email} (${user.role}).`,
          userId: user.id,
        },
      });
    } catch {
      // Ignorer
    }

    return {
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        avatarUrl: user.avatarUrl || "",
      },
      token,
    };
  },

  /**
   * Enregistre un échec et active le verrouillage si le seuil maximal est atteint
   */
  recordFailedAttempt(key: string, ipAddress: string, identifier: string) {
    const existing = loginAttemptsTracker.get(key) || {
      count: 0,
      updatedAt: Date.now(),
    };
    existing.count += 1;
    existing.updatedAt = Date.now();

    if (existing.count >= MAX_ATTEMPTS) {
      existing.lockedUntil = Date.now() + LOCKOUT_MS;
      void logSecurityIncident({
        category: "account_lockout",
        level: "critical",
        action: "Verrouillage anti brute-force déclenché",
        target: identifier,
        ipAddress,
        details: `Seuil de ${MAX_ATTEMPTS} échecs atteint. Compte/IP verrouillé pour 15 minutes.`,
      });
    } else {
      void logSecurityIncident({
        category: "failed_login",
        level: "warning",
        action: "Échec d’authentification",
        target: identifier,
        ipAddress,
        details: `Tentative de connexion infructueuse (${existing.count}/${MAX_ATTEMPTS}).`,
      });
    }

    loginAttemptsTracker.set(key, existing);
  },

  /**
   * Récupère le profil de l'utilisateur connecté depuis PostgreSQL
   */
  async getProfile(userId: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        avatarUrl: true,
        createdAt: true,
      },
    });
    return user;
  },

  /**
   * Met à jour l'avatar de l'administrateur
   */
  async updateAvatar(userId: string, avatarUrl: string) {
    return prisma.user.update({
      where: { id: userId },
      data: { avatarUrl },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        avatarUrl: true,
      },
    });
  },

  /**
   * Met à jour le profil de l'administrateur (nom, avatar)
   */
  async updateProfile(
    userId: string,
    data: { name?: string; avatarUrl?: string },
  ) {
    const updateData: { name?: string; avatarUrl?: string } = {};
    if (data.name !== undefined) updateData.name = data.name;
    if (data.avatarUrl !== undefined) updateData.avatarUrl = data.avatarUrl;

    const user = await prisma.user.update({
      where: { id: userId },
      data: updateData,
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        avatarUrl: true,
      },
    });

    try {
      await prisma.log.create({
        data: {
          type: "audit",
          level: "info",
          user: user.name,
          userEmail: user.email,
          action: "Mise à jour du profil administrateur",
          target: user.name,
          ipAddress: "127.0.0.1",
          result: "success",
          details: `Profil mis à jour pour ${user.email} (nom: ${user.name}).`,
          userId: user.id,
        },
      });
    } catch {
      // Ignorer
    }

    return user;
  },

  /**
   * Récupère la liste de tous les comptes administrateurs depuis PostgreSQL
   */
  async listAdmins(currentUserId?: string) {
    const users = await prisma.user.findMany({
      orderBy: { createdAt: "asc" },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        avatarUrl: true,
        createdAt: true,
      },
    });

    return users.map((u) => ({
      ...u,
      avatarUrl: u.avatarUrl || "",
      isCurrentUser: Boolean(currentUserId && u.id === currentUserId),
      createdAt: new Intl.DateTimeFormat("fr-FR", {
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
      }).format(u.createdAt),
    }));
  },

  /**
   * Valide la robustesse d'un mot de passe selon la politique ANSSI / OWASP ASVS §2.1
   * Exigences : 12 caractères minimum, majuscule, minuscule, chiffre, caractère spécial.
   * Retourne un message d'erreur ou null si le mot de passe est conforme.
   */
  validatePasswordStrength(password: string): string | null {
    if (typeof password !== "string" || password.length < 12) {
      return "Le mot de passe doit comporter au moins 12 caractères.";
    }
    if (!/[A-Z]/.test(password)) {
      return "Le mot de passe doit contenir au moins une lettre majuscule.";
    }
    if (!/[a-z]/.test(password)) {
      return "Le mot de passe doit contenir au moins une lettre minuscule.";
    }
    if (!/[0-9]/.test(password)) {
      return "Le mot de passe doit contenir au moins un chiffre.";
    }
    if (!/[^A-Za-z0-9]/.test(password)) {
      return "Le mot de passe doit contenir au moins un caractère spécial (ex : @, #, !, $, …).";
    }
    return null; // Mot de passe conforme
  },

  /**
   * Crée un nouveau compte administrateur dans PostgreSQL
   * OWASP ASVS §2.1 : Un mot de passe fort est obligatoire — aucun fallback silencieux.
   */
  async createAdmin(
    data: {
      name: string;
      email: string;
      role: string;
      password: string;
      avatarUrl?: string;
    },
    createdBy?: string,
  ) {
    const trimmedEmail = data.email.trim().toLowerCase();
    const existing = await prisma.user.findUnique({
      where: { email: trimmedEmail },
    });
    if (existing) {
      throw new Error("Un compte avec cette adresse e-mail existe déjà.");
    }

    // Validation stricte du mot de passe — aucun mot de passe par défaut autorisé
    const passwordError = this.validatePasswordStrength(data.password);
    if (passwordError) {
      throw new Error(passwordError);
    }

    const passwordHash = await this.hashPassword(data.password);

    const newUser = await prisma.user.create({
      data: {
        email: trimmedEmail,
        name: data.name.trim(),
        role: data.role || "Administrateur",
        password: passwordHash,
        avatarUrl: data.avatarUrl || null,
        isCurrentUser: false,
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        avatarUrl: true,
        createdAt: true,
      },
    });

    try {
      await prisma.log.create({
        data: {
          type: "audit",
          level: "info",
          user: createdBy || "Administrateur",
          action: "Création d’un compte administrateur",
          target: newUser.email,
          ipAddress: "127.0.0.1",
          result: "success",
          details: `Compte créé pour ${newUser.name} (${newUser.email}) avec le rôle ${newUser.role}.`,
        },
      });
    } catch {
      // Ignorer
    }

    return {
      ...newUser,
      avatarUrl: newUser.avatarUrl || "",
      isCurrentUser: false,
      createdAt: new Intl.DateTimeFormat("fr-FR", {
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
      }).format(newUser.createdAt),
    };
  },

  /**
   * Supprime un compte administrateur (Protection contre auto-suppression et suppression du dernier admin)
   */
  async deleteAdmin(adminId: string, currentUserId?: string) {
    if (currentUserId && adminId === currentUserId) {
      throw new Error(
        "Action refusée : Vous ne pouvez pas supprimer votre propre compte connecté.",
      );
    }

    const totalAdmins = await prisma.user.count();
    if (totalAdmins <= 1) {
      throw new Error(
        "Action refusée : Impossible de supprimer l’unique compte administrateur du système.",
      );
    }

    const targetUser = await prisma.user.findUnique({
      where: { id: adminId },
    });
    if (!targetUser) {
      throw new Error("Compte introuvable ou déjà supprimé.");
    }

    const deleted = await prisma.user.delete({
      where: { id: adminId },
      select: { id: true, email: true, name: true },
    });

    try {
      await prisma.log.create({
        data: {
          type: "audit",
          level: "warning",
          user: "Administrateur",
          action: "Suppression d’un compte administrateur",
          target: deleted.email,
          ipAddress: "127.0.0.1",
          result: "success",
          details: `Compte administrateur révoqué : ${deleted.name} (${deleted.email}).`,
        },
      });
    } catch {
      // Ignorer
    }

    return deleted;
  },
};
