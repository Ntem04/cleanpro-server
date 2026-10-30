import { Request, Response, NextFunction } from 'express';
import { authService } from '../services/auth.service.js';
import { sendResponse } from '../utils/apiResponse.js';
import { extractClientIp } from '../middlewares/securityLogger.js';

export const authController = {
  /**
   * POST /api/v1/auth/login
   * Authentification avec émission du JWT en cookie HttpOnly + SameSite + Secure
   */
  async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { identifier, password } = req.body;

      if (!identifier || !password) {
        res.status(400).json(
          sendResponse(false, 'Identifiant et mot de passe requis.')
        );
        return;
      }

      const ip = extractClientIp(req);
      const result = await authService.login(identifier, password, ip);

      if (result.locked) {
        res.status(429).json(sendResponse(false, result.message));
        return;
      }

      if (result.error || !result.user || !result.token) {
        res.status(401).json(sendResponse(false, result.error || 'Échec de connexion.'));
        return;
      }

      // Émission du jeton exclusivement en Cookie HttpOnly (Anti-XSS absolu, OWASP A07 & CWE-312)
      // Le token JWT n'est JAMAIS renvoyé dans le corps JSON pour empêcher tout vol par script JS (XSS).
      res.cookie('cleanpro_jwt', result.token, {
        httpOnly: true, // Inaccessible aux scripts client / document.cookie
        secure: process.env.NODE_ENV === 'production', // Forcé HTTPS en production
        sameSite: 'lax', // Protection anti-CSRF native
        maxAge: 8 * 60 * 60 * 1000, // 8 heures
        path: '/',
      });

      res.status(200).json(
        sendResponse(true, 'Connexion réussie', {
          user: result.user,
        })
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * POST /api/v1/auth/logout
   * Déconnexion sécurisée et suppression des cookies de session
   */
  async logout(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      res.clearCookie('cleanpro_jwt', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
      });

      res.status(200).json(
        sendResponse(true, 'Déconnexion effectuée avec succès.')
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * GET /api/v1/auth/me
   * Récupère le profil administrateur de la session active
   */
  async getProfile(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json(sendResponse(false, 'Non authentifié.'));
        return;
      }

      const user = await authService.getProfile(req.user.userId);
      if (!user) {
        res.status(404).json(sendResponse(false, 'Utilisateur introuvable.'));
        return;
      }

      res.status(200).json(
        sendResponse(true, 'Profil administrateur récupéré', user)
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * PATCH /api/v1/auth/avatar
   * Mise à jour de la photo de profil administrateur
   */
  async updateAvatar(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json(sendResponse(false, 'Non authentifié.'));
        return;
      }

      const { avatarUrl } = req.body;
      if (typeof avatarUrl !== 'string') {
        res.status(400).json(sendResponse(false, 'Format d’avatar invalide.'));
        return;
      }

      const updated = await authService.updateAvatar(req.user.userId, avatarUrl);
      res.status(200).json(
        sendResponse(true, 'Avatar mis à jour avec succès.', updated)
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * PATCH /api/v1/auth/profile
   * Mise à jour du nom et profil de l'administrateur
   */
  async updateProfile(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json(sendResponse(false, 'Non authentifié.'));
        return;
      }

      const { name, avatarUrl } = req.body;
      if (name !== undefined && (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 100)) {
        res.status(400).json(sendResponse(false, 'Le nom doit comporter entre 2 et 100 caractères.'));
        return;
      }

      const updated = await authService.updateProfile(req.user.userId, {
        name: typeof name === 'string' ? name.trim() : undefined,
        avatarUrl: typeof avatarUrl === 'string' ? avatarUrl.trim() : undefined,
      });

      res.status(200).json(
        sendResponse(true, 'Profil administrateur mis à jour avec succès.', updated)
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * GET /api/v1/auth/admins
   * Liste les comptes administrateurs depuis PostgreSQL
   */
  async listAdmins(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const admins = await authService.listAdmins(req.user?.userId);
      res.status(200).json(
        sendResponse(true, 'Comptes administrateurs récupérés', admins)
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * POST /api/v1/auth/admins
   * Création d'un nouveau compte administrateur avec mot de passe haché
   */
  async createAdmin(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { name, email, role, password, avatarUrl } = req.body;
      if (!name || !email || !password) {
        res.status(400).json(sendResponse(false, 'Nom, e-mail et mot de passe obligatoires.'));
        return;
      }

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        res.status(400).json(sendResponse(false, 'Format d’adresse e-mail invalide.'));
        return;
      }

      const passwordError = authService.validatePasswordStrength(password);
      if (passwordError) {
        res.status(400).json(sendResponse(false, passwordError));
        return;
      }

      const admin = await authService.createAdmin(
        { name, email, role, password, avatarUrl },
        req.user?.email
      );

      res.status(201).json(
        sendResponse(true, 'Compte administrateur créé avec succès', admin)
      );
    } catch (error: any) {
      if (error?.message?.includes('déjà')) {
        res.status(409).json(sendResponse(false, error.message));
        return;
      }
      if (error?.message?.includes('mot de passe') || error?.message?.includes('caractères')) {
        res.status(400).json(sendResponse(false, error.message));
        return;
      }
      next(error);
    }
  },

  /**
   * DELETE /api/v1/auth/admins/:id
   * Suppression d'un compte administrateur
   */
  async deleteAdmin(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const adminId = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
      if (!adminId) {
        res.status(400).json(sendResponse(false, 'Identifiant requis.'));
        return;
      }

      const deleted = await authService.deleteAdmin(adminId, req.user?.userId);
      res.status(200).json(
        sendResponse(true, 'Compte administrateur révoqué avec succès', deleted)
      );
    } catch (error: any) {
      if (error?.message?.includes('refusée') || error?.message?.includes('supprimer')) {
        res.status(400).json(sendResponse(false, error.message));
        return;
      }
      next(error);
    }
  },
};

