import { Request, Response, NextFunction } from 'express';
import { prisma } from '../config/prisma.js';
import { contactService, MessageStatus } from '../services/contact.service.js';
import { sendResponse } from '../utils/apiResponse.js';
import { logSecurityIncident } from '../middlewares/securityLogger.js';

// Regex e-mail conforme RFC 5322 simplifiée mais robuste (OWASP Validation)
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

/**
 * Valide et assainit le formulaire de contact (CWE-20 & Protection anti-DoS CWE-400)
 */
function validateContactPayload(body: unknown): {
  error?: string;
  isSpam?: boolean;
  value?: {
    name: string;
    email: string;
    subject?: string;
    message: string;
  };
} {
  if (!body || typeof body !== 'object') {
    return { error: 'Corps de requête invalide (JSON attendu).' };
  }

  const payload = body as Record<string, unknown>;

  // Piège anti-robot (Honeypot) : si ce champ masqué est rempli par un bot, on intercepte
  if (payload.website || payload.honeypot || payload.botField) {
    return { isSpam: true };
  }

  // Support des deux conventions : { name, email, message } et { sender, email, content }
  const rawName = payload.name ?? payload.sender;
  const rawEmail = payload.email;
  const rawSubject = payload.subject;
  const rawMessage = payload.message ?? payload.content;

  // Validation du nom (obligatoire, 2 à 100 caractères)
  if (!rawName || typeof rawName !== 'string') {
    return { error: 'Le nom est obligatoire.' };
  }
  const name = rawName.trim();
  if (name.length < 2 || name.length > 100) {
    return { error: 'Le nom doit comporter entre 2 et 100 caractères.' };
  }

  // Validation de l'e-mail (obligatoire, format strict, max 150 caractères)
  if (!rawEmail || typeof rawEmail !== 'string') {
    return { error: 'Une adresse e-mail valide est obligatoire.' };
  }
  const email = rawEmail.trim().toLowerCase();
  if (email.length > 150 || !EMAIL_REGEX.test(email)) {
    return { error: 'Adresse e-mail invalide.' };
  }

  // Validation du sujet (optionnel, max 150 caractères)
  let subject: string | undefined;
  if (rawSubject !== undefined && rawSubject !== null) {
    if (typeof rawSubject !== 'string') {
      return { error: 'Le sujet doit être une chaîne de caractères.' };
    }
    if (rawSubject.length > 150) {
      return { error: 'Le sujet ne peut pas dépasser 150 caractères.' };
    }
    subject = rawSubject.trim();
  }

  // Validation du corps du message (obligatoire, 5 à 4000 caractères max anti-DoS)
  if (!rawMessage || typeof rawMessage !== 'string') {
    return { error: 'Le message est obligatoire.' };
  }
  const message = rawMessage.trim();
  if (message.length < 5) {
    return { error: 'Le message doit comporter au moins 5 caractères.' };
  }
  if (message.length > 4000) {
    return { error: 'Le message ne peut pas dépasser 4000 caractères.' };
  }

  return {
    value: {
      name,
      email,
      subject,
      message,
    },
  };
}

/**
 * Extrait l'adresse IP cliente de manière sécurisée
 */
function getClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }
  return req.ip || req.socket.remoteAddress || '127.0.0.1';
}

/**
 * Contrôleur HTTP pour les Messages et le Formulaire de Contact
 */
export const contactController = {
  /**
   * POST /api/v1/contact (Formulaire de contact public)
   */
  async submitPublicContact(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const validation = validateContactPayload(req.body);

      // Si le honeypot a été activé par un bot : journalisation de sécurité et réponse silencieuse (tarpit anti-scraping)
      if (validation.isSpam) {
        const ipAddress = getClientIp(req);
        void logSecurityIncident({
          category: 'honeypot_bot',
          level: 'warning',
          action: 'Bot spameur intercepté (Honeypot)',
          target: 'POST /api/v1/contact',
          ipAddress,
          details: 'Un robot automatisé a tenté de soumettre un message publicitaire en remplissant un champ piégé masqué.',
        });

        res.status(200).json(
          sendResponse(true, 'Votre message a été transmis avec succès.', {
            referenceId: `CP-${Date.now().toString(36).toUpperCase()}`,
          })
        );
        return;
      }

      if (validation.error || !validation.value) {
        res.status(400).json(sendResponse(false, validation.error || 'Données invalides.'));
        return;
      }

      const ipAddress = getClientIp(req);
      const result = await contactService.createMessage(
        {
          sender: validation.value.name,
          email: validation.value.email,
          subject: validation.value.subject,
          content: validation.value.message,
          source: 'Formulaire de contact web',
        },
        {
          userName: validation.value.name,
          userEmail: validation.value.email,
          ipAddress,
        }
      );

      res.status(200).json(
        sendResponse(true, 'Votre message a été transmis avec succès. Notre équipe vous recontactera sous 24h.', {
          referenceId: result.referenceId,
          subject: result.message.subject,
          receivedAt: result.message.createdAt,
        })
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * GET /api/v1/messages ou /api/v1/dashboard/messages
   */
  async getAll(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const status = req.query.status as MessageStatus | undefined;
      const [messages, counts] = await Promise.all([
        contactService.getAllMessages(status),
        contactService.getCounts(),
      ]);

      res.status(200).json(
        sendResponse(true, 'Messages récupérés de PostgreSQL', {
          unreadCount: counts.unreadCount,
          total: counts.total,
          data: messages,
        })
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * GET /api/v1/messages/unread-count ou /api/v1/dashboard/messages/unread-count
   */
  async getUnreadCount(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const counts = await contactService.getCounts();
      res.status(200).json(
        sendResponse(true, 'Nombre de messages non lus récupéré avec succès', {
          unreadCount: counts.unreadCount,
          total: counts.total,
          timestamp: new Date().toISOString(),
        })
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * GET /api/v1/messages/:id
   */
  async getById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = String(req.params.id);
      const message = await contactService.getMessageById(id);

      if (!message) {
        res.status(404).json(sendResponse(false, 'Message introuvable.'));
        return;
      }

      res.status(200).json(
        sendResponse(true, 'Détails du message récupérés', message)
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * POST /api/v1/messages ou /api/v1/dashboard/messages (Création manuelle / API)
   */
  async create(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const validation = validateContactPayload(req.body);
      if (validation.error || !validation.value) {
        res.status(400).json(sendResponse(false, validation.error || 'Données invalides.'));
        return;
      }

      const ipAddress = getClientIp(req);
      const result = await contactService.createMessage(
        {
          sender: validation.value.name,
          email: validation.value.email,
          subject: validation.value.subject,
          content: validation.value.message,
          source: (req.body as Record<string, string>).source || 'Dashboard CleanPro',
        },
        {
          userName: 'Administrateur',
          ipAddress,
        }
      );

      const counts = await contactService.getCounts();

      res.status(201).json(
        sendResponse(true, 'Message enregistré avec succès dans PostgreSQL', {
          message: result.message,
          unreadCount: counts.unreadCount,
        })
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * PATCH /api/v1/messages/:id/read ou /api/v1/dashboard/messages/:id/read
   */
  async toggleRead(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = String(req.params.id);
      const ipAddress = getClientIp(req);
      const result = await contactService.toggleReadStatus(id, {
        userName: 'Administrateur',
        ipAddress,
      });

      if (!result) {
        res.status(404).json(sendResponse(false, 'Message introuvable.'));
        return;
      }

      res.status(200).json(
        sendResponse(true, 'Statut de lecture mis à jour', {
          message: result.updated,
          unreadCount: result.unreadCount,
        })
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * PATCH /api/v1/messages/:id/archive ou /api/v1/dashboard/messages/:id/archive
   */
  async archive(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = String(req.params.id);
      const ipAddress = getClientIp(req);
      const result = await contactService.archiveMessage(id, {
        userName: 'Administrateur',
        ipAddress,
      });

      if (!result) {
        res.status(404).json(sendResponse(false, 'Message introuvable.'));
        return;
      }

      res.status(200).json(
        sendResponse(true, 'Message archivé avec succès', {
          message: result.updated,
          unreadCount: result.unreadCount,
        })
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * DELETE /api/v1/messages/:id ou /api/v1/dashboard/messages/:id
   */
  async delete(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const id = String(req.params.id);
      const ipAddress = getClientIp(req);
      const result = await contactService.deleteMessage(id, {
        userName: 'Administrateur',
        ipAddress,
      });

      if (!result) {
        res.status(404).json(sendResponse(false, 'Message introuvable.'));
        return;
      }

      res.status(200).json(
        sendResponse(true, 'Message supprimé de la base de données', {
          id: result.id,
          unreadCount: result.unreadCount,
        })
      );
    } catch (error) {
      next(error);
    }
  },

  /**
   * POST /api/v1/messages/:id/reply ou /api/v1/dashboard/messages/:id/reply
   * Envoie la réponse de l'administrateur par e-mail au visiteur via Nodemailer (Gmail)
   */
  async reply(req: Request, res: Response, _next: NextFunction): Promise<void> {
    const id = String(req.params.id);
    const ipAddress = getClientIp(req);
    try {
      const { replyContent, recipientEmail } = req.body;

      if (!replyContent || typeof replyContent !== 'string' || replyContent.trim().length < 2) {
        res.status(400).json(sendResponse(false, 'Le contenu de la réponse est obligatoire (minimum 2 caractères).'));
        return;
      }

      if (replyContent.trim().length > 5000) {
        res.status(400).json(sendResponse(false, 'La réponse ne peut pas dépasser 5000 caractères.'));
        return;
      }

      const result = await contactService.replyToMessage(
        id,
        replyContent.trim(),
        typeof recipientEmail === 'string' ? recipientEmail : undefined,
        {
          userName: 'Administrateur',
          ipAddress,
        }
      );

      if (result.notFound) {
        res.status(404).json(sendResponse(false, 'Message introuvable.'));
        return;
      }

      if (result.error) {
        res.status(400).json(sendResponse(false, result.error));
        return;
      }

      res.status(200).json(
        sendResponse(true, 'Réponse transmise avec succès dans la boîte e-mail du visiteur.', {
          message: result.updated,
          unreadCount: result.unreadCount,
        })
      );
    } catch (error) {
      console.error('Erreur lors de l’envoi de la réponse :', error);
      try {
        await prisma.log.create({
          data: {
            type: 'technical',
            level: 'warning',
            user: 'Administrateur',
            action: 'Échec d’envoi de réponse e-mail',
            target: id,
            ipAddress,
            result: 'failure',
            details: `Réponse e-mail échouée pour le message ${id} : ${(error as Error).message}`,
          },
        });
      } catch {
        // Ignorer
      }
      res.status(500).json(
        sendResponse(false, `Échec de l'envoi de l'e-mail : ${(error as Error).message}`)
      );
    }
  },
};

