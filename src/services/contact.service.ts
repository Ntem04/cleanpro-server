import prisma from '../config/prisma.js';
import { sendContactNotificationEmail, sendReplyToVisitorEmail } from '../utils/mailer.js';

export type MessageStatus = 'unread' | 'read' | 'archived';

export interface CreateContactMessageDTO {
  sender: string;
  email: string;
  subject?: string;
  content: string;
  source?: string;
  subtitle?: string;
}

export interface AuditContext {
  userName?: string;
  userEmail?: string;
  ipAddress?: string;
}

/**
 * Service Métier pour les Messages et le Formulaire de Contact
 * Connecté à PostgreSQL via Prisma avec respect strict du RGPD (Minimisation des données)
 */
export const contactService = {
  /**
   * Enregistre un nouveau message client en base de données PostgreSQL
   */
  async createMessage(dto: CreateContactMessageDTO, audit?: AuditContext) {
    const trimmedSender = dto.sender.trim();
    const trimmedEmail = dto.email.trim().toLowerCase();
    const trimmedSubject = (dto.subject || 'Demande de contact').trim();
    const trimmedContent = dto.content.trim();
    const source = dto.source || 'Formulaire de contact web';

    // Génération d'un snippet sécurisé (60 caractères max) pour l'aperçu sans charger le texte complet
    const snippet = trimmedContent.length > 60
      ? `${trimmedContent.slice(0, 60)}...`
      : trimmedContent;

    // Formatage lisible de la date en français
    const dateFormatted = new Intl.DateTimeFormat('fr-FR', {
      month: 'long',
      year: 'numeric',
    }).format(new Date());

    // Génération de la référence unique du ticket client
    const referenceId = `CP-${Date.now().toString(36).toUpperCase()}`;

    const newMessage = await prisma.message.create({
      data: {
        sender: trimmedSender,
        email: trimmedEmail,
        subject: trimmedSubject,
        subtitle: dto.subtitle || trimmedSubject,
        content: trimmedContent,
        source,
        snippet,
        date: dateFormatted,
        status: 'unread',
      },
    });

    // Envoi asynchrone non-bloquant de la notification e-mail à l'administrateur (Réponse instantanée < 50ms)
    sendContactNotificationEmail({
      name: trimmedSender,
      email: trimmedEmail,
      subject: trimmedSubject,
      message: trimmedContent,
      referenceId,
    }).catch(async (mailError) => {
      // Enregistrement de l'échec dans le journal technique en tâche de fond sans bloquer l'utilisateur
      try {
        await prisma.log.create({
          data: {
            type: 'technical',
            level: 'warning',
            user: 'Système Mailer',
            action: 'Échec d’envoi de notification e-mail',
            target: referenceId,
            ipAddress: audit?.ipAddress || '127.0.0.1',
            result: 'failure',
            details: `Notification SMTP échouée pour ${referenceId} : ${(mailError as Error).message}`,
          },
        });
      } catch {
        // Ignorer
      }
    });

    // Journalisation d'audit conforme RGPD (Art. 5.1.c : Minimisation des données)
    // RÈGLE DE SÉCURITÉ : Ne JAMAIS inclure le corps du message complet dans les logs
    try {
      await prisma.log.create({
        data: {
          type: 'audit',
          level: 'info',
          user: trimmedSender,
          userEmail: trimmedEmail,
          action: 'Réception message contact',
          target: referenceId,
          ipAddress: audit?.ipAddress || '127.0.0.1',
          result: 'success',
          details: `Message reçu de ${trimmedSender} (${trimmedEmail}) sous la référence ${referenceId}. Sujet: ${trimmedSubject}.`,
        },
      });
    } catch {
      // Ignorer pour ne pas bloquer l'enregistrement du message
    }

    return {
      message: newMessage,
      referenceId,
    };
  },

  /**
   * Récupère la liste des messages avec filtre optionnel par statut
   */
  async getAllMessages(statusFilter?: MessageStatus) {
    return prisma.message.findMany({
      where: statusFilter ? { status: statusFilter } : {},
      orderBy: { createdAt: 'desc' },
    });
  },

  /**
   * Récupère un message par son identifiant unique
   */
  async getMessageById(id: string) {
    return prisma.message.findUnique({
      where: { id },
    });
  },

  /**
   * Calcule le nombre de messages non lus et le total
   */
  async getCounts() {
    const [unreadCount, total] = await Promise.all([
      prisma.message.count({ where: { status: 'unread' } }),
      prisma.message.count(),
    ]);

    return { unreadCount, total };
  },

  /**
   * Bascule l'état de lecture d'un message (unread <-> read)
   */
  async toggleReadStatus(id: string, audit?: AuditContext) {
    const target = await prisma.message.findUnique({ where: { id } });
    if (!target) {
      return null;
    }

    const nextStatus: MessageStatus = target.status === 'read' ? 'unread' : 'read';

    const updated = await prisma.message.update({
      where: { id },
      data: { status: nextStatus },
    });

    const unreadCount = await prisma.message.count({ where: { status: 'unread' } });

    // Journalisation d'audit
    try {
      await prisma.log.create({
        data: {
          type: 'audit',
          level: 'info',
          user: audit?.userName || 'Administrateur',
          userEmail: audit?.userEmail,
          action: nextStatus === 'read' ? 'Message marqué comme lu' : 'Message marqué comme non lu',
          target: target.sender,
          ipAddress: audit?.ipAddress || '127.0.0.1',
          result: 'success',
          details: `Statut du message ${id} passé à "${nextStatus}".`,
        },
      });
    } catch {
      // Ignorer
    }

    return { updated, unreadCount };
  },

  /**
   * Archive un message
   */
  async archiveMessage(id: string, audit?: AuditContext) {
    const target = await prisma.message.findUnique({ where: { id } });
    if (!target) {
      return null;
    }

    const updated = await prisma.message.update({
      where: { id },
      data: { status: 'archived' },
    });

    const unreadCount = await prisma.message.count({ where: { status: 'unread' } });

    try {
      await prisma.log.create({
        data: {
          type: 'audit',
          level: 'info',
          user: audit?.userName || 'Administrateur',
          userEmail: audit?.userEmail,
          action: 'Message archivé',
          target: target.sender,
          ipAddress: audit?.ipAddress || '127.0.0.1',
          result: 'success',
          details: `Message ${id} déplacé vers les archives.`,
        },
      });
    } catch {
      // Ignorer
    }

    return { updated, unreadCount };
  },

  /**
   * Supprime définitivement un message de la base de données
   */
  async deleteMessage(id: string, audit?: AuditContext) {
    const target = await prisma.message.findUnique({ where: { id } });
    if (!target) {
      return null;
    }

    await prisma.message.delete({ where: { id } });
    const unreadCount = await prisma.message.count({ where: { status: 'unread' } });

    try {
      await prisma.log.create({
        data: {
          type: 'audit',
          level: 'warning',
          user: audit?.userName || 'Administrateur',
          userEmail: audit?.userEmail,
          action: 'Suppression d’un message',
          target: target.sender,
          ipAddress: audit?.ipAddress || '127.0.0.1',
          result: 'success',
          details: `Message ${id} de ${target.sender} supprimé définitivement.`,
        },
      });
    } catch {
      // Ignorer
    }

    return { id, unreadCount };
  },

  /**
   * Envoie une réponse par e-mail directement au visiteur et met à jour le statut du message
   */
  async replyToMessage(
    id: string,
    replyContent: string,
    overrideRecipientEmail?: string,
    audit?: AuditContext
  ) {
    let target = await prisma.message.findUnique({ where: { id } });
    if (!target) {
      if (overrideRecipientEmail && overrideRecipientEmail.includes('@')) {
        const recipientEmail = overrideRecipientEmail.trim().toLowerCase();
        await sendReplyToVisitorEmail({
          recipientName: 'Visiteur CleanPro',
          recipientEmail,
          subject: 'Votre message CleanPro',
          replyContent: replyContent.trim(),
        });

        try {
          await prisma.log.create({
            data: {
              type: 'audit',
              level: 'info',
              user: audit?.userName || 'Administrateur',
              userEmail: audit?.userEmail,
              action: 'Réponse e-mail transmise au visiteur',
              target: recipientEmail,
              ipAddress: audit?.ipAddress || '127.0.0.1',
              result: 'success',
              details: `Réponse e-mail expédiée avec succès à ${recipientEmail} (message ${id}).`,
            },
          });
        } catch {
          // Ignorer
        }

        const unreadCount = await prisma.message.count({ where: { status: 'unread' } });
        return {
          updated: { id, status: 'read', email: recipientEmail },
          unreadCount,
        };
      }
      return { notFound: true };
    }

    const recipientEmail = (overrideRecipientEmail || target.email).trim().toLowerCase();
    if (!recipientEmail || !recipientEmail.includes('@')) {
      return { error: 'Aucune adresse e-mail valide pour ce destinataire.' };
    }

    // Expédition effective de l'e-mail via Nodemailer (Gmail)
    await sendReplyToVisitorEmail({
      recipientName: target.sender,
      recipientEmail,
      subject: target.subject || 'Votre message CleanPro',
      replyContent: replyContent.trim(),
      originalMessageSnippet: target.snippet || undefined,
    });

    // Mise à jour du statut du message en base
    const updated = await prisma.message.update({
      where: { id },
      data: { status: 'read' },
    });

    // Journalisation d'audit de la réponse (RGPD : on ne stocke pas le texte complet)
    try {
      await prisma.log.create({
        data: {
          type: 'audit',
          level: 'info',
          user: audit?.userName || 'Administrateur',
          userEmail: audit?.userEmail,
          action: 'Réponse e-mail transmise au visiteur',
          target: `${target.sender} (${recipientEmail})`,
          ipAddress: audit?.ipAddress || '127.0.0.1',
          result: 'success',
          details: `Réponse e-mail expédiée avec succès à ${target.sender} (${recipientEmail}) pour le message ${id}.`,
        },
      });
    } catch {
      // Ignorer
    }

    const unreadCount = await prisma.message.count({ where: { status: 'unread' } });

    return {
      updated,
      unreadCount,
    };
  },
};

