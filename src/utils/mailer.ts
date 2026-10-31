import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Chargement garanti du fichier .env du backend, quel que soit le dossier courant de démarrage
dotenv.config({ path: path.resolve(__dirname, '../../.env') });
dotenv.config();

/**
 * Configuration du transporteur Nodemailer avec Gmail
 * Sécurité : Utilise un mot de passe d'application Google (App Password)
 * Les identifiants sont strictement chargés depuis process.env (jamais codés en dur)
 */
export function getGmailConfig() {
  const user = process.env.GMAIL_USER?.trim();
  const pass = process.env.GMAIL_APP_PASSWORD?.replace(/\s+/g, '').trim();
  const recipient = process.env.GMAIL_RECIPIENT?.trim() || user;
  return { user, pass, recipient };
}

export function createMailerTransporter(): Transporter {
  const { user, pass } = getGmailConfig();
  return nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true, // SSL direct via le port 465 (indispensable sur Cloud pour éviter les blocages de port)
    auth: {
      user,
      pass,
    },
    tls: {
      rejectUnauthorized: true,
    },
    connectionTimeout: 10000,
  });
}

export const mailerTransporter: Transporter = createMailerTransporter();

/**
 * Vérifie la configuration et la connectivité SMTP / HTTP API au démarrage de l'application
 * Conforme OWASP ASVS §13.2 (Vérification proactive des dépendances réseau)
 */
export async function verifyMailerConnection(): Promise<boolean> {
  const brevoApiKey = process.env.BREVO_API_KEY?.trim();
  const resendApiKey = process.env.RESEND_API_KEY?.trim();

  if (brevoApiKey) {
    if (brevoApiKey.startsWith('xsmtpsib-')) {
      console.error('❌ [Mailer Erreur Clé] Vous avez configuré une clé SMTP (xsmtpsib-...) au lieu d\'une clé API HTTP (xkeysib-...).');
      console.error('   👉 Rendez-vous dans Brevo > Menu Compte > "SMTP & API" > Cliquez sur l\'onglet "API Keys" (et NON l\'onglet SMTP) > "Generate a new API key".');
      return false;
    }

    if (brevoApiKey.startsWith('xkeysib-')) {
      console.log('✅ [Mailer] Mode Brevo HTTP API actif (Port 443 HTTPS - Conforme Cloud)');
      return true;
    }
  }

  if (resendApiKey) {
    console.log('✅ [Mailer] Mode HTTP API actif via Resend (Port 443 HTTPS)');
    return true;
  }

  const { user, pass } = getGmailConfig();

  if (!user || !pass || user.includes('votre_adresse') || pass.includes('votre_mot_de_passe')) {
    console.warn('⚠️  [SMTP Mailer] GMAIL_USER ou GMAIL_APP_PASSWORD non configuré dans .env. Les envois de mail seront simulés en développement.');
    return false;
  }

  try {
    const transporter = createMailerTransporter();
    await transporter.verify();
    console.log(`✅ [SMTP Mailer] Connexion SMTP Gmail établie avec succès pour ${user}`);
    return true;
  } catch (error) {
    console.error('❌ [SMTP Mailer] Échec de la vérification SMTP Gmail :', (error as Error).message);
    return false;
  }
}

export interface SendContactMailParams {
  name: string;
  email: string;
  subject?: string;
  message: string;
  referenceId: string;
}

export interface SendReplyMailParams {
  recipientName: string;
  recipientEmail: string;
  subject?: string;
  replyContent: string;
  originalMessageSnippet?: string;
}

interface DispatchEmailOptions {
  fromName: string;
  fromEmail: string;
  toEmail: string;
  replyTo?: string;
  subject: string;
  text: string;
  html: string;
}

/**
 * Expéditeur universel d'e-mails :
 * 1. Brevo HTTP API (Port 443 HTTPS - Jamais bloqué par les pare-feux Cloud de Render Free)
 * 2. Resend HTTP API (Port 443 HTTPS)
 * 3. Fallback SMTP Nodemailer (Port 465 SSL)
 */
async function dispatchEmail(options: DispatchEmailOptions): Promise<{ messageId: string }> {
  const brevoApiKey = process.env.BREVO_API_KEY?.trim();
  const resendApiKey = process.env.RESEND_API_KEY?.trim();

  // 1. Priorité Cloud : Brevo HTTP REST API (Port 443 HTTPS standard - Conforme OWASP & ANSSI)
  if (brevoApiKey) {
    if (brevoApiKey.startsWith('xsmtpsib-')) {
      throw new Error('Clé Brevo invalide : vous utilisez une clé SMTP (xsmtpsib-...) au lieu d\'une clé API HTTP (xkeysib-...). Allez dans Brevo > SMTP & API > onglet "API Keys".');
    }

    const verifiedSender = process.env.BREVO_SENDER_EMAIL?.trim() || process.env.GMAIL_USER?.trim() || options.fromEmail;

    // Assainissement de l'email replyTo (CWE-20 : extraction d'adresse email stricte)
    let cleanReplyTo = options.replyTo?.trim();
    if (cleanReplyTo && cleanReplyTo.includes('<')) {
      const match = cleanReplyTo.match(/<([^>]+)>/);
      if (match) cleanReplyTo = match[1];
    }

    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'accept': 'application/json',
        'api-key': brevoApiKey,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        sender: { name: options.fromName, email: verifiedSender },
        to: [{ email: options.toEmail.trim().toLowerCase() }],
        replyTo: cleanReplyTo ? { email: cleanReplyTo } : undefined,
        subject: options.subject,
        textContent: options.text,
        htmlContent: options.html,
      }),
      signal: AbortSignal.timeout(10000), // CWE-400 : protection contre les blocages réseau
    });

    if (!response.ok) {
      const errorBody = await response.text();
      console.error(`❌ [Brevo API Error] ${response.status} : ${errorBody}`);
      throw new Error(`Brevo HTTP API (${response.status}) : ${errorBody}`);
    }

    const data = (await response.json()) as { messageId?: string };
    console.log(`✅ [Mailer] E-mail transmis avec succès via Brevo HTTP API (ID: ${data.messageId})`);
    return { messageId: data.messageId || `brevo-${Date.now()}` };
  }

  // 2. Priorité Cloud : Resend HTTP REST API (Port 443 HTTPS standard)
  if (resendApiKey) {
    try {
      const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${resendApiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: `${options.fromName} <onboarding@resend.dev>`,
          to: [options.toEmail],
          reply_to: options.replyTo,
          subject: options.subject,
          text: options.text,
          html: options.html,
        }),
      });

      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(`Resend HTTP API ${response.status}: ${errorBody}`);
      }

      const data = (await response.json()) as { id?: string };
      console.log(`✅ [Mailer] E-mail transmis avec succès via Resend HTTP API (ID: ${data.id})`);
      return { messageId: data.id || `resend-${Date.now()}` };
    } catch (resendErr) {
      console.warn('⚠️ [Mailer] Échec via Resend HTTP API, bascule sur SMTP :', (resendErr as Error).message);
    }
  }

  // 3. Fallback standard : Transporteur SMTP Nodemailer (Port 465 SSL)
  const transporter = createMailerTransporter();
  return transporter.sendMail({
    from: `"${options.fromName}" <${options.fromEmail}>`,
    to: options.toEmail,
    replyTo: options.replyTo,
    subject: options.subject,
    text: options.text,
    html: options.html,
  });
}

/**
 * Envoie une notification e-mail à l'administrateur lors de la soumission du formulaire de contact public
 */
export async function sendContactNotificationEmail(params: SendContactMailParams): Promise<{ messageId: string }> {
  const mailSubject = `[CleanPro Contact] ${params.subject || 'Nouveau message'} - de ${params.name} (${params.referenceId})`;

  const textVersion = `
NOUVEAU MESSAGE CLIENT - CLEANPRO
--------------------------------------------------
Référence : ${params.referenceId}
Expéditeur : ${params.name}
Adresse e-mail : ${params.email}
Sujet : ${params.subject || 'Demande de renseignement'}
Date : ${new Date().toLocaleString('fr-FR')}

Message :
${params.message}

--------------------------------------------------
Pour répondre directement à ce visiteur, cliquez simplement sur "Répondre" dans votre messagerie.
`;

  const htmlVersion = `
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1e293b; background-color: #f8fafc; margin: 0; padding: 20px; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); }
    .header { background: #135d3b; padding: 24px; text-align: center; color: #ffffff; }
    .header h1 { margin: 0; font-size: 20px; font-weight: 700; }
    .content { padding: 30px 24px; }
    .badge { display: inline-block; background: #e0f2fe; color: #0369a1; padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; margin-bottom: 16px; }
    .info-table { width: 100%; border-collapse: collapse; margin-bottom: 24px; }
    .info-table td { padding: 8px 0; font-size: 14px; border-bottom: 1px solid #f1f5f9; }
    .info-table td.label { width: 130px; font-weight: 600; color: #64748b; }
    .message-box { background: #f8fafc; border-left: 4px solid #135d3b; padding: 16px; border-radius: 0 8px 8px 0; font-size: 14px; color: #0f172a; white-space: pre-wrap; }
    .footer { background: #f8fafc; padding: 16px 24px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; }
    .btn { display: inline-block; background: #135d3b; color: #ffffff !important; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: 600; font-size: 14px; margin-top: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>CleanPro — Notification Client</h1>
    </div>
    <div class="content">
      <span class="badge">Nouveau message reçu</span>
      <table class="info-table">
        <tr>
          <td class="label">Référence :</td>
          <td><strong>${escapeHtml(params.referenceId)}</strong></td>
        </tr>
        <tr>
          <td class="label">Expéditeur :</td>
          <td><strong>${escapeHtml(params.name)}</strong></td>
        </tr>
        <tr>
          <td class="label">Adresse e-mail :</td>
          <td><a href="mailto:${escapeHtml(params.email)}" style="color: #135d3b;">${escapeHtml(params.email)}</a></td>
        </tr>
        <tr>
          <td class="label">Objet :</td>
          <td>${escapeHtml(params.subject || 'Demande de contact')}</td>
        </tr>
        <tr>
          <td class="label">Date :</td>
          <td>${new Date().toLocaleString('fr-FR')}</td>
        </tr>
      </table>

      <h3 style="font-size: 14px; color: #334155; margin-bottom: 8px;">Contenu du message :</h3>
      <div class="message-box">${escapeHtml(params.message)}</div>

      <div style="text-align: center; margin-top: 24px;">
        <a href="mailto:${escapeHtml(params.email)}?subject=Re:%20[CleanPro]%20${encodeURIComponent(params.subject || 'Demande de contact')}" class="btn">Répondre au visiteur</a>
      </div>
    </div>
    <div class="footer">
      Cet e-mail a été généré automatiquement par le formulaire de contact CleanPro SARL.<br>
      Pour répondre, utilisez le bouton ci-dessus ou répondez directement à cet e-mail (champ reply-to configuré).
    </div>
  </div>
</body>
</html>
`;

  const { user, recipient } = getGmailConfig();
  return dispatchEmail({
    fromName: 'CleanPro Notification',
    fromEmail: user || 'contact@cleanpro.cm',
    toEmail: recipient || user || 'frankyenspd@gmail.com',
    replyTo: params.email,
    subject: mailSubject,
    text: textVersion,
    html: htmlVersion,
  });
}

/**
 * Envoie la réponse de l'administrateur directement dans la boîte mail du visiteur
 */
export async function sendReplyToVisitorEmail(params: SendReplyMailParams): Promise<{ messageId: string }> {
  const mailSubject = params.subject
    ? (params.subject.startsWith('Re:') ? params.subject : `Re: ${params.subject}`)
    : 'Re: Votre demande de contact - CleanPro';

  const textVersion = `
Bonjour ${params.recipientName},

Merci d'avoir contacté CleanPro. Voici notre réponse à votre demande :

--------------------------------------------------
${params.replyContent}
--------------------------------------------------

${params.originalMessageSnippet ? `Rappel de votre message :\n"${params.originalMessageSnippet}"\n` : ''}

Restant à votre entière disposition pour tout renseignement complémentaire,

Cordialement,
L'équipe CleanPro SARL
contact@cleanpro.cm | +237 600 000 000
www.cleanpro.cm
`;

  const htmlVersion = `
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1e293b; background-color: #f8fafc; margin: 0; padding: 20px; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); }
    .header { background: #135d3b; padding: 24px; text-align: center; color: #ffffff; }
    .header h1 { margin: 0; font-size: 20px; font-weight: 700; }
    .content { padding: 30px 24px; }
    .reply-box { background: #f0fdf4; border-left: 4px solid #135d3b; padding: 18px; border-radius: 0 8px 8px 0; font-size: 15px; color: #0f172a; white-space: pre-wrap; margin: 20px 0; }
    .original-quote { background: #f8fafc; border: 1px dashed #cbd5e1; padding: 12px 16px; border-radius: 8px; font-size: 13px; color: #64748b; margin-top: 20px; }
    .footer { background: #f8fafc; padding: 20px 24px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>CleanPro — Service Client & Hygiène</h1>
    </div>
    <div class="content">
      <p style="font-size: 16px; margin-top: 0;">Bonjour <strong>${escapeHtml(params.recipientName)}</strong>,</p>
      <p>Nous vous remercions pour l'intérêt que vous portez à nos prestations de nettoyage et propreté professionnelle. Voici la réponse apportée par notre équipe :</p>

      <div class="reply-box">${escapeHtml(params.replyContent)}</div>

      ${params.originalMessageSnippet ? `
      <div class="original-quote">
        <strong style="color: #475569;">Rappel de votre message :</strong><br>
        <em>« ${escapeHtml(params.originalMessageSnippet)} »</em>
      </div>` : ''}

      <p style="margin-top: 24px; font-size: 14px;">
        N'hésitez pas à répondre directement à cet e-mail si vous avez des questions complémentaires.
      </p>

      <p style="margin-bottom: 0; font-size: 14px;">
        Bien cordialement,<br>
        <strong style="color: #135d3b;">L'équipe CleanPro</strong><br>
        <span style="font-size: 13px; color: #64748b;">Votre partenaire propreté et hygiène</span>
      </p>
    </div>
    <div class="footer">
      CleanPro SARL · Boulevard de la Liberté, Douala, Cameroun<br>
      Téléphone : +237 600 000 000 · E-mail : contact@cleanpro.cm
    </div>
  </div>
</body>
</html>
`;

  const { user } = getGmailConfig();
  return dispatchEmail({
    fromName: 'CleanPro Service Client',
    fromEmail: user || 'contact@cleanpro.cm',
    toEmail: params.recipientEmail,
    replyTo: user || 'contact@cleanpro.cm',
    subject: mailSubject,
    text: textVersion,
    html: htmlVersion,
  });
}

/**
 * Échappement anti-XSS des chaînes injectées dans le gabarit HTML (CWE-79)
 */
function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
