import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Amorçage de la base de données PostgreSQL CleanPro...');

  // 1. Initialisation de l'administrateur sécurisé (OWASP ASVS §2.1)
  const seedEmail = process.env.SEED_ADMIN_EMAIL?.trim().toLowerCase() || 'ntem04';
  const seedPassword = process.env.SEED_ADMIN_PASSWORD?.trim() || '360042QSe@*#';

  const saltRounds = 12; // Recommandation stricte ANSSI / OWASP
  const passwordHash = await bcrypt.hash(seedPassword, saltRounds);

  const superAdmin = await prisma.user.upsert({
    where: { email: seedEmail },
    update: {
      password: passwordHash,
      role: 'Super Administrateur',
    },
    create: {
      email: seedEmail,
      name: 'Super Administrateur',
      password: passwordHash,
      role: 'Super Administrateur',
      isCurrentUser: true,
    },
  });
  console.log(` Administrateur configuré : ${superAdmin.email}`);

  // 2. Initialisation des 4 prestations de référence CleanPro
  const initialServices = [
    {
      id: 'bureaux',
      title: 'Bureaux & Espaces professionnels',
      description:
        'Nous assurons le nettoyage quotidien ou ponctuel de vos bureaux, salles de réunion et espaces de travail, afin de garantir un environnement propre, sain et agréable pour vos équipes et vos visiteurs.',
      image: 'services-bureaux0',
      prestations: [
        'Bureaux, open spaces, salles de réunion',
        'Désinfection des surfaces',
        'Gestion des déchets',
      ],
      status: 'disponible',
      badgeLabel: 'Disponible',
    },
    {
      id: 'residences',
      title: 'Résidences & Appartements',
      description:
        'Nous prenons soin de votre intérieur avec des prestations de nettoyage complètes et personnalisées, pour un cadre de vie propre et agréable.',
      image: 'services-residences',
      prestations: [
        'Ménage régulier ou ponctuel',
        'Nettoyage en profondeur',
        'Lavage des vitres',
      ],
      status: 'disponible',
      badgeLabel: 'Disponible',
    },
    {
      id: 'industries',
      title: 'Industries & Entrepôts',
      description:
        'Nous intervenons dans les environnements industriels et logistiques pour un nettoyage en profondeur, sécurisé et conforme aux normes de sécurité.',
      image: 'industriesImage',
      prestations: [
        'Grands espaces et zones de stockage',
        'Équipements industriels',
        'Nettoyage haute pression',
      ],
      status: 'disponible',
      badgeLabel: 'Disponible',
    },
    {
      id: 'espaces-publics',
      title: 'Espaces publics & Événements',
      description:
        'Nous intervenons dans les lieux publics et lors de vos événements pour garantir un espace propre, accueillant et sécurisé pour tous.',
      image: 'services-publics',
      prestations: [
        'Centres commerciaux',
        'Événements professionnels et privés',
        'Nettoyage après événement',
      ],
      status: 'disponible',
      badgeLabel: 'Disponible',
    },
  ];

  for (const s of initialServices) {
    await prisma.service.upsert({
      where: { id: s.id },
      update: s,
      create: s,
    });
  }
  console.log(` ${initialServices.length} prestations du catalogue enregistrées.`);

  // 3. Initialisation des paramètres de l'entreprise
  await prisma.settings.upsert({
    where: { id: 'singleton' },
    update: {},
    create: {
      id: 'singleton',
      companyName: 'CleanPro SARL',
      companySignature: 'CleanPro – Votre partenaire propreté et hygiène au Cameroun.',
      phone: '+237 600 000 000',
      whatsapp: '+237 600 000 000',
      email: 'contact@cleanpro.cm',
      address: 'Boulevard de la Liberté, Douala, Cameroun',
      weekdaysHours: '07:30 – 18:30',
      saturdayHours: '08:00 – 16:00',
      sundayHours: 'Urgences sur demande',
      visitorsHours: '08:30 – 17:30',
      notifications: {
        newMessages: true,
        planningAlerts: true,
        securityAlerts: true,
        reports: 'Hebdomadaire',
      },
    },
  });
  console.log(' Coordonnées et paramètres entreprise configurés.');

  console.log(' Amorçage terminé avec succès.');
}

main()
  .catch((e) => {
    console.error('❌ Erreur lors de l\'amorçage Prisma :', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

