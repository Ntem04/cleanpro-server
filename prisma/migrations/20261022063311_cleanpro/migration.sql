-- CreateTable
CREATE TABLE "users" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'admin',
    "avatarUrl" TEXT,
    "isCurrentUser" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "services" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "image" TEXT NOT NULL,
    "prestations" TEXT[],
    "status" TEXT NOT NULL DEFAULT 'disponible',
    "badgeLabel" TEXT DEFAULT 'Disponible',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "services_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "planning_slots" (
    "id" TEXT NOT NULL,
    "day" TEXT NOT NULL,
    "dateFormatted" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "location" TEXT NOT NULL,
    "startTime" TEXT NOT NULL,
    "endTime" TEXT NOT NULL,
    "team" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "colorTheme" TEXT DEFAULT 'emerald',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "planning_slots_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "messages" (
    "id" TEXT NOT NULL,
    "sender" TEXT NOT NULL,
    "subtitle" TEXT,
    "source" TEXT NOT NULL DEFAULT 'Formulaire de contact web',
    "snippet" TEXT,
    "email" TEXT NOT NULL,
    "subject" TEXT,
    "content" TEXT NOT NULL,
    "date" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'unread',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "messages_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "logs" (
    "id" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "type" TEXT NOT NULL,
    "level" TEXT NOT NULL DEFAULT 'info',
    "user" TEXT NOT NULL DEFAULT 'Système',
    "userEmail" TEXT,
    "action" TEXT NOT NULL,
    "target" TEXT NOT NULL,
    "ipAddress" TEXT NOT NULL DEFAULT '127.0.0.1',
    "result" TEXT NOT NULL DEFAULT 'success',
    "details" TEXT NOT NULL,
    "metadata" JSONB,
    "userId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "settings" (
    "id" TEXT NOT NULL DEFAULT 'singleton',
    "companyName" TEXT NOT NULL DEFAULT 'CleanPro SARL',
    "companySignature" TEXT NOT NULL DEFAULT 'CleanPro – Votre partenaire propreté et hygiène.',
    "logoUrl" TEXT,
    "phone" TEXT NOT NULL DEFAULT '+237 600 000 000',
    "whatsapp" TEXT NOT NULL DEFAULT '+237 600 000 000',
    "email" TEXT NOT NULL DEFAULT 'contact@cleanpro.cm',
    "address" TEXT NOT NULL DEFAULT 'Boulevard de la Liberté, Douala, Cameroun',
    "officeNote" TEXT,
    "weekdaysHours" TEXT NOT NULL DEFAULT '07:30 – 18:30',
    "saturdayHours" TEXT NOT NULL DEFAULT '08:00 – 16:00',
    "sundayHours" TEXT NOT NULL DEFAULT 'Urgences sur demande',
    "visitorsHours" TEXT NOT NULL DEFAULT '08:30 – 17:30',
    "notifications" JSONB,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "settings_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- AddForeignKey
ALTER TABLE "logs" ADD CONSTRAINT "logs_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
