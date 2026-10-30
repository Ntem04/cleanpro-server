-- CreateTable
CREATE TABLE "page_visits" (
    "id" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "ipAddress" TEXT NOT NULL,
    "visitorType" TEXT NOT NULL DEFAULT 'visiteur',
    "label" TEXT NOT NULL DEFAULT 'Visiteur légitime',
    "userAgent" TEXT,
    "location" TEXT,
    "status" INTEGER NOT NULL DEFAULT 200,
    "details" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "page_visits_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "page_visits_visitorType_idx" ON "page_visits"("visitorType");

-- CreateIndex
CREATE INDEX "page_visits_createdAt_idx" ON "page_visits"("createdAt");
