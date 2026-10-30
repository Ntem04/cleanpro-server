-- AlterTable
ALTER TABLE "page_visits" ADD COLUMN     "visitorId" TEXT;

-- CreateTable
CREATE TABLE "page_stats" (
    "id" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "uniqueVisitors" INTEGER NOT NULL DEFAULT 0,
    "totalHits" INTEGER NOT NULL DEFAULT 0,
    "lastVisitAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "page_stats_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "page_stats_path_key" ON "page_stats"("path");

-- CreateIndex
CREATE INDEX "page_stats_path_idx" ON "page_stats"("path");

-- CreateIndex
CREATE INDEX "page_visits_visitorId_idx" ON "page_visits"("visitorId");

-- CreateIndex
CREATE INDEX "page_visits_path_visitorId_idx" ON "page_visits"("path", "visitorId");
