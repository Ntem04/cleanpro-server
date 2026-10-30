# ─── Étape 1 : Build TypeScript & Génération Prisma ────────────────────────
FROM node:22-alpine AS builder

WORKDIR /app

# Dépendances système pour Prisma sur Alpine
RUN apk add --no-cache openssl

# Copie des fichiers de dépendances
COPY package.json package-lock.json* ./

RUN npm install

# Copie de l'ensemble du code source du backend
COPY . .

# Génération du client Prisma et compilation TypeScript
RUN npx prisma generate
RUN npm run build

# ─── Étape 2 : Image d'exécution Node.js de production durcie ───────────────
FROM node:22-alpine AS runner

WORKDIR /app

# Installation d'OpenSSL nécessaire pour le moteur binaire Prisma
RUN apk add --no-cache openssl

ENV NODE_ENV=production
ENV PORT=5000

COPY package.json package-lock.json* ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/prisma ./prisma

EXPOSE 5000

CMD ["sh", "-c", "npx prisma migrate deploy && node dist/server.js"]
