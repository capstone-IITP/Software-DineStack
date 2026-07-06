# Stage 1: Build TypeScript and Prisma client
FROM node:20-alpine AS builder

WORKDIR /usr/src/app

COPY package*.json ./
COPY tsconfig*.json ./

RUN npm ci

# Generate Prisma Client specifically for Cloud Postgres
COPY prisma ./prisma
RUN npx prisma generate --schema=prisma/schema.prisma

# Build the TypeScript project
COPY . .
RUN npm run build

# Stage 2: Lightweight runner stage containing only required dependencies
FROM node:20-alpine AS runner

WORKDIR /usr/src/app

ENV NODE_ENV=production

# Ensure permissions and switch to node user
RUN chown -R node:node /usr/src/app

USER node

# Install only production dependencies
COPY --chown=node:node package*.json ./
RUN npm ci --only=production

# Copy built server bundle and generated Prisma Client
COPY --chown=node:node --from=builder /usr/src/app/dist ./dist
COPY --chown=node:node --from=builder /usr/src/app/node_modules/.prisma ./node_modules/.prisma
COPY --chown=node:node --from=builder /usr/src/app/node_modules/@prisma/client ./node_modules/@prisma/client
COPY --chown=node:node --from=builder /usr/src/app/prisma ./prisma

EXPOSE 5001

CMD ["node", "dist/server.js"]
