# syntax=docker/dockerfile:1
# ==============================================================================
# Oh-My-SSO admin console (Next.js, "standalone" output).
#   docker build -t oh-my-sso-admin ./admin
# Configuration comes at run time (environment), never at build time: the
# same image runs everywhere. See admin/.env.example.
# https://nextjs.org/docs/app/getting-started/deploying#docker
# ==============================================================================
ARG NODE_VERSION=22.22.0

# --- 1. dependencies (cached while package-lock.json does not change) ------------
FROM node:${NODE_VERSION}-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

# --- 2. build ------------------------------------------------------------------
FROM node:${NODE_VERSION}-alpine AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

# --- 3. runtime: only the standalone server, no dev dependencies, no sources ---
FROM node:${NODE_VERSION}-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0 \
    TZ=UTC
# Files belong to root and are read-only for the process: a compromised
# server cannot rewrite its own code.
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public
# The "node" user (uid 1000) of the official image: never root.
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/healthz > /dev/null || exit 1
CMD ["node", "server.js"]
