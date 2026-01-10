# syntax=docker/dockerfile:1

# ---- deps/build stage ----
FROM node:20-alpine AS deps
WORKDIR /app

# Copy app manifests first for caching
COPY apps/node-hello/package.json apps/node-hello/package-lock.json ./
RUN npm ci --omit=dev

# Copy app source
COPY apps/node-hello/ ./

# Optional build step if it exists
RUN npm run build --if-present


# ---- runtime stage (minimal) ----
FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

# Copy built app + node_modules only
COPY --from=deps /app /app

# 🔥 Remove npm to eliminate npm-bundled vulns (cross-spawn/glob live under npm)
RUN rm -rf /usr/local/lib/node_modules/npm \
  && rm -f /usr/local/bin/npm /usr/local/bin/npx

EXPOSE 3000

# Run the app directly (no npm)
CMD ["node", "server.js"]
