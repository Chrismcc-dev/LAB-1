# ---- deps stage (needs npm) ----
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

# ---- runtime stage (no npm/corepack) ----
FROM node:20-alpine AS runtime
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Remove npm + corepack so Trivy doesn't scan their bundled deps
RUN rm -rf /usr/local/lib/node_modules/npm \
           /usr/local/bin/npm \
           /usr/local/bin/npx \
           /usr/local/lib/node_modules/corepack \
           /usr/local/bin/corepack || true

EXPOSE 3000
CMD ["node", "server.js"]
