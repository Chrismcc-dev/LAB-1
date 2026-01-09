# ---- deps stage (needs npm) ----
FROM node:20-alpine AS deps
WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

# ---- runtime stage (no npm needed) ----
FROM node:20-alpine AS runtime
WORKDIR /app

# Copy only dependencies + app code
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Remove npm/corepack from final image so Trivy doesn't flag npm's bundled deps
RUN rm -rf /usr/local/lib/node_modules/npm \
           /usr/local/bin/npm \
           /usr/local/bin/npx \
           /usr/local/lib/node_modules/corepack \
           /usr/local/bin/corepack || true

EXPOSE 3000
CMD ["node", "server.js"]
