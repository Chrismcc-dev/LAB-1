# syntax=docker/dockerfile:1

# ---- deps stage ----
FROM node:20-alpine AS deps
WORKDIR /app

# Copy only the app's package files first for better caching
COPY apps/node-hello/package*.json ./

# Use lockfile-based install (requires package-lock.json in apps/node-hello)
RUN npm ci --omit=dev

# Copy the rest of the app source
COPY apps/node-hello/ ./

# If your app has a build step, keep it safe:
RUN npm run build --if-present

# ---- runtime stage ----
FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

# Copy installed deps + built app
COPY --from=deps /app /app

# Update this if your app listens on a different port
EXPOSE 3000

# If package.json has "start", this will work:
CMD ["npm", "start"]
