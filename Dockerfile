# Minimal, secure-ish Node image for CI scanning
FROM node:20-alpine

# Fix Trivy findings from npm bundled deps
RUN npm install -g npm@latest

WORKDIR /app

# Install only production dependencies
COPY package*.json ./
RUN npm ci --omit=dev

# Copy application code
COPY . .

EXPOSE 3000
CMD ["node", "server.js"]
