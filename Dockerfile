# syntax=docker/dockerfile:1

FROM node:20-alpine AS deps
WORKDIR /app

COPY apps/node-hello/package.json apps/node-hello/package-lock.json ./
RUN npm ci --omit=dev

COPY apps/node-hello/ ./
RUN npm run build --if-present

FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

COPY --from=deps /app /app

EXPOSE 3000
CMD ["npm", "start"]
