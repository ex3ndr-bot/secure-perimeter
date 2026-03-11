# Multi-stage build for minimal image
FROM node:22-slim AS builder
WORKDIR /app
COPY server/package.json server/package-lock.json* ./
RUN npm ci --production=false
COPY server/ .
RUN npm run build

FROM node:22-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends tpm2-tools && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json .

USER 1000
EXPOSE 8443
CMD ["node", "dist/main.js"]
