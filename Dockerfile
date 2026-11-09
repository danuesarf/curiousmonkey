# One image, two roles. The command decides which: `node src/server.js` (API + portal) or `node src/worker.js` (scanner).
# The base is a tag that Dependabot keeps current. To pin it by digest (recommended for production):
#   docker buildx imagetools inspect node:22-alpine --format '{{json .Manifest.Digest}}'
# and use FROM node:22-alpine@sha256:<digest> in both stages; Dependabot then bumps the digest too.
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
# OS security updates; npm, npx and corepack are not needed at runtime (and their bundled packages are a common
# finding in image scans), so they go; a fixed, high UID that matches the Kubernetes runAsUser.
RUN apk upgrade --no-cache \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
 && addgroup -S -g 10001 cm && adduser -S -u 10001 -G cm cm
COPY --from=deps --chown=root:root /app/node_modules ./node_modules
COPY --chown=root:root package.json ./
COPY --chown=root:root src ./src
COPY --chown=root:root public ./public
USER 10001:10001
EXPOSE 8080 8081
# The API answers on 8080, the worker on 8081 (set HEALTH_PORT=8081 for a worker started without compose).
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD wget -qO- "http://127.0.0.1:${HEALTH_PORT:-8080}/healthz" >/dev/null || exit 1
# Default role is the API. The worker overrides the command.
CMD ["node", "src/server.js"]
