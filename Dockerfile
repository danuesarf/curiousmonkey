# One image, two roles. The command decides which: `node src/server.js` (API + portal) or `node src/worker.js` (scanner).
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
RUN addgroup -S cm && adduser -S cm -G cm
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY public ./public
USER cm
EXPOSE 8080 8081
# Default role is the API. The worker overrides the command.
CMD ["node", "src/server.js"]
