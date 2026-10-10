FROM node:22-alpine AS build
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@10.6.5 --activate
# Build context is the repository root:
#   docker build -f packages/mcp/Dockerfile -t theauth-mcp .
COPY . .
RUN pnpm install --frozen-lockfile --filter @glinr/theauth-mcp... \
 && pnpm --filter @glinr/theauth-mcp build \
 && pnpm --filter @glinr/theauth-mcp deploy --prod /out

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /out/package.json ./package.json
COPY --from=build /out/dist ./dist
COPY --from=build /out/node_modules ./node_modules
USER node
# No secrets are baked in. Pass THEAUTH_API_URL and THEAUTH_API_KEY at run time.
ENTRYPOINT ["node", "/app/dist/bin.js"]
