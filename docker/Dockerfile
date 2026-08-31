# selfhostauth server image
#
# pnpm monorepo: build everything in the build stage, prune dev deps, then
# copy the tree (node_modules store + workspace packages + server app).
# pnpm uses RELATIVE symlinks on Linux, so the copied layout stays valid.

FROM node:26-alpine AS build
WORKDIR /app
RUN corepack enable

# Install with workspace manifests only (fast, cache-friendly)
COPY package.json pnpm-workspace.yaml tsconfig.base.json ./
COPY packages/core/package.json packages/core/
COPY packages/client/package.json packages/client/
COPY apps/server/package.json apps/server/
COPY apps/web/package.json apps/web/
RUN pnpm install --frozen-lockfile=false

# Copy sources and build all packages (including web UI)
COPY packages/core packages/core
COPY packages/client packages/client
COPY apps/server apps/server
COPY apps/web apps/web
RUN pnpm --filter @selfhostauth/server... build && pnpm --filter @selfhostauth/web build

# Prune dev dependencies for a lean runtime image
RUN pnpm install --prod --frozen-lockfile=false

FROM node:26-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/package.json /app/package.json
COPY --from=build /app/pnpm-workspace.yaml /app/pnpm-workspace.yaml
COPY --from=build /app/node_modules /app/node_modules
COPY --from=build /app/packages /app/packages
COPY --from=build /app/apps/server /app/apps/server
COPY --from=build /app/apps/web/dist /app/apps/web/dist
ENV DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8787
CMD ["node", "apps/server/dist/index.js"]