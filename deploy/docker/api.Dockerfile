# Control plane image: API server, background worker, migrations and the vigil-admin CLI.
# Build context: repository root.
FROM node:22.22.2-bookworm-slim AS base
ENV PNPM_HOME=/pnpm PATH=/pnpm:$PATH CI=1
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
WORKDIR /app

FROM base AS deps
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/api/package.json apps/api/
COPY packages/core/package.json packages/core/
COPY packages/db/package.json packages/db/
# Root (tsx loader) + api and its workspace dependencies; the web app is not part of this image.
RUN pnpm install --frozen-lockfile --filter . --filter "@vigil/api..." --filter @vigil/db

FROM base AS runtime
ENV NODE_ENV=production VIGIL_HOST=0.0.0.0 PORT=8080
COPY --from=deps /app /app
COPY tsconfig.base.json ./
COPY packages/core packages/core
COPY packages/db packages/db
COPY apps/api apps/api
COPY deploy/docker/entrypoint.sh /usr/local/bin/vigil-entrypoint
RUN printf '#!/bin/sh\ncd /app/apps/api && exec node --import tsx src/admin-cli.ts "$@"\n' > /usr/local/bin/vigil-admin \
 && printf '#!/bin/sh\ncd /app/packages/db && exec node --import tsx src/migrate.ts\n' > /usr/local/bin/vigil-migrate \
 && chmod 755 /usr/local/bin/vigil-admin /usr/local/bin/vigil-migrate /usr/local/bin/vigil-entrypoint \
 && mkdir -p /data && chown node:node /data
ARG VIGIL_VERSION=dev
ENV VIGIL_VERSION=$VIGIL_VERSION VIGIL_DATA_DIR=/data
USER node
WORKDIR /app/apps/api
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
ENTRYPOINT ["/usr/local/bin/vigil-entrypoint"]
CMD ["node", "--import", "tsx", "src/server.ts"]
