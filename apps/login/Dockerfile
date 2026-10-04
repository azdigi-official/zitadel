FROM node:22-alpine
WORKDIR /app
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs
# If /.env-file/.env is mounted into the container, its variables are made available to the server before it starts up.
RUN mkdir -p /.env-file && touch /.env-file/.env && chown -R nextjs:nodejs /.env-file

COPY --chown=nextjs:nodejs .next/standalone ./
# AZDIGI: the standalone server runs from apps/login and serves public/ relative to it; the traced output puts
# public/ at the root, so static files (checkbox.svg, azdigi/logo.png) were 404 without this copy.
COPY --chown=nextjs:nodejs public ./apps/login/public

USER nextjs
ENV HOSTNAME="::" \
    PORT="3000" \
    NODE_ENV="production"

# TODO: Check healthy, not ready
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/bin/sh", "-c", "node /app/healthcheck.js http://localhost:${PORT}/ui/v2/login/healthy"]
ENTRYPOINT ["/app/entrypoint.sh", "node", "apps/login/server.js" ]
