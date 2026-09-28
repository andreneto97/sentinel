# The other half of every branch the shipping-stage reader has: a digest-pinned
# base, a final stage that names an earlier one by alias, a HEALTHCHECK, an
# explicit `USER root`, and a credential in the environment the image ships.
FROM node:24.8.0-bookworm-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS base

WORKDIR /srv

FROM base

ENV SERVICE_API_TOKEN=live-token-not-a-placeholder

HEALTHCHECK --interval=10s CMD curl -f http://localhost:3000/health || exit 1

USER root

CMD ["node", "server.js"]
