# A per-app image in a workspace: the build stage compiles the whole workspace,
# and the final stage packs prod-only files and drops to `nobody` through a
# build argument. One unit of audit, anchored at the second `FROM`.
FROM node:24-bookworm-slim as build

ARG NODE_AUTH_TOKEN
ENV NODE_AUTH_TOKEN=$NODE_AUTH_TOKEN

WORKDIR /tmp

COPY package.json ./
COPY apps ./apps
COPY libs ./libs

RUN npm install

RUN npm run build

#Packing prod-only files
FROM node:24-bookworm-slim
ARG USERNAME=nobody

RUN apt-get update \
    && apt-get install -y openssl dumb-init curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/dock-api

COPY --from=build /tmp/build ./build

COPY --from=build /tmp/node_modules ./node_modules

USER $USERNAME

CMD ["dumb-init", "node", "./build/apps/dock-api/src/main.js"]
