# A developer-tooling image: it maps the host's uid and gid through build args so
# a bind-mounted checkout stays writable, and copies no application source of its
# own. Nothing deploys it, which is what the tooling classifier has to notice.
FROM node:24-bookworm-slim

ARG APP_USER=runner
ARG DOCKER_USER_ID
ARG DOCKER_GROUP_ID

RUN groupadd --gid "$DOCKER_GROUP_ID" --non-unique "$APP_USER" \
    && useradd --create-home --uid "$DOCKER_USER_ID" --gid "$DOCKER_GROUP_ID" \
       --non-unique --shell /bin/bash "$APP_USER"

COPY ./ops/docker/nodejs/entrypoint.sh /opt/entrypoint.sh

USER $APP_USER
ENTRYPOINT [ "bash", "/opt/entrypoint.sh" ]
