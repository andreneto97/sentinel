# The developer image: its build args map the host's uid/gid so a bind-mounted
# checkout stays writable, and it copies no application source of its own. That
# is what makes it tooling rather than an image anything deploys.
FROM node:24-bookworm-slim

ARG UNAME=dev
ARG DOCKER_USER_ID
ARG DOCKER_GROUP_ID

ENV DOCKER_USER_ID=$DOCKER_USER_ID\
    DOCKER_GROUP_ID=$DOCKER_GROUP_ID

RUN groupadd -g $DOCKER_GROUP_ID -o $UNAME
RUN useradd -m -u $DOCKER_USER_ID -g $DOCKER_GROUP_ID -o -s /bin/bash $UNAME

WORKDIR /app

ADD ./ops/compose/devbox/entrypoint.sh /opt/entrypoint.sh

USER $UNAME
# run the server with watcher
ENTRYPOINT [ "bash", "/opt/entrypoint.sh" ]
