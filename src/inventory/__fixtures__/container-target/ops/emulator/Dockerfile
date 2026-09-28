# The local cloud emulator, on an untagged base image, with no USER of its own:
# a tooling image whose two worst-looking shapes are both inherent to it.
FROM localstack/localstack

# Install Node.js and necessary tools
ENV NODE_MAJOR=22
RUN apt-get update && \
    apt-get install -y ca-certificates curl jq xz-utils && \
    rm -rf /var/lib/apt/lists/*
