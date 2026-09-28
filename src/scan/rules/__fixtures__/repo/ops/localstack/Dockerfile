# A local service emulator on an untagged base image with no `USER` of its own:
# the two shapes a whole-repository scan reports at `high` on an image that only
# a workstation ever builds, and which the tooling classifier therefore caps.
FROM localstack/localstack

RUN apt-get update && \
    apt-get install -y python3-pip unzip && \
    rm -rf /var/lib/apt/lists/*
