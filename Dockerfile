FROM debian:12-slim

# Noninteractive to keep apt quiet in CI
ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies only (no -dev packages)
# Use BuildKit cache mounts for speedy rebuilds
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    set -eux; \
    apt-get update; \
    apt-get install --no-install-recommends -y \
      ca-certificates \
      libc6 \
      libc-bin \
      libgcc-s1 \
      libstdc++6 \
      libjson-c5 \
      libp11-kit0 \
      libcurl4 \
      libssl3 \
      jq \
      file \
    ; \
    rm -rf /var/lib/apt/lists/*

# Add required libs for pkcs11 provider in separate layer for better caching
# ignore symlinks.
# Note: The build process will copy the appropriate architecture libs
COPY vcpkg/installed/*/lib/ /usr/local/lib/

# Install aws kms (depends on aws-sdk-cpp libs) 
COPY aws-kms-pkcs11/aws_kms_pkcs11.so /usr/local/lib/

# Create required symlinks for above libs
RUN /usr/sbin/ldconfig

# Bootstrap the aws-kms provider (separate layer for config)
RUN mkdir -p /etc/aws-kms-pkcs11/ && ln -s /depot/aws-kms-config.json /etc/aws-kms-pkcs11/config.json

# Copy application binary (this should be the most frequently changing layer)
COPY certsquirt/certsquirt /usr/local/bin/certsquirt

# Set up working directory
WORKDIR /depot

ENTRYPOINT ["/usr/local/bin/certsquirt"]
