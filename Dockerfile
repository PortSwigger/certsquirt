FROM ubuntu:latest

# Install aws kms dependencies in a single layer with cache mount
# awscli has been removed from the repo's and is now - unhelpfully - a 'snap' installed app.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt update && apt install --no-install-recommends -y \
    libc6 \
    libc6-dev \
    libjson-c5 \
    libp11-kit0 \
    libcurl4 \
    libssl3 \
    jq \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Add required libs for pkcs11 provider in separate layer for better caching
# ignore symlinks.
COPY vcpkg/installed/x64-linux-dynamic/lib/ /usr/local/lib/

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
