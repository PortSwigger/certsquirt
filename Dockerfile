FROM ubuntu:latest

# Install aws kms dependencies
# awscli has been removed from the repo's and is now - unhelpfully - a 'snap' installed app.
RUN apt update && apt install --no-install-recommends -y libjson-c5 jq ca-certificates

### add required libs for pkcs11 provider
# ignore symlinks.
COPY vcpkg/installed/x64-linux-dynamic/lib/ /usr/local/lib/

# Install aws kms (depends on aws-sdk-cpp libs
COPY aws-kms-pkcs11/aws_kms_pkcs11.so /usr/local/lib/
# create required symlinks for above libs
RUN /usr/sbin/ldconfig

# bootstrap the aws-kms provider
RUN mkdir -p /etc/aws-kms-pkcs11/ && ln -s /depot/aws-kms-config.json /etc/aws-kms-pkcs11/config.json

# Copy SCEP server images
COPY certsquirt /certsquirt

ENTRYPOINT ["/certsquirt/certsquirt"]
