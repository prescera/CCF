FROM mcr.microsoft.com/azurelinux/base/core:3.0
RUN gpg --import /etc/pki/rpm-gpg/MICROSOFT-RPM-GPG-KEY && tdnf -y update && \
    tdnf -y install ca-certificates openssl libuv nghttp2 curl-libs util-linux && \
    tdnf clean all && rm -rf /var/cache/tdnf
COPY cchost /usr/bin/cchost
COPY verify_tdx_attestation /usr/bin/verify_tdx_attestation
COPY constitution /opt/ccf-tdx/constitution
COPY collateral /opt/ccf-tdx/collateral
COPY initdata.toml /opt/ccf-tdx/initdata.toml
COPY node-config.json /opt/ccf-tdx/node-config.json
COPY node-config-join.json /opt/ccf-tdx/node-config-join.json
WORKDIR /host
