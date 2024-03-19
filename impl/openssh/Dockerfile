# Dockerfile for OpenSSH 9.4p1 / 9.5p1 (based on Debian Bullseye)

ARG VERSION=9.5p1
ARG USERNAME=victim
ARG PASSWORD=secret

FROM debian:bullseye AS openssh-builder
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    libssl-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
ARG VERSION
WORKDIR /src
COPY source/openssh-${VERSION}.tar.gz /tmp/
RUN tar -xzf /tmp/openssh-${VERSION}.tar.gz -C /src && rm /tmp/openssh-${VERSION}.tar.gz

WORKDIR "/src/openssh-${VERSION}"
RUN ./configure --prefix /install && \
    make -j "$(nproc)" && \
    make install-files install-sysconf

# Common base image for client and server image.
FROM debian:bullseye AS openssh-base
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

ARG USERNAME
ARG PASSWORD
RUN useradd --create-home --groups users "${USERNAME}" && \
    echo "${USERNAME}:${PASSWORD}" | chpasswd

COPY files/ssh_host_rsa_key /install/etc/
RUN chmod 600 /install/etc/ssh_host_rsa_key

# Server image
FROM openssh-base AS openssh-server

RUN useradd --system --no-create-home sshd && mkdir -p "/var/empty"

ARG VERSION
COPY --from=openssh-builder /install /install
LABEL ssh.implementation.name="openssh" \
      ssh.implementation.version="${VERSION}" \
      ssh.implementation.type="server"

# Rate Limit: Increase `MaxStartups` to make it unlikely to trigger the
# `Exceeded MaxStartups\r\n` issue, even when opening a lot of connections.
ENTRYPOINT [ "/install/sbin/sshd", "-D", "-e", "-o", "MaxStartups=65536" ]
EXPOSE 22

# Client image
FROM openssh-base AS openssh-client

ARG VERSION
COPY --from=openssh-builder /install /install
COPY files/known_hosts /root/.ssh/

LABEL ssh.implementation.name="openssh" \
      ssh.implementation.version="${VERSION}" \
      ssh.implementation.type="client"
ENTRYPOINT [ "/install/bin/ssh" ]
