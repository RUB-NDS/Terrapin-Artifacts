# Dockerfile for PuTTY 0.79 (client only; based on Debian Bullseye)

ARG VERSION=0.79

FROM debian:bullseye AS putty-client
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        build-essential \
        libssl-dev \
        zlib1g-dev \
        libgtk-3-0 \
        libgtk-3-dev \
        cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/bin/putty
ARG VERSION
COPY source/putty-${VERSION}.tar.gz /usr/bin/putty/
RUN tar xzf putty-${VERSION}.tar.gz --strip-components=1 -C . \
    && rm -rf putty-0.79.tar.gz

RUN cmake . && \
    cmake --build . && \
    cmake --build . --target install

COPY files/sshhostkeys /root/.putty/

LABEL "ssh.implementation.name"="putty" \
    "ssh.implementation.version"="${VERSION}" \
    "ssh.implementation.type"="client"
ENTRYPOINT [ "/usr/local/bin/plink" ]

