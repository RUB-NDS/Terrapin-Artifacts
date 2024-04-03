# Dockerfile for Dropbear 2022.83 (based on Alpine Linux 3.16)

ARG VERSION=2022.83
ARG USERNAME=victim
ARG PASSWORD=secret

FROM alpine:3.16 as dropbear-builder
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
RUN apk add --no-cache bzip2 build-base zlib-dev

ARG VERSION
# RUN wget -O - -q "https://matt.ucc.asn.au/dropbear/releases/dropbear-${VERSION}.tar.bz2" | bunzip2 | tar -xf -
COPY source/dropbear-${VERSION}.tar.bz2 /
RUN cat "/dropbear-${VERSION}.tar.bz2" | bunzip2 | tar -xf -
WORKDIR "/dropbear-${VERSION}"

# Server image
FROM dropbear-builder as dropbear-server
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
# Configure, build and install dropbear, then add the pre-generated hostkeys.
RUN ./configure && \
    make PROGRAMS="dropbear" -j "$(nproc)" && \
    make PROGRAMS="dropbear" install

COPY files/dropbear_rsa_host_key /etc/dropbear/
RUN chmod 600 /etc/dropbear/dropbear_rsa_host_key

# Set up SSH user and configure a password
ARG USERNAME
ARG PASSWORD
RUN adduser -D "${USERNAME}" && \
    echo "${USERNAME}:${PASSWORD}" | chpasswd && \
    chown -R "${USERNAME}:${USERNAME}" "/home/${USERNAME}"
ARG VERSION
LABEL ssh.implementation.name="dropbear" \
      ssh.implementation.version="${VERSION}" \
      ssh.implementation.type="server"
ENTRYPOINT ["dropbear", "-FEB"]
EXPOSE 22

# Client image
FROM dropbear-builder AS dropbear-client

# Configure, build and install dbclient
RUN ./configure && \
    make PROGRAMS="dbclient" -j "$(nproc)" && \
    make PROGRAMS="dbclient" install

COPY files/known_hosts /root/.ssh/

ARG VERSION
LABEL ssh.implementation.name="dropbear" \
      ssh.implementation.version="${VERSION}" \
      ssh.implementation.type="client"
ENTRYPOINT [ "dbclient" ]
