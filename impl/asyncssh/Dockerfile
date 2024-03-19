# Dockerfile for AsyncSSH 2.13.2

ARG VERSION=2.13.2
ARG USERNAME=victim
ARG PASSWORD=secret

FROM python:3.12 AS asyncssh-base

WORKDIR /usr/src/app
COPY files/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

ARG VERSION
COPY source/asyncssh-${VERSION}-py3-none-any.whl /usr/src/app/
RUN pip install --no-cache-dir asyncssh-${VERSION}-py3-none-any.whl && \
      rm asyncssh-${VERSION}-py3-none-any.whl

# Server image
FROM asyncssh-base AS asyncssh-server

ARG USERNAME
ARG PASSWORD

# Copy server script and RSA server key
COPY files/simple_server.py files/ssh_host_rsa_key ./
RUN chmod 600 ssh_host_rsa_key

LABEL ssh.implementation.name="asyncssh" \
      ssh.implementation.version="${VERSION}" \
      ssh.implementation.type="server"
# Environment variables are picked up by the simple_server.py script
ENV SSH_USERNAME="${USERNAME}" SSH_PASSWORD="${PASSWORD}"

ENTRYPOINT [ "python", "/usr/src/app/simple_server.py" ]
EXPOSE 22

# Client image
FROM asyncssh-base AS asyncssh-client

# Copy client script
COPY files/simple_client.py ./
COPY files/known_hosts /root/.ssh/

LABEL ssh.implementation.name="asyncssh" \
      ssh.implementation.version="${VERSION}" \
      ssh.implementation.type="client"

ENTRYPOINT [ "python", "/usr/src/app/simple_client.py" ]
