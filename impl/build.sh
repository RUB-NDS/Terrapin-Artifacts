#!/bin/bash
# This script will conditionally build all required SSH implementation images to reproduce
# the evaluation results of the Terrapin attack paper.

SCRIPT_DIR=$(dirname "$0")

# AsyncSSH server 2.13.2
if ! docker image inspect terrapin-artifacts/asyncssh-server:2.13.2 > /dev/null 2>&1; then
  docker build $SCRIPT_DIR/asyncssh --target asyncssh-server -t terrapin-artifacts/asyncssh-server:2.13.2
fi
# AsyncSSH client 2.13.2
if ! docker image inspect terrapin-artifacts/asyncssh-client:2.13.2 > /dev/null 2>&1; then
  docker build $SCRIPT_DIR/asyncssh --target asyncssh-client -t terrapin-artifacts/asyncssh-client:2.13.2
fi
# Dropbear client 2022.83
if ! docker image inspect terrapin-artifacts/dropbear-client:2022.83 > /dev/null 2>&1; then
  docker build $SCRIPT_DIR/dropbear --target dropbear-client -t terrapin-artifacts/dropbear-client:2022.83
fi
# libssh client 0.10.5
if ! docker image inspect terrapin-artifacts/libssh-client:0.10.5 > /dev/null 2>&1; then
  docker build $SCRIPT_DIR/libssh --target libssh-client -t terrapin-artifacts/libssh-client:0.10.5
fi
# OpenSSH client 9.4p1
if ! docker image inspect terrapin-artifacts/openssh-client:9.4p1 > /dev/null 2>&1; then
  docker build $SCRIPT_DIR/openssh --target openssh-client -t terrapin-artifacts/openssh-client:9.4p1 --build-arg "VERSION=9.4p1"
fi
# OpenSSH server 9.4p1
if ! docker image inspect terrapin-artifacts/openssh-server:9.4p1 > /dev/null 2>&1; then
  docker build $SCRIPT_DIR/openssh --target openssh-server -t terrapin-artifacts/openssh-server:9.4p1 --build-arg "VERSION=9.4p1"
fi
# OpenSSH client 9.5p1
if ! docker image inspect terrapin-artifacts/openssh-client:9.5p1 > /dev/null 2>&1; then
  docker build $SCRIPT_DIR/openssh --target openssh-client -t terrapin-artifacts/openssh-client:9.5p1
fi
# OpenSSH server 9.5p1
if ! docker image inspect terrapin-artifacts/openssh-server:9.5p1 > /dev/null 2>&1; then
  docker build $SCRIPT_DIR/openssh --target openssh-server -t terrapin-artifacts/openssh-server:9.5p1
fi
# PuTTY client 0.79
if ! docker image inspect terrapin-artifacts/putty-client:0.79 > /dev/null 2>&1; then
  docker build $SCRIPT_DIR/putty --target putty-client -t terrapin-artifacts/putty-client:0.79
fi
