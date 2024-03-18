#!/bin/bash
# This script will conditionally build all required PoC images to reproduce
# the evaluation results of the Terrapin attack paper.

SCRIPT_DIR=$(dirname "$0")

function build_image_conditional {
  if ! docker image inspect terrapin-artifacts/$1 > /dev/null 2>&1; then
    docker build $SCRIPT_DIR --target $1 -t terrapin-artifacts/$1
  fi
}

############################################################
## Sequence Number Manipulations (Section 4.1)            ##
############################################################
build_image_conditional sqn-rcv-decrease
build_image_conditional sqn-rcv-increase
build_image_conditional sqn-snd-decrease
build_image_conditional sqn-snd-increase

############################################################
## Extension Downgrade (Section 5.2 / Figure 5)           ##
############################################################
build_image_conditional ext-downgrade-chacha20-poly1305
build_image_conditional ext-downgrade-cbc-unknown
build_image_conditional ext-downgrade-cbc-ping

############################################################
## Attacks on AsyncSSH (Section 6.1-6.2 / Figure 6-7)     ##
############################################################
build_image_conditional asyncssh-rogue-extension-negotiation
build_image_conditional asyncssh-rogue-session-attack
