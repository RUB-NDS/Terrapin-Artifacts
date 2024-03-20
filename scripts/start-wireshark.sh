#!/bin/bash
wireshark -i lo \
  -k \
  -d tcp.port==2200,ssh \
  -d tcp.port==2201,ssh \
  -Y ssh
