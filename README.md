# Artifacts for Terrapin

This repository contains artifacts for the paper "Terrapin Attack: Breaking SSH Channel Integrity By Sequence Number Manipulation", accepted at 33rd USENIX Security Symposium.

## Repository Structure

    .
    ├── impl
    │   ├── asyncssh                 # AsyncSSH 2.13.2 (client / server) Dockerfile and additional files
    │   ├── dropbear                 # Dropbear 2022.83 (client / server) Dockerfile and additional files
    │   ├── libssh                   # libssh 0.10.5 (client / server) Dockerfile and additional files
    │   ├── openssh                  # OpenSSH 9.4p1 / 9.5p1 (client / server) Dockerfile and additional files
    │   ├── putty                    # PuTTY 0.79 (client only) Dockerfile and additional files
    │   └── build.sh                 # Script to build all required implementation Docker images for reproducing our results
    ├── pocs                         # Proof of concept scripts
    │   ├── sqn-manipulations        # Scripts related to sequence number manipulation (section 4.1)
    │   ├── ext-downgrade            # Scripts related to the extension downgrade attack (section 5.2)
    │   ├── asyncssh                 # Scripts related to AsyncSSH vulnerabilities (section 6)
    │   ├── Dockerfile               # Multistage Dockerfile to build PoC docker images
    │   └── build.sh                 # Script to build all required PoC Docker images for reproducing our results
    ├── scan                         # Files related to the internet-wide scan conducted
    │   ├── 20231010_zgrab2_22_clean.acc.json 
    │   │                            # Aggregated results file produced by the scan_util.py script (anonymized)
    │   ├── scan_util.py             # Utility script for aggregating zgrab2 ssh results
    │   ├── requirements.txt         # pip requirements file for scan_util.py
    │   └── Dockerfile               # Dockerfile for scan_util.py
    ├── scripts                      # Scripts for easier reproduction of our results presented in the paper
    │   ├── bench-ext-downgrade.sh   # Benchmark script to evaluate the success rate of the CBC-EtM variant of the extension downgrade attack
    │   ├── cleanup-system.sh        # A cleanup script which can be used to containers and images related to these artifacts
    │   ├── test-asyncssh-rogue-extension-negotiation.sh
    │   │                            # Test script for the AsyncSSH-specific rogue extension negotiation attack (section 6.1 / figure 6)
    │   ├── test-asnycssh-rogue-session-attack.sh
    │   │                            # Test script for the AsyncSSH-specific rogue session attack (section 6.2 / figure 7)
    │   ├── test-ext-downgrade.sh    # Test script for the extension downgrade attack (section 5.2 / figure 5)
    │   └── test-sqn-manipulation.sh # Test script for sequence number manipulation (section 4.1)
    ├── traces                       # PCAP traces of the PoC scripts
    ├── LICENSE
    └── README.md

## Getting Started

All PoCs and scripts contained within these artifacts are designed to be run inside of Docker containers. As such, ensure that you have a recent
Linux (tested) or MacOS / Windows (untested) operating system with Docker installed. For easy reproduction of the paper results refer to the
scripts contained in the `scripts` folder (see repository structure above).

All scripts will run the containers in `--network host` to allow for easy capturing using Wireshark on the lo interface. By default, SSH servers
will bind to port 2200/tcp while PoC scripts will bind to 2201/tcp. As PoC scripts and SSH servers are binding to 0.0.0.0 it is advised to disconnect
your system from the network or configure your firewall properly to avoid disclosing insecure SSH services to your local network.

You may also build and run individual Docker containers (PoC and SSH implementations) at your own discretion.

### Usage examples for scan_util.py

Evaluation of a zgrab2 results file:

```bash
python scan_util.py -i zgrab2.json -o zgrab2.acc.json
```

Removal of blocked IP addresses from a list of IP addresses returned by zmap:

```bash
python scan_util.py filter-blocked-ips -i zmap.csv -o zmap-filtered.csv -b blocklist.txt
```

Tidying zgrab2 results file by removing entries with connection failures:

```bash
python scan_util.py tidy-zgrab2 -i zgrab2.json -o zgrab2-clean.json
```

## Troubleshooting

1. When exiting a test script prematurely (i.e. by through a keyboard interrupt), containers will not be terminated nor removed from the system. This can impact subsequent runs of
test scripts as container names are reused throughout the scripts. To avoid this, please run `scripts/cleanup-system.sh` which will terminate and remove any running container
related to these artifacts and cause images to be rebuilt upon next test script run.
2. PoC scripts may exit with an error indicating that the address is already in use. This can occur when a test script run has been interrupted earlier and another test script
is started in quick succession. To resolve the issue wait a decent amount of time in between runs (~1 minute) to allow the system to cleanup the socket listener.

## Acknowledgements

The following third party libraries are used:

- CLI interface: [Click](https://github.com/pallets/click/)
- CLI progress bar: [tqdm](https://github.com/tqdm/tqdm)
