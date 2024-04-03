# Artifacts for Terrapin

This repository contains artifacts for the paper "Terrapin Attack: Breaking SSH Channel Integrity By Sequence Number Manipulation", accepted at 33rd USENIX Security Symposium.

The code in this repository contains, among other artifacts, proof-of-concept attack proxies for the following CVEs:

- [CVE-2023-48795](https://nvd.nist.gov/vuln/detail/CVE-2023-48795) (general protocol flaw)
- [CVE-2023-46445](https://nvd.nist.gov/vuln/detail/CVE-2023-46445) (AsyncSSH rogue extension negotiation)
- [CVE-2023-46446](https://nvd.nist.gov/vuln/detail/CVE-2023-46446) (AsyncSSH rogue session attack)

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
    │   ├── paper                    # Directory containing the aggregated scan data referenced in the final version of the paper
    │   ├── sample	                 # Directory containing an anonymized zgrab2 ssh results sample to use with scan_util.py
    │   ├── scan_util.py             # Utility script for aggregating zgrab2 ssh results
    │   ├── requirements.txt         # pip requirements file for scan_util.py
    │   └── Dockerfile               # Dockerfile to build a docker image running scan_util.py
    ├── scripts                      # Scripts for easier reproduction of our results presented in the paper
    │   ├── bench-ext-downgrade.sh   # Benchmark script to evaluate the success rate of the CBC-EtM variant of the extension downgrade attack
    │   ├── cleanup-system.sh        # A cleanup script which can be used to containers and images related to these artifacts
        ├── start-wireshark.sh       # A convenience script to start Wireshark capturing on lo interface with SSH decoding and display filter
    │   ├── test-asyncssh-rogue-extension-negotiation.sh
    │   │                            # Test script for the AsyncSSH-specific rogue extension negotiation attack (section 6.1 / figure 6)
    │   ├── test-asnycssh-rogue-session-attack.sh
    │   │                            # Test script for the AsyncSSH-specific rogue session attack (section 6.2 / figure 7)
    │   ├── test-ext-downgrade.sh    # Test script for the extension downgrade attack (section 5.2 / figure 5)
    │   └── test-sqn-manipulation.sh # Test script for sequence number manipulation (section 4.1)
    ├── traces                       # PCAP traces of the PoC scripts
    ├── LICENSE
    └── README.md

## Getting Started (PoCs)

All PoCs and scripts contained within these artifacts are designed to be run inside of Docker containers. As such, ensure that you have a recent
Linux (tested) or MacOS / Windows (untested) operating system with Docker installed. For easy reproduction of the paper results refer to the
scripts contained in the `scripts` folder (see repository structure above).

All scripts will run the containers in `--network host` to allow for easy capturing using Wireshark on the lo interface. By default, SSH servers
will bind to port 2200/tcp while PoC scripts will bind to 2201/tcp. As PoC scripts and SSH servers are binding to 0.0.0.0 it is advised to disconnect
your system from the network or configure your firewall properly to avoid disclosing insecure SSH services to your local network.

You may also build and run individual Docker containers (PoC and SSH implementations) at your own discretion.

## Getting Started (scan_util.py)

To use scan_util.py, build the docker container by running the following command inside the `scan` folder:

```bash
docker build . -t terrapin-artifacts/scan-util
```

### Usage

Evaluation of a zgrab2 results file:

```bash
docker run --rm -v ./sample:/files terrapin-artifacts/scan-util evaluate -i /files/sample.json -o /files/sample.acc.json
```

Removal of blocked IP addresses from a list of IP addresses returned by zmap:

```bash
docker run --rm -v ./sample:/files terrapin-artifacts/scan-util filter-blocked-ips -i /files/zmap.csv -o /files/zmap-filtered.csv -b /files/blocklist.txt
```

Tidying zgrab2 results file by removing entries with connection failures:

```bash
docker run --rm -v ./sample:/files terrapin-artifacts/scan-util tidy-zgrab2 -i /files/sample.json -o /files/sample-clean.json
```

## Troubleshooting

1. When exiting a test script prematurely (i.e. by through a keyboard interrupt), containers will not be terminated nor removed from the system. This can impact subsequent runs of
test scripts as container names are reused throughout the scripts. To avoid this, please run `scripts/cleanup-system.sh` which remove any intermediate results and terminate and remove any running container
related to these artifacts. To rebuild the images on next execution of a test script, specify the `--full` flag.
2. PoC scripts may exit with an error indicating that the address is already in use. This can occur when a test script run has been interrupted earlier and another test script
is started in quick succession. To resolve the issue wait a decent amount of time in between runs (up to 4 minutes) to allow the system to cleanup the socket listener.

## Acknowledgements

The following third party libraries are used:

- CLI interface: [Click](https://github.com/pallets/click/)
- CLI progress bar: [tqdm](https://github.com/tqdm/tqdm)
