# Terrapin Attack: Breaking SSH Channel Integrity By Sequence Number Manipulation - Artifacts

This repository contains artifacts for the paper "Terrapin Attack: Breaking SSH Channel Integrity By Sequence Number Manipulation", accepted at 33rd USENIX Security Symposium.

The code in this repository contains, among other artifacts, proof-of-concept attack proxies for the following CVEs:

- [CVE-2023-48795](https://nvd.nist.gov/vuln/detail/CVE-2023-48795) (general protocol flaw)
- [CVE-2023-46445](https://nvd.nist.gov/vuln/detail/CVE-2023-46445) (AsyncSSH rogue extension negotiation)
- [CVE-2023-46446](https://nvd.nist.gov/vuln/detail/CVE-2023-46446) (AsyncSSH rogue session attack)

## Description & Requirements

All PoCs and scripts contained within these artifacts are designed to be run inside of Docker containers. As such, ensure that you have a recent
Linux (tested) or MacOS / Windows (untested) operating system with Docker installed. For easy reproduction of the paper results refer to the
scripts contained in the `scripts` folder (see repository structure above).

All scripts will run the containers in `--network host` to allow for easy capturing using Wireshark on the lo interface. By default, SSH servers
will bind to port 2200/tcp while PoC scripts will bind to 2201/tcp. As PoC scripts and SSH servers are binding to 0.0.0.0 it is advised to disconnect
your system from the network or configure your firewall properly to avoid disclosing insecure SSH services to your local network.

You may also build and run individual Docker containers (PoC and SSH implementations) at your own discretion.

### Software Requirements

- Linux or MacOS. No specific distribution or version is required. We used Manjaro (rolling release in March 2024) and MacOS 14.4 (Sonoma). Windows WSL might work but is untested and not supported.
- Bash shell interpreter (typically included in the above). No specific version is required. We used bash 5.2.26 and 3.2.57.
- Docker Engine or Docker Desktop. While Docker Engine suffices and is typically included in Linux distributions, Docker Desktop is a separate install on MacOS. No specific version is required. We used Docker Engine 25.0.3 and Docker Desktop 4.28.0.
  - **Linux:** [https://docs.docker.com/engine/install](https://docs.docker.com/engine/install)
  - **MacOS:** [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop)

### Basic Functionality Test

You may run `impl/build.sh` and `pocs/build.sh` to check your setup. The output should indicate that the evaluation images are being built using Docker. If there is no output, all docker images are already built.

```bash
$ impl/build.sh
[+] Building 2.0s (15/15) FINISHED
[...]
=> => naming to docker.io/terrapin-artifacts/openssh-server:9.4p1
[...]
$ pocs/build.sh
[...]
```

## Evaluation Workflow

### Major Claims

- **(C1): Sequence Number Manipulation (Sect. 4.1).** We verified all techniques successfully against PuTTY 0.79. Additionally, our experiments show that OpenSSH 9.5p1 recognizes a rollover of sequence numbers and terminates the connection, thus not affected by any technique but RcvIncrease. AsyncSSH 2.13.2 and libssh 0.10.5 allow for RcvIncrease but terminate the connection due to handshake timeouts before any advanced technique concludes. Dropbear 2022.83 disconnects on UNKNOWN messages instead of responding with UNIMPLEMENTED but allows Rcv to roll over, therefore being affected by RcvIncrease and RcvDecrease only.
- **(C2): Extension Downgrade (Sect. 5.2).** We successfully evaluated the attack in 10,000 trials on ChaCha20-Poly1305 and CBC-EtM against OpenSSH 9.5p1 and PuTTY 0.79 clients, connecting to OpenSSH 9.4p1 (UNKNOWN only) and 9.5p1. For CBC-EtM, our success rate in practice was 0.0003 (OpenSSH) resp. 0.0300 (PuTTY), improved to 0.0074 (OpenSSH) resp. 0.8383 (PuTTY) when sending PING instead of UNKNOWN.
- **(C3): Rogue Extension Negotiation (Sect. 6.1).** We successfully evaluated the attack against AsyncSSH 2.13.2 as a client, connecting to AsyncSSH 2.13.2.
- **(C4): Rogue Session Attack (Sect. 6.2).** We successfully evaluated the attack against AsyncSSH 2.13.2 as a server, connecting to AsyncSSH 2.13.2.

### Expected Results

|        Attack        |            PuTTY 0.79             |   OpenSSH 9.4p1    |           OpenSSH 9.5p1           |  Dropbear 2022.83  |  AsyncSSH 2.13.2   |   libssh 0.10.5    |
| :------------------: | :-------------------------------: | :----------------: | :-------------------------------: | :----------------: | :----------------: | :----------------: |
|    C1 RcvIncrease    |        :white_check_mark:         |         -          |        :white_check_mark:         | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|    C1 RcvDecrease    |        :white_check_mark:         |         -          |                 R                 | :white_check_mark: |         T          |         T          |
|    C1 SndIncrease    |        :white_check_mark:         |         -          |                 R                 |         U          |         T          |         T          |
|    C1 SndDecrease    |        :white_check_mark:         |         -          |                 R                 |         U          |         T          |         T          |
| C2 ChaCha20-Poly1305 |        :white_check_mark:         | :white_check_mark: |        :white_check_mark:         |         -          |         -          |         -          |
|      C2 CBC-EtM      | 0.0300 (UNKNOWN)<br>0.8383 (PING) |  0.0003 (UNKNOWN)  | 0.0003 (UNKNOWN)<br>0.0074 (PING) |         -          |         -          |         -          |
|  C3 Rogue Extension  |                 -                 |         -          |                 -                 |         -          | :white_check_mark: |         -          |
|   C4 Rogue Session   |                 -                 |         -          |                 -                 |         -          | :white_check_mark: |         -          |

### Experiments

- **(E1): `scripts/test-sqn-manipulation.sh`** - Run one of the four sequence number manipulation attacks to prove (C1).
  - _Expected Runtime:_ About 1 - 3 hours per client / variant combination.
  - _Execution:_ After starting the script, choose a client, one of the four attack options, and input the manipulation offset N. To prove (C1), input N = 1.
  - _Results:_ The attack is complete once the progress bar fills. After that, there will be an error message because the secure channel is broken, as the script does not implement any prefix truncation to complete the attack.
- **(E2a): `scripts/test-ext-downgrade.sh`** - Run the extension downgrade attack to prove (C2) for ChaCha20-Poly1305.

  - _Expected Runtime:_ About 1 minute.
  - _Execution:_ After starting the script, choose an arbitrary client and server combination. Afterward, choose attack variant 1 to select ChaCha20-Poly1305.
  - _Results:_ The script will conclude by opening the following files simultaneously in `less`:

    1. `diff` of files 3 and 4
    2. `diff` of files 5 and 6
    3. Server log (unmodified connection)
    4. Server log (tampered connection)
    5. Client log (unmodified connection)
    6. Client log (tampered connection)
    7. PoC proxy log

    Navigate to the second file. The file compares the output of the selected SSH client in the case of an extension downgrade attack to the output of an unmodified connection. The diff will indicate the presence of SSH_MSG_EXT_INFO and absence of SSH_MSG_IGNORE in the unmodified connection only, thus proving (C2) for ChaCha20-Poly1305.

- **(E2b): `scripts/bench-ext-downgrade.sh`** - Run the extension downgrade attack 10,000 times to prove (C2) for CBC-EtM (UNKNOWN and PING).
  - _Expected Runtime:_ About 1 - 2 hours per client/variant combination.
  - _Execution:_ After starting the script, choose between UNKNOWN and PING variants of the attack, then select between OpenSSH and PuTTY client. A progress bar will show the current trial.
  - _Results:_ After finishing all trial connections, the number of successful trial runs will be outputted to the console. The relative success rate will be close to the values claimed in (C2), thus proving the functionality and success probability claims in (C2) in the case of CBC-EtM.
- **(E3): `scripts/test-asyncssh-rogue-ext-negotiation.sh`**
  - _Expected Runtime:_ About 1 minute.
  - _Execution:_ The attack is automatic.
  - _Results:_ The script will conclude by opening a set of seven files in `less`. Refer to the results of (E2a) for a list of files opened. Navigate to the second file. The diff will indicate the presence of the server-sig-algs extension with an attacker-chosen value in the tampered connection, thus proving (C3).
- **(E4): `scripts/test-asyncssh-rogue-session-attack.sh`**
  - _Expected Runtime:_ About 1 minute.
  - _Execution:_ The attack is automatic.
  - _Results:_ The script will conclude by opening a set of seven files in `less`. Refer to the results of (E2a) for a list of files opened. Navigate to the first file. The diff will indicate successful authentication for the victim (unmodified connection) and attacker (tampered connection), respectively. Afterward, navigate to the second file and examine the output of each client connection at the end of the file. In the unmodified connection, the server will respond with the username victim, while in the attacked connection, the server will respond with the username attacker. This proves (C4).

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
    │   ├── sample                   # Directory containing an anonymized zgrab2 ssh results sample to use with scan_util.py
    │   ├── scan_util.py             # Utility script for aggregating zgrab2 ssh results
    │   ├── requirements.txt         # pip requirements file for scan_util.py
    │   └── Dockerfile               # Dockerfile to build a docker image running scan_util.py
    ├── scripts                      # Scripts for easier reproduction of our results presented in the paper
    │   ├── bench-ext-downgrade.sh   # Benchmark script to evaluate the success rate of the CBC-EtM variant of the extension downgrade attack
    │   ├── cleanup-system.sh        # A cleanup script which can be used to containers and images related to these artifacts
    │   ├── start-wireshark.sh       # A convenience script to start Wireshark capturing on lo interface with SSH decoding and display filter
    │   ├── test-asyncssh-rogue-ext-negotiation.sh
    │   │                            # Test script for the AsyncSSH-specific rogue extension negotiation attack (section 6.1 / figure 6)
    │   ├── test-asnycssh-rogue-session-attack.sh
    │   │                            # Test script for the AsyncSSH-specific rogue session attack (section 6.2 / figure 7)
    │   ├── test-ext-downgrade.sh    # Test script for the extension downgrade attack (section 5.2 / figure 5)
    │   └── test-sqn-manipulation.sh # Test script for sequence number manipulation (section 4.1)
    ├── traces                       # PCAP traces of the PoC scripts
    ├── LICENSE
    └── README.md

## Acknowledgements

The following third party libraries are used:

- CLI interface: [Click](https://github.com/pallets/click/)
- CLI progress bar: [tqdm](https://github.com/tqdm/tqdm)
