# Artifacts for Terrapin

This repository contains artifacts for the paper "Terrapin Attack: Breaking SSH Channel Integrity By Sequence Number Manipulation", currently under submission.

## Repository Structure

    .
    ├── pocs                    # Proof of concept scripts
    │   ├── sqn-manipulations   # Scripts related to sequence number manipulation (section 4.1)
    │   ├── ext-downgrade       # Scripts related to the extension downgrade attack (section 5.2)
    │   └── asyncssh            # Scripts related to AsyncSSH vulnerabilities (section 6)
    ├── scan                    # Files related to the internet-wide scan conducted
    │   ├── 20231010_zgrab2_22_clean.acc.json 
    │   │                       # Aggregated results file produced by the scan_util.py script (anonymized)
    │   ├── scan_util.py        # Utility script for aggregating zgrab2 ssh results
    │   └── requirements.txt    # pip requirements file for scan_util.py
    ├── traces                  # PCAP traces of the PoC scripts
    ├── LICENSE
    └── README.md

## Getting Started (PoCs)

First of all, make sure that you are running a recent version of Python 3 (Python 3.11.4 has been used during development). Then, install the external dependencies by running:

```bash
pip install -r pocs/requirements.txt
```

To run a PoC, simply execute the corresponding python script. All PoCs are implemented as proxies at the TCP layer and bind to 127.0.0.1:2222 by default, connecting to the server on 127.0.0.1:22. This reduces the management overhead, as we don't have to deal with TCP sequence numbers and checksums. All PoCs can also be implemented at a lower layer and could use well-known techniques to obtain a man-in-the-middle position.

## Getting Started (scan_util.py)

Make sure you have a recent version of Python 3 installed (Python 3.11.4 has been used during development).

Install the required pip libraries by calling:

```bash
pip install -r scan/requirements.txt
```

You now may use the tool. A CLI help for the entire tool as well as individual commands is available by calling:

```bash
python scan_util.py [Command] --help
```

### Usage examples

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

## Acknowledgements

The following third party libraries are used:

- CLI interface: [Click](https://github.com/pallets/click/)
- CLI progress bar: [tqdm](https://github.com/tqdm/tqdm)
