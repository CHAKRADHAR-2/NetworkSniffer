# CodeAlpha Basic Network Sniffer

## Project Overview

A beginner-friendly Python-based passive network sniffer built with Scapy. It captures packets from a specified interface, analyzes their structure, and prints readable summaries and statistics for educational demonstrations.

## Objectives

- Demonstrate packet capture using Scapy's `sniff()`.
- Analyze common network protocols (TCP, UDP, ICMP, ARP, DNS).
- Show packet metadata and a safe payload summary.

## Features

- CLI-based sniffer (`sniffer.py`) with options for interface, packet count, timeout, and simple filters.
- Protocol identification via layer inspection.
- Safe, truncated payload summaries (sensitive keywords redacted).
- Capture statistics and top talkers.
- Basic unit tests for analysis logic.

## Technologies

- Python 3
- Scapy
- Pytest (for tests)

## Project Structure

codealpha-network-sniffer/
├── sniffer.py
├── packet_analyzer.py
├── protocol_utils.py
├── requirements.txt
├── README.md
├── .gitignore
└── tests/
    └── test_packet_analyzer.py

## Installation

1. Create and activate a virtual environment (recommended):

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows (PowerShell)
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

Note: On Windows install Npcap (https://nmap.org/npcap/) and run the script with Administrator privileges. On Linux, run with `sudo` or ensure appropriate capabilities (e.g., `setcap`).

## Finding Interfaces

List interfaces:

```bash
python sniffer.py --list-ifaces
```

## Usage Examples

Start sniffing on default interface (first available):

```bash
python sniffer.py
```

Capture 10 packets on interface `eth0`:

```bash
python sniffer.py -i eth0 -c 10
```

Capture for 30 seconds:

```bash
python sniffer.py -i eth0 -t 30
```

Filter only TCP packets:

```bash
python sniffer.py -i eth0 -f tcp
```

Filter by host IP:

```bash
python sniffer.py -i eth0 -f host=192.168.1.5
```

## Example Output

# ==================================================
CODEALPHA NETWORK SNIFFER

## Capture Configuration
Interface: eth0
Packet limit: 10
Filter: tcp

## Captured Packet
Packet number: 1
Timestamp: 2026-08-15T12:00:00
Source: 192.168.1.5
Destination: 93.184.216.34
Protocol: TCP
Source Port: 53624
Destination Port: 80
Length: 74
Payload: GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: ...

## Testing

Run pytest:

```bash
pytest -q
```

## Ethical and Legal Notice

Only capture traffic on networks and interfaces you own or where you have explicit authorization. Do not use this tool to intercept other people's private or sensitive data. This project is educational and does not provide any offensive capabilities.

## Limitations

- Does not attempt to decrypt TLS/HTTPS traffic.
- Payload summaries are truncated and redact common sensitive keywords, but users must take care not to expose secrets.

## Future Enhancements

- Add PCAP export (opt-in) with user confirmation.
- Add JSON output mode for further processing.
- Add richer protocol parsing for HTTP, DHCP, TLS metadata (no decryption).

## Recommended GitHub repository name

CodeAlpha_BasicNetworkSniffer
