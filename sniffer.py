#!/usr/bin/env python3
"""CodeAlpha Network Sniffer - CLI entry point

Passive packet capture using Scapy with analysis hooks.
"""
from __future__ import annotations

import argparse
import signal
import sys
from typing import Optional

from scapy.all import sniff, get_if_list, get_if_addr
from scapy.all import IFACES

from packet_analyzer import PacketAnalyzer


def list_interfaces() -> list[str]:
    try:
        # Try to provide richer information on Windows via IFACES
        try:
            # IFACES is a scapy object mapping names to details on all platforms
            results = []
            for name, obj in IFACES.items():
                desc = getattr(obj, 'description', None) or getattr(obj, 'name', None) or name
                # Try to get an IPv4 address for readability
                ip = None
                try:
                    ip = get_if_addr(name)
                except Exception:
                    ip = None
                if ip in (None, "127.0.0.1"):
                    results.append(f"{name} — {desc}")
                else:
                    results.append(f"{name} — {desc} — {ip}")
            if results:
                return results
        except Exception:
            pass
        return get_if_list()
    except Exception:
        return []


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CodeAlpha Basic Network Sniffer")
    parser.add_argument("-i", "--iface", help="Network interface to capture on (default: first available)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-c", "--count", type=int, help="Number of packets to capture")
    group.add_argument("-t", "--timeout", type=int, help="Capture duration in seconds")
    parser.add_argument("-f", "--filter", default="", help="Simple filter: tcp, udp, icmp, arp, dns, host=<IP>")
    parser.add_argument("--list-ifaces", action="store_true", help="List available interfaces and exit")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output (if supported)")
    return parser.parse_args()


def translate_filter(user_filter: str) -> str:
    """Translate a simple user-friendly filter into a libpcap/BPF expression.

    Supported user filters: tcp, udp, icmp, arp, dns, host=<IP>
    Returns an empty string when no BPF should be applied.
    """
    if not user_filter:
        return ""
    uf = user_filter.strip().lower()
    if uf in ("tcp", "udp", "icmp", "arp"):
        return uf
    if uf == "dns":
        # Capture DNS over UDP and TCP (port 53) for IPv4 and IPv6
        return "(udp port 53 or tcp port 53)"
    if uf.startswith("host="):
        _, host = uf.split("=", 1)
        # Validate IP
        import ipaddress

        try:
            ipaddress.ip_address(host)
        except Exception:
            raise ValueError(f"Invalid host IP: {host}")
        return f"host {host}"
    # Unknown filters fall back to empty (no BPF)
    return ""


def main() -> None:
    args = parse_args()

    if args.list_ifaces:
        ifaces = list_interfaces()
        print("Available interfaces:")
        for i in ifaces:
            print(f" - {i}")
        return

    iface = args.iface
    if iface is None:
        # Prefer a non-loopback interface that has an IPv4 address
        candidates = []
        try:
            raw_ifaces = get_if_list()
            for ifn in raw_ifaces:
                try:
                    addr = get_if_addr(ifn)
                except Exception:
                    addr = None
                if addr and not addr.startswith("127."):
                    candidates.append(ifn)
            iface = candidates[0] if candidates else (raw_ifaces[0] if raw_ifaces else None)
        except Exception:
            iface = None

    if iface is None:
        print("No network interface found. Use --list-ifaces to see available interfaces.")
        sys.exit(1)

    if args.filter:
        user_filter = args.filter.strip().lower()
    else:
        user_filter = ""

    analyzer = PacketAnalyzer()

    print("# ==================================================")
    print("CODEALPHA NETWORK SNIFFER")
    print()
    print("## Capture Configuration")
    print(f"Interface: {iface}")
    print(f"Packet limit: {args.count or 'unlimited'}")
    print(f"Filter: {user_filter or 'none'}")
    print()

    # Build Scapy capture params
    capture_kwargs: dict = {"iface": iface, "store": False}
    if args.count:
        capture_kwargs["count"] = args.count
    if args.timeout:
        capture_kwargs["timeout"] = args.timeout

    # scapy BPF filter can be left empty for simple filtering implemented in analyzer
    bpf = ""
    bpf = translate_filter(user_filter)
    if bpf:
        try:
            capture_kwargs["filter"] = bpf
        except Exception:
            # If setting filter fails in this context, show friendly message
            print(f"Warning: could not apply BPF filter '{bpf}' — proceeding without BPF filter.")

    # Handle Ctrl+C gracefully
    stop_sniff = False

    def handle_sigint(signum, frame):
        nonlocal stop_sniff
        stop_sniff = True
        print("\nStopping capture... (graceful)")

    signal.signal(signal.SIGINT, handle_sigint)

    packet_counter = 0

    def _process(pkt):
        nonlocal packet_counter
        packet_counter += 1
        try:
            analyzer.analyze_packet(pkt, packet_counter, user_filter)
        except Exception as e:
            print(f"Error analyzing packet #{packet_counter}: {e}")

    try:
        # Attempt to sniff, handle permission errors
        print("Starting capture... Press Ctrl+C to stop.")
        sniff(prn=_process, **capture_kwargs)
    except PermissionError:
        print("Permission denied: you likely need to run this program with elevated privileges.")
        print("On Linux use: sudo python3 sniffer.py ...")
        sys.exit(2)
    except OSError as e:
        print(f"OS error while trying to capture packets: {e}")
        sys.exit(3)
    except KeyboardInterrupt:
        print("Capture interrupted by user.")

    # Print summary
    print()
    analyzer.print_summary()


if __name__ == "__main__":
    main()
