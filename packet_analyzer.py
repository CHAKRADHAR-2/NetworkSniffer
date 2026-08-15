"""Packet analysis logic for CodeAlpha Network Sniffer.

Provides functions to extract key metadata and to print a readable summary.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Dict, Optional

from scapy.all import ARP, DNS, Ether, IP, IPv6, Raw, raw

from protocol_utils import identify_protocol, extract_ports


class PacketAnalyzer:
    """Maintain stats and analyze packets."""

    def __init__(self) -> None:
        self.total = 0
        self.counters = Counter()
        self.src_counter = Counter()
        self.dst_counter = Counter()

    def get_packet_info(self, pkt: Any, number: int, user_filter: Optional[str] = None) -> Dict[str, Any]:
        """Extract structured information from a Scapy packet.

        Returns a dict with keys: number, timestamp, src, dst, protocol, sport, dport, length, payload_summary
        """
        info: Dict[str, Any] = {"number": number}
        info["timestamp"] = datetime.fromtimestamp(pkt.time).isoformat()

        # Default values
        info["src"] = None
        info["dst"] = None
        info["protocol"] = identify_protocol(pkt)
        info["sport"], info["dport"] = extract_ports(pkt)

        # IPv4
        try:
            if pkt.haslayer(IP):
                ip = pkt.getlayer(IP)
                info["src"] = ip.src
                info["dst"] = ip.dst
        except Exception:
            pass

        # IPv6
        try:
            if pkt.haslayer(IPv6):
                ip6 = pkt.getlayer(IPv6)
                info["src"] = ip6.src
                info["dst"] = ip6.dst
        except Exception:
            pass

        # ARP fallback (non-IP)
        try:
            if pkt.haslayer(ARP):
                arp = pkt.getlayer(ARP)
                info["src"] = getattr(arp, "psrc", None)
                info["dst"] = getattr(arp, "pdst", None)
        except Exception:
            pass

        # Length
        try:
            info["length"] = len(raw(pkt))
        except Exception:
            info["length"] = None

        # Payload summary
        info["payload_summary"] = self._safe_payload_summary(pkt)

        return info

    def analyze_packet(self, pkt: Any, number: int, user_filter: Optional[str] = None) -> None:
        info = self.get_packet_info(pkt, number, user_filter)

        # Simple filter applied post-capture (in addition to any BPF)
        if user_filter:
            uf = user_filter.lower()
            if uf in ("tcp", "udp", "icmp", "arp"):
                if info["protocol"] is None or info["protocol"].lower() != uf:
                    return
            elif uf == "dns":
                # Accept DNS when DNS layer present or when ports indicate DNS (53)
                sport = info.get("sport")
                dport = info.get("dport")
                if not (pkt.haslayer(DNS) or sport == 53 or dport == 53):
                    return
            elif uf.startswith("host="):
                _, host = uf.split("=", 1)
                if info.get("src") != host and info.get("dst") != host:
                    return

        # Update counters
        self.total += 1
        proto = info.get("protocol", "OTHER")
        self.counters[proto] += 1
        if info.get("src"):
            self.src_counter[info["src"]] += 1
        if info.get("dst"):
            self.dst_counter[info["dst"]] += 1

        # Print nicely
        print("## Captured Packet")
        print(f"Packet number: {info['number']}")
        print(f"Timestamp: {info['timestamp']}")
        print(f"Source: {info.get('src')}")
        print(f"Destination: {info.get('dst')}")
        print(f"Protocol: {info.get('protocol')}")
        print(f"Source Port: {info.get('sport')}")
        print(f"Destination Port: {info.get('dport')}")
        print(f"Length: {info.get('length')}")
        print(f"Payload: {info.get('payload_summary')}")
        print()

    def _safe_payload_summary(self, pkt: Any, max_len: int = 128) -> str:
        """Create a safe, truncated payload summary.

        Avoid printing sensitive keywords. Non-printable bytes are replaced.
        """
        # If DNS layer present, return queried domain(s) in readable form
        try:
            if pkt.haslayer(DNS):
                dns = pkt.getlayer(DNS)
                qnames = []
                if dns.qd:
                    # qd can be a DNSQR or a list
                    try:
                        qd = dns.qd
                        # single query
                        qnames.append(getattr(qd, "qname", b"").decode(errors="ignore").rstrip("."))
                    except Exception:
                        pass
                if qnames:
                    return ", ".join(qnames)
        except Exception:
            pass

        try:
            if pkt.haslayer(Raw):
                b = bytes(pkt.getlayer(Raw).load)
            else:
                # upper payload bytes may be empty for pure headers
                b = raw(pkt.payload)
        except Exception:
            try:
                b = raw(pkt)
            except Exception:
                return "None"

        if not b:
            return "None"

        # Truncate but inspect printability
        n = len(b)
        head = b[:max_len]
        # Heuristic: consider printable if most bytes are in printable ASCII range
        printable = sum(1 for c in head if 32 <= c <= 126)
        ratio = printable / max(1, len(head))
        if ratio > 0.8:
            try:
                s = head.decode("utf-8", errors="replace")
            except Exception:
                s = str(head)
            safe = "".join((c if 32 <= ord(c) <= 126 else ".") for c in s)
            if n > max_len:
                safe = safe + "..."
            return safe
        # Non-printable -> show readable summary
        return f"Binary/Encrypted data ({n} bytes)"

    def print_summary(self) -> None:
        print("# ==================================================")
        print("Capture Summary")
        print(f"Total packets captured: {self.total}")
        print(f"TCP: {self.counters.get('TCP', 0)}")
        print(f"UDP: {self.counters.get('UDP', 0)}")
        print(f"ICMP: {self.counters.get('ICMP', 0)}")
        print(f"ARP: {self.counters.get('ARP', 0)}")
        other_count = sum(v for k, v in self.counters.items() if k not in ("TCP", "UDP", "ICMP", "ARP"))
        print(f"Other/Unknown: {other_count}")

        print("Top source IPs:")
        for ip, c in self.src_counter.most_common(5):
            print(f" - {ip}: {c}")

        print("Top destination IPs:")
        for ip, c in self.dst_counter.most_common(5):
            print(f" - {ip}: {c}")
