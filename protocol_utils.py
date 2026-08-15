"""Protocol identification utilities for CodeAlpha sniffer.

Inspect Scapy packet layers to determine protocol and extract fields.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

from scapy.all import ARP, DNS, ICMP, TCP, UDP


def identify_protocol(pkt) -> str:
    """Identify protocol by inspecting Scapy layers.

    Returns a short protocol name (e.g., 'TCP', 'UDP', 'ICMP', 'ARP', 'DNS', 'OTHER').
    """
    try:
        if pkt.haslayer(ARP):
            return "ARP"
        # Prefer transport-layer identification first (TCP/UDP/ICMP)
        if pkt.haslayer(TCP):
            return "TCP"
        if pkt.haslayer(UDP):
            return "UDP"
        if pkt.haslayer(ICMP):
            return "ICMP"
        # Application-layer protocols (DNS) as fallback
        if pkt.haslayer(DNS):
            return "DNS"
    except Exception:
        pass
    return "OTHER"


def extract_ports(pkt) -> Tuple[Optional[int], Optional[int]]:
    """Return (sport, dport) when available.

    If ports aren't applicable (e.g., ARP), returns (None, None).
    """
    try:
        if pkt.haslayer(TCP):
            layer = pkt.getlayer(TCP)
            return int(layer.sport), int(layer.dport)
        if pkt.haslayer(UDP):
            layer = pkt.getlayer(UDP)
            return int(layer.sport), int(layer.dport)
    except Exception:
        pass
    return None, None
