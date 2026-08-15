from __future__ import annotations

import sys
from pathlib import Path

# Make project importable
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from packet_analyzer import PacketAnalyzer
from scapy.all import Ether, IPv6, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw


def test_ipv6_tcp_packet():
    pkt = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=1234, dport=80) / Raw(b"GET /\r\n")
    analyzer = PacketAnalyzer()
    info = analyzer.get_packet_info(pkt, 1)
    assert info["src"] == "2001:db8::1"
    assert info["dst"] == "2001:db8::2"
    assert info["protocol"] == "TCP"


def test_ipv6_udp_packet():
    pkt = Ether() / IPv6(src="fe80::1", dst="fe80::2") / UDP(sport=5555, dport=53) / DNS(rd=1, qd=DNSQR(qname=b"example.com."))
    analyzer = PacketAnalyzer()
    info = analyzer.get_packet_info(pkt, 2)
    assert info["src"] == "fe80::1"
    assert info["dst"] == "fe80::2"
    # UDP packets with DNS should be identified as UDP by transport-first logic
    assert info["protocol"] in ("UDP", "DNS")
    # DNS qname should be included in payload summary
    assert "example.com" in info["payload_summary"]


def test_binary_payload_summary():
    # Create a packet with mostly non-printable payload
    raw_bytes = bytes(range(0, 200))
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1234, dport=5678) / Raw(raw_bytes)
    analyzer = PacketAnalyzer()
    info = analyzer.get_packet_info(pkt, 3)
    assert info["payload_summary"].startswith("Binary/Encrypted data")


def test_arp_packet():
    pkt = Ether() / ARP(psrc="10.0.0.2", pdst="10.0.0.3")
    analyzer = PacketAnalyzer()
    info = analyzer.get_packet_info(pkt, 4)
    assert info["protocol"] == "ARP"
