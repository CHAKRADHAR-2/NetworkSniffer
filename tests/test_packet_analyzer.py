"""Basic tests for packet analysis logic using constructed Scapy packets."""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is on sys.path for imports when running tests
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from packet_analyzer import PacketAnalyzer
from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, DNS, DNSQR, Raw


def test_tcp_packet_identification():
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"GET / HTTP/1.1")
    analyzer = PacketAnalyzer()
    info = analyzer.get_packet_info(pkt, 1)
    assert info["protocol"] == "TCP"
    assert info["sport"] == 12345
    assert info["dport"] == 80
    assert info["src"] == "10.0.0.1"
    assert info["dst"] == "10.0.0.2"


def test_udp_packet_identification():
    pkt = Ether() / IP(src="192.168.0.5", dst="8.8.8.8") / UDP(sport=5555, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
    analyzer = PacketAnalyzer()
    info = analyzer.get_packet_info(pkt, 2)
    assert info["protocol"] in ("UDP", "DNS")
    assert info["sport"] == 5555
    assert info["dport"] == 53


def test_icmp_and_arp():
    icmp_pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / ICMP()
    arp_pkt = Ether() / ARP(psrc="10.0.0.2", pdst="10.0.0.3")
    analyzer = PacketAnalyzer()
    info1 = analyzer.get_packet_info(icmp_pkt, 3)
    info2 = analyzer.get_packet_info(arp_pkt, 4)
    assert info1["protocol"] == "ICMP"
    assert info2["protocol"] == "ARP"
