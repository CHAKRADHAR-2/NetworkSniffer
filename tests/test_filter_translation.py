from __future__ import annotations

import sys
from pathlib import Path

# Make project importable
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sniffer import translate_filter


def test_translate_tcp():
    assert translate_filter("tcp") == "tcp"


def test_translate_udp():
    assert translate_filter("udp") == "udp"


def test_translate_icmp():
    assert translate_filter("icmp") == "icmp"


def test_translate_arp():
    assert translate_filter("arp") == "arp"


def test_translate_dns():
    assert "port 53" in translate_filter("dns")


def test_translate_host():
    assert translate_filter("host=127.0.0.1") == "host 127.0.0.1"


def test_translate_host_invalid():
    import pytest

    with pytest.raises(ValueError):
        translate_filter("host=not_an_ip")
