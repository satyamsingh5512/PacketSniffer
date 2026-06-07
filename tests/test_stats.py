"""Statistics unit tests — stdlib unittest only (Requirement 15).

No third-party imports; only unittest, collections, json, and sniffer.
"""

import collections
import json
import sys
import os
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sniffer.models import PacketRecord
from sniffer.stats import TrafficStats


def _record(protocol="TCP", src_ip="1.2.3.4", dst_ip="5.6.7.8",
            dst_port=80, src_port=12345):
    """Build a minimal PacketRecord for testing."""
    return PacketRecord(
        timestamp=time.time(),
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        size=60,
        ttl=64,
        src_port=src_port if protocol != "ICMP" else None,
        dst_port=dst_port if protocol != "ICMP" else None,
    )


# 3 TCP + 2 UDP fixture used by multiple tests
def _make_fixture():
    stats = TrafficStats()
    records = [
        _record("TCP", "10.0.0.1", "10.0.0.2", dst_port=80),
        _record("TCP", "10.0.0.1", "10.0.0.3", dst_port=443),
        _record("TCP", "10.0.0.2", "10.0.0.3", dst_port=80),
        _record("UDP", "10.0.0.1", "8.8.8.8",  dst_port=53),
        _record("UDP", "10.0.0.3", "8.8.8.8",  dst_port=53),
    ]
    for r in records:
        stats.update(r)
    return stats, records


# ---------------------------------------------------------------------------
# Property 14: Statistics counting  (Req 11.1)
# ---------------------------------------------------------------------------

class TestProperty14Counting(unittest.TestCase):
    # Feature: packet-sniffer, Property 14: Statistics counting
    def test_property_14_counting(self):
        stats, records = _make_fixture()

        # Model-based: build reference counters independently
        ref_proto = collections.Counter(r.protocol for r in records)
        ref_src   = collections.Counter(r.src_ip for r in records)
        ref_dst   = collections.Counter(r.dst_ip for r in records)
        ref_ports = collections.Counter(r.dst_port for r in records if r.dst_port is not None)

        self.assertEqual(dict(stats.protocols), dict(ref_proto))
        self.assertEqual(dict(stats.sources),   dict(ref_src))
        self.assertEqual(dict(stats.destinations), dict(ref_dst))
        self.assertEqual(dict(stats.ports),     dict(ref_ports))
        self.assertEqual(stats.total, len(records))


# ---------------------------------------------------------------------------
# Property 15: Top-N ranking  (Req 11.2, 11.3)
# ---------------------------------------------------------------------------

class TestProperty15TopN(unittest.TestCase):
    # Feature: packet-sniffer, Property 15: Top-N ranking
    def test_property_15_topn_ranking(self):
        stats, _ = _make_fixture()
        for n in [1, 2, 10]:
            talkers = stats.top_talkers(n)
            ports = stats.top_ports(n)
            self.assertLessEqual(len(talkers), n)
            self.assertLessEqual(len(ports), n)
            # Non-increasing order
            counts_t = [c for _, c in talkers]
            self.assertEqual(counts_t, sorted(counts_t, reverse=True))
            counts_p = [c for _, c in ports]
            self.assertEqual(counts_p, sorted(counts_p, reverse=True))
        # Top source should be 10.0.0.1 with count 3
        self.assertEqual(stats.top_talkers(1)[0], ("10.0.0.1", 3))
        # Top port should be 80 or 53 (both appear twice)
        top_port_val = stats.top_ports(1)[0][1]
        self.assertEqual(top_port_val, 2)


# ---------------------------------------------------------------------------
# Property 16: Summary content  (Req 11.4, 15.4)
# ---------------------------------------------------------------------------

class TestProperty16SummaryContent(unittest.TestCase):
    # Feature: packet-sniffer, Property 16: Summary content
    def test_property_16_summary_content(self):
        stats, _ = _make_fixture()
        summary = stats.summary()
        self.assertTrue(len(summary) > 0)
        self.assertIn("\n", summary)          # multi-line
        self.assertIn("TCP", summary)
        self.assertIn("UDP", summary)


# ---------------------------------------------------------------------------
# Property 17: Statistics serialization  (Req 11.5)
# ---------------------------------------------------------------------------

class TestProperty17Serialization(unittest.TestCase):
    # Feature: packet-sniffer, Property 17: Statistics serialization
    def test_property_17_serialization(self):
        stats, _ = _make_fixture()
        d = stats.to_dict()
        # Must not raise
        json.dumps(d)
        # Keys present
        for key in ("protocols", "sources", "destinations", "ports", "total"):
            self.assertIn(key, d)


# ---------------------------------------------------------------------------
# Requirement 15 required example tests
# ---------------------------------------------------------------------------

class TestReq15Examples(unittest.TestCase):
    """Required example tests from Requirement 15."""

    def test_req15_1_protocol_counting(self):
        """3 TCP + 2 UDP protocol counting (15.1)."""
        stats, _ = _make_fixture()
        self.assertEqual(stats.protocols["TCP"], 3)
        self.assertEqual(stats.protocols["UDP"], 2)

    def test_req15_2_top_talkers_ranking(self):
        """Top talkers ranking (15.2)."""
        stats, _ = _make_fixture()
        talkers = stats.top_talkers(3)
        # 10.0.0.1 sent 3 packets — must be first
        self.assertEqual(talkers[0][0], "10.0.0.1")
        self.assertEqual(talkers[0][1], 3)

    def test_req15_3_top_ports_ranking(self):
        """Top ports ranking (15.3)."""
        stats, _ = _make_fixture()
        ports = stats.top_ports(3)
        # port 80 and 53 each appear twice; port 443 once
        top_two_ports = {p for p, _ in ports[:2]}
        self.assertIn(80, top_two_ports)
        self.assertIn(53, top_two_ports)

    def test_req15_4_summary_non_empty_contains_protocols(self):
        """Summary is non-empty and contains 'TCP' and 'UDP' (15.4)."""
        stats, _ = _make_fixture()
        summary = stats.summary()
        self.assertTrue(len(summary) > 0)
        self.assertIn("TCP", summary)
        self.assertIn("UDP", summary)


if __name__ == "__main__":
    unittest.main()
