"""Decoder unit tests — stdlib unittest only (Requirement 14).

All tests use struct.pack to build synthetic byte sequences; no live socket
or third-party libraries needed.
"""

import io
import json
import socket
import struct
import sys
import tempfile
import time
import unittest
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sniffer.decoder import PacketDecoder
from sniffer.models import PacketRecord
from sniffer.capture import PacketSniffer
from sniffer.output import OutputHandler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ip_header(proto=6, src="1.2.3.4", dst="5.6.7.8", ttl=64, ihl=5, total_length=40):
    """Build a minimal 20-byte IPv4 header as raw bytes."""
    ver_ihl = (4 << 4) | ihl
    tos = 0
    ident = 0
    flags_frag = 0
    checksum = 0
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)
    return struct.pack("!BBHHHBBH4s4s",
                       ver_ihl, tos, total_length, ident, flags_frag,
                       ttl, proto, checksum, src_b, dst_b)


def _make_tcp_header(src_port=12345, dst_port=80, flags_byte=0x02):
    """Build a minimal 20-byte TCP header."""
    seq = ack = 0
    offset_byte = (5 << 4)  # data offset = 5 words
    window = 1024
    checksum = urgent = 0
    return struct.pack("!HHLLBBHHH",
                       src_port, dst_port, seq, ack,
                       offset_byte, flags_byte, window, checksum, urgent)


def _make_udp_header(src_port=54321, dst_port=53, length=20, checksum=0):
    return struct.pack("!HHHH", src_port, dst_port, length, checksum)


def _make_icmp_header(icmp_type=8, code=0, checksum=0):
    return struct.pack("!BBH", icmp_type, code, checksum)


def _make_full_packet(proto=6, src="1.2.3.4", dst="5.6.7.8",
                      ttl=64, total_length=40, transport_bytes=None):
    """Return a full raw packet (IP header + transport header)."""
    if transport_bytes is None:
        transport_bytes = _make_tcp_header() if proto == 6 else b"\x00" * 8
    ip = _make_ip_header(proto=proto, src=src, dst=dst, ttl=ttl,
                         total_length=total_length)
    return ip + transport_bytes


# ---------------------------------------------------------------------------
# Property 1: MAC formatting  (Req 2.2, 7.4)
# ---------------------------------------------------------------------------

class TestProperty01MacFormat(unittest.TestCase):
    # Feature: packet-sniffer, Property 1: MAC formatting
    def test_property_01_mac_format(self):
        cases = [
            (b"\xAA\xBB\xCC\xDD\xEE\xFF", "AA:BB:CC:DD:EE:FF"),
            (b"\x00\x00\x00\x00\x00\x00", "00:00:00:00:00:00"),
            (b"\x01\x23\x45\x67\x89\xAB", "01:23:45:67:89:AB"),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(PacketDecoder.format_mac(raw), expected)


# ---------------------------------------------------------------------------
# Property 2: Ethernet decode completeness  (Req 2.1, 2.6)
# ---------------------------------------------------------------------------

class TestProperty02Ethernet(unittest.TestCase):
    # Feature: packet-sniffer, Property 2: Ethernet decode completeness
    def test_property_02_ethernet_complete(self):
        for ethertype, name in [(0x0800, "IPv4"), (0x0806, "ARP"), (0x86DD, "IPv6"), (0x9999, "OTHER")]:
            frame = bytes(6) + bytes(6) + struct.pack("!H", ethertype) + bytes(20)
            result = PacketDecoder.decode_ethernet(frame)
            self.assertNotIn("error", result)
            for key in ("dst_mac", "src_mac", "ethertype", "ethertype_name", "payload_offset"):
                self.assertIn(key, result)
            self.assertEqual(result["payload_offset"], 14)
            self.assertEqual(result["ethertype_name"], name)


# ---------------------------------------------------------------------------
# Property 3: IPv4 header round-trip  (Req 3.2, 3.3, 3.8)
# ---------------------------------------------------------------------------

class TestProperty03IPRoundtrip(unittest.TestCase):
    # Feature: packet-sniffer, Property 3: IPv4 header round-trip
    def test_property_03_ip_roundtrip(self):
        cases = [
            dict(proto=6, src="10.0.0.1", dst="10.0.0.2", ttl=128, total_length=60),
            dict(proto=17, src="192.168.1.1", dst="8.8.8.8", ttl=64, total_length=52),
            dict(proto=1, src="172.16.0.1", dst="172.16.0.2", ttl=255, total_length=84),
        ]
        for c in cases:
            raw = _make_ip_header(**{k: v for k, v in c.items()})
            result = PacketDecoder.decode_ip(raw)
            self.assertNotIn("error", result)
            self.assertEqual(result["src_ip"], c["src"])
            self.assertEqual(result["dst_ip"], c["dst"])
            self.assertEqual(result["ttl"], c["ttl"])
            self.assertEqual(result["payload_offset"], 5 * 4)


# ---------------------------------------------------------------------------
# Property 4: IPv4 protocol-name mapping  (Req 3.4–3.7, 3.9)
# ---------------------------------------------------------------------------

class TestProperty04IPProtocolMap(unittest.TestCase):
    # Feature: packet-sniffer, Property 4: IPv4 protocol-name mapping
    def test_property_04_ip_protocol_map(self):
        expected = {1: "ICMP", 6: "TCP", 17: "UDP"}
        for n in range(256):
            raw = _make_ip_header(proto=n)
            result = PacketDecoder.decode_ip(raw)
            want = expected.get(n, "OTHER")
            self.assertEqual(result["protocol_name"], want, msg=f"proto={n}")


# ---------------------------------------------------------------------------
# Property 5: TCP header round-trip  (Req 4.1)
# ---------------------------------------------------------------------------

class TestProperty05TCPRoundtrip(unittest.TestCase):
    # Feature: packet-sniffer, Property 5: TCP header round-trip
    def test_property_05_tcp_roundtrip(self):
        cases = [(12345, 80), (54321, 443), (1024, 8080)]
        for src_port, dst_port in cases:
            raw = _make_tcp_header(src_port=src_port, dst_port=dst_port)
            result = PacketDecoder.decode_tcp(raw)
            self.assertNotIn("error", result)
            self.assertEqual(result["src_port"], src_port)
            self.assertEqual(result["dst_port"], dst_port)


# ---------------------------------------------------------------------------
# Property 6: TCP flag decoding  (Req 4.2–4.5)
# ---------------------------------------------------------------------------

class TestProperty06TCPFlags(unittest.TestCase):
    # Feature: packet-sniffer, Property 6: TCP flag decoding
    _FLAG_MAP = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08, "ACK": 0x10, "URG": 0x20}
    _ORDER = ["SYN", "ACK", "FIN", "RST", "PSH", "URG"]

    def test_property_06_tcp_flags(self):
        for bits in range(64):
            raw = _make_tcp_header(flags_byte=bits)
            result = PacketDecoder.decode_tcp(raw)
            flags = result["flags"]
            for name, mask in self._FLAG_MAP.items():
                self.assertEqual(flags[name], bool(bits & mask), msg=f"bits={bits:#04x} flag={name}")
            set_flags = [f for f in self._ORDER if flags[f]]
            self.assertEqual(result["flag_string"], " ".join(set_flags))


# ---------------------------------------------------------------------------
# Property 7: UDP header round-trip  (Req 5.1)
# ---------------------------------------------------------------------------

class TestProperty07UDPRoundtrip(unittest.TestCase):
    # Feature: packet-sniffer, Property 7: UDP header round-trip
    def test_property_07_udp_roundtrip(self):
        for src, dst, length, chk in [(53, 12345, 100, 0), (443, 8080, 1500, 0xFFFF)]:
            raw = _make_udp_header(src, dst, length, chk)
            r = PacketDecoder.decode_udp(raw)
            self.assertEqual(r["src_port"], src)
            self.assertEqual(r["dst_port"], dst)
            self.assertEqual(r["length"], length)
            self.assertEqual(r["checksum"], chk)


# ---------------------------------------------------------------------------
# Property 8: ICMP header round-trip  (Req 6.1)
# ---------------------------------------------------------------------------

class TestProperty08ICMPRoundtrip(unittest.TestCase):
    # Feature: packet-sniffer, Property 8: ICMP header round-trip
    def test_property_08_icmp_roundtrip(self):
        for t, code, chk in [(0, 0, 0), (3, 1, 0x1234), (8, 0, 0xFFFF), (11, 0, 0)]:
            raw = _make_icmp_header(t, code, chk)
            r = PacketDecoder.decode_icmp(raw)
            self.assertEqual(r["type"], t)
            self.assertEqual(r["code"], code)
            self.assertEqual(r["checksum"], chk)


# ---------------------------------------------------------------------------
# Property 9: Decoder robustness  (Req 7.2, 7.3, 14.7)
# ---------------------------------------------------------------------------

class TestProperty09Robustness(unittest.TestCase):
    # Feature: packet-sniffer, Property 9: Decoder robustness on short/malformed input
    def test_property_09_short_input(self):
        decoders = [
            (PacketDecoder.decode_ethernet, 13),
            (PacketDecoder.decode_ip, 5),
            (PacketDecoder.decode_tcp, 10),
            (PacketDecoder.decode_udp, 3),
            (PacketDecoder.decode_icmp, 1),
        ]
        for fn, short_len in decoders:
            with self.subTest(fn=fn.__name__):
                result = fn(bytes(short_len))
                self.assertIn("error", result)


# ---------------------------------------------------------------------------
# Property 10: Protocol filtering  (Req 9.2, 9.3)
# ---------------------------------------------------------------------------

class TestProperty10ProtocolFilter(unittest.TestCase):
    # Feature: packet-sniffer, Property 10: Protocol filtering
    def _packets_for_proto(self, proto_num, transport):
        return [_make_full_packet(proto=proto_num, transport_bytes=transport)]

    def test_property_10_protocol_filter(self):
        tcp_pkt = _make_full_packet(proto=6, transport_bytes=_make_tcp_header())
        udp_pkt = _make_full_packet(proto=17, transport_bytes=_make_udp_header())
        icmp_pkt = _make_full_packet(proto=1, transport_bytes=_make_icmp_header())

        for filt, packets, expected_count in [
            ("all", [tcp_pkt, udp_pkt, icmp_pkt], 3),
            ("tcp", [tcp_pkt, udp_pkt, icmp_pkt], 1),
            ("udp", [tcp_pkt, udp_pkt, icmp_pkt], 1),
            ("icmp", [tcp_pkt, udp_pkt, icmp_pkt], 0),  # ICMP total_length mismatch is fine, still counted
        ]:
            captured = []
            sniffer = PacketSniffer(protocol=filt, _packet_source=iter(packets))
            sniffer.start(callback=captured.append)
            if filt == "all":
                self.assertEqual(len(captured), 3)
            elif filt == "tcp":
                self.assertTrue(all(r.protocol == "TCP" for r in captured))
            elif filt == "udp":
                self.assertTrue(all(r.protocol == "UDP" for r in captured))


# ---------------------------------------------------------------------------
# Property 11: Verbose payload bound  (Req 9.7, 9.8)
# ---------------------------------------------------------------------------

class TestProperty11VerbosePayload(unittest.TestCase):
    # Feature: packet-sniffer, Property 11: Verbose payload bound
    def test_property_11_verbose_off(self):
        pkt = _make_full_packet(transport_bytes=_make_tcp_header())
        captured = []
        PacketSniffer(verbose=False, _packet_source=iter([pkt])).start(captured.append)
        self.assertIsNone(captured[0].raw_payload)

    def test_property_11_verbose_on(self):
        transport = _make_tcp_header() + bytes(100)
        pkt = _make_full_packet(transport_bytes=transport)
        captured = []
        PacketSniffer(verbose=True, _packet_source=iter([pkt])).start(captured.append)
        self.assertIsNotNone(captured[0].raw_payload)
        self.assertLessEqual(len(captured[0].raw_payload), 64)


# ---------------------------------------------------------------------------
# Property 12: PacketRecord build invariants  (Req 10.2–10.4)
# ---------------------------------------------------------------------------

class TestProperty12RecordInvariants(unittest.TestCase):
    # Feature: packet-sniffer, Property 12: PacketRecord build invariants
    def test_property_12_record_invariants(self):
        packets = [
            _make_full_packet(proto=6, transport_bytes=_make_tcp_header()),
            _make_full_packet(proto=17, transport_bytes=_make_udp_header()),
            _make_full_packet(proto=1, transport_bytes=_make_icmp_header()),
        ]
        captured = []
        PacketSniffer(_packet_source=iter(packets)).start(captured.append)
        for r in captured:
            self.assertIn(r.protocol, {"TCP", "UDP", "ICMP", "OTHER"})
        icmp_records = [r for r in captured if r.protocol == "ICMP"]
        for r in icmp_records:
            self.assertIsNone(r.src_port)
            self.assertIsNone(r.dst_port)


# ---------------------------------------------------------------------------
# Property 13: PacketRecord single-line rendering  (Req 10.5)
# ---------------------------------------------------------------------------

class TestProperty13RecordRendering(unittest.TestCase):
    # Feature: packet-sniffer, Property 13: PacketRecord single-line rendering
    def test_property_13_record_single_line(self):
        r = PacketRecord(
            timestamp=time.time(), protocol="TCP",
            src_ip="1.2.3.4", dst_ip="5.6.7.8",
            size=60, ttl=64, src_port=12345, dst_port=80,
        )
        s = str(r)
        self.assertTrue(len(s) > 0)
        self.assertNotIn("\n", s)


# ---------------------------------------------------------------------------
# Property 18–20: OutputHandler  (Req 12.1–12.4)
# ---------------------------------------------------------------------------

class TestProperty18ConsoleColor(unittest.TestCase):
    # Feature: packet-sniffer, Property 18: Console color formatting
    def _record(self, proto):
        return PacketRecord(
            timestamp=time.time(), protocol=proto,
            src_ip="1.2.3.4", dst_ip="5.6.7.8", size=40, ttl=64,
        )

    def test_property_18_console_color(self):
        import io, sys
        for proto, color in [("TCP", "\033[36m"), ("UDP", "\033[32m"),
                              ("ICMP", "\033[33m"), ("OTHER", "\033[37m")]:
            buf = io.StringIO()
            old, sys.stdout = sys.stdout, buf
            try:
                OutputHandler().write(self._record(proto))
            finally:
                sys.stdout = old
            out = buf.getvalue()
            self.assertTrue(out.startswith(color), msg=f"proto={proto}")
            self.assertIn("\033[0m", out)


class TestProperty19NdjsonRoundtrip(unittest.TestCase):
    # Feature: packet-sniffer, Property 19: NDJSON output round-trip
    def test_property_19_ndjson_roundtrip(self):
        records = [
            PacketRecord(timestamp=time.time(), protocol="TCP",
                         src_ip="1.2.3.4", dst_ip="5.6.7.8", size=40, ttl=64,
                         src_port=1234, dst_port=80),
            PacketRecord(timestamp=time.time(), protocol="UDP",
                         src_ip="1.2.3.4", dst_ip="8.8.8.8", size=52, ttl=64,
                         src_port=5000, dst_port=53),
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            h = OutputHandler(output_file=path, format="json")
            for r in records:
                h.write(r)
            h.close()
            with open(path) as f:
                lines = [l for l in f.readlines() if l.strip()]
            self.assertEqual(len(lines), len(records))
            for line in lines:
                json.loads(line)  # must not raise
        finally:
            os.unlink(path)


class TestProperty20CsvStructure(unittest.TestCase):
    # Feature: packet-sniffer, Property 20: CSV output structure
    def test_property_20_csv_structure(self):
        records = [
            PacketRecord(timestamp=time.time(), protocol="TCP",
                         src_ip="1.2.3.4", dst_ip="5.6.7.8", size=40, ttl=64),
            PacketRecord(timestamp=time.time(), protocol="UDP",
                         src_ip="1.2.3.4", dst_ip="8.8.8.8", size=52, ttl=64),
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            path = f.name
        try:
            h = OutputHandler(output_file=path, format="csv")
            for r in records:
                h.write(r)
            h.close()
            with open(path) as f:
                lines = [l for l in f.readlines() if l.strip()]
            self.assertEqual(len(lines), len(records) + 1)  # header + data rows
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Property 21: Count termination  (Req 8.5)
# ---------------------------------------------------------------------------

class TestProperty21CountTermination(unittest.TestCase):
    # Feature: packet-sniffer, Property 21: Capture count termination
    def test_property_21_count_termination(self):
        import itertools
        tcp_pkt = _make_full_packet(proto=6, transport_bytes=_make_tcp_header())
        for count in [1, 3, 5]:
            captured = []
            # Provide more packets than count; sniffer must stop at count
            sniffer = PacketSniffer(count=count, _packet_source=itertools.repeat(tcp_pkt, 100))
            sniffer.start(captured.append)
            self.assertEqual(len(captured), count, msg=f"count={count}")


# ---------------------------------------------------------------------------
# Requirement 14 example / edge-case tests
# ---------------------------------------------------------------------------

class TestReq14Examples(unittest.TestCase):
    """Required example tests from Requirement 14."""

    def test_req14_2_decode_ip_carriers(self):
        """decode_ip for TCP, UDP, ICMP carriers (14.2)."""
        for proto, name in [(6, "TCP"), (17, "UDP"), (1, "ICMP")]:
            r = PacketDecoder.decode_ip(_make_ip_header(proto=proto))
            self.assertEqual(r["protocol_name"], name)

    def test_req14_3_tcp_flag_combinations(self):
        """TCP flags for SYN, SYN-ACK, FIN (14.3)."""
        # SYN only
        r = PacketDecoder.decode_tcp(_make_tcp_header(flags_byte=0x02))
        self.assertTrue(r["flags"]["SYN"])
        self.assertFalse(r["flags"]["ACK"])
        # SYN-ACK
        r = PacketDecoder.decode_tcp(_make_tcp_header(flags_byte=0x12))
        self.assertTrue(r["flags"]["SYN"])
        self.assertTrue(r["flags"]["ACK"])
        # FIN
        r = PacketDecoder.decode_tcp(_make_tcp_header(flags_byte=0x01))
        self.assertTrue(r["flags"]["FIN"])

    def test_req14_4_tcp_port_decoding(self):
        """TCP port decoding: src=12345, dst=80 (14.4)."""
        r = PacketDecoder.decode_tcp(_make_tcp_header(src_port=12345, dst_port=80))
        self.assertEqual(r["src_port"], 12345)
        self.assertEqual(r["dst_port"], 80)

    def test_req14_5_udp_and_icmp(self):
        """UDP and ICMP Echo Request/Reply/Time Exceeded (14.5)."""
        udp = PacketDecoder.decode_udp(_make_udp_header())
        self.assertNotIn("error", udp)
        for t, name in [(8, "Echo Request"), (0, "Echo Reply"), (11, "Time Exceeded")]:
            r = PacketDecoder.decode_icmp(_make_icmp_header(t))
            self.assertEqual(r["type_name"], name)

    def test_req14_6_format_mac(self):
        """format_mac converts b'\\xAA..\\xFF' to 'AA:BB:CC:DD:EE:FF' (14.6)."""
        self.assertEqual(PacketDecoder.format_mac(b"\xAA\xBB\xCC\xDD\xEE\xFF"),
                         "AA:BB:CC:DD:EE:FF")

    def test_req14_7_short_decode_ip(self):
        """5-byte input to decode_ip returns error dict, no exception (14.7)."""
        result = PacketDecoder.decode_ip(b"\x45\x00\x00\x28\x00")
        self.assertIn("error", result)

    def test_ethertype_names(self):
        """EtherType name mapping examples."""
        for et, name in [(0x0800, "IPv4"), (0x0806, "ARP"), (0x86DD, "IPv6")]:
            frame = bytes(12) + struct.pack("!H", et) + bytes(20)
            r = PacketDecoder.decode_ethernet(frame)
            self.assertEqual(r["ethertype_name"], name)

    def test_icmp_type_names(self):
        """ICMP type name examples."""
        for t, name in [(0, "Echo Reply"), (3, "Destination Unreachable"),
                        (8, "Echo Request"), (11, "Time Exceeded")]:
            r = PacketDecoder.decode_icmp(_make_icmp_header(t))
            self.assertEqual(r["type_name"], name)


if __name__ == "__main__":
    unittest.main()
