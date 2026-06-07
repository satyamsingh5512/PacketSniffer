"""Raw socket capture loop for the PacketSniffer application.

Defines :class:`PacketSniffer`, which owns a raw socket, runs the packet
capture loop, applies protocol filtering, and dispatches :class:`PacketRecord`
instances to a caller-supplied callback (or prints them).

Standard library only; Python 3.8+ compatible.
"""

import socket
import struct
import sys
import time
from typing import Callable, Optional

from .decoder import PacketDecoder
from .models import PacketRecord
from .stats import TrafficStats


class PacketSniffer:
    """Raw-socket capture loop with filtering and dispatch (Requirement 8, 9)."""

    def __init__(
        self,
        interface: str = "0.0.0.0",
        protocol: str = "all",
        verbose: bool = False,
        count: int = 0,
        _packet_source=None,  # injectable for tests (iterable of raw bytes)
    ) -> None:
        self.interface = interface
        self.protocol = protocol.lower()
        self.verbose = verbose
        self.count = count  # 0 = unbounded
        self._packet_source = _packet_source  # None means use live socket
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._retained = 0
        self._link_layer = False  # set True when using AF_PACKET (Linux)
        self._stats = TrafficStats()

    # ------------------------------------------------------------------
    # Socket creation
    # ------------------------------------------------------------------

    def _create_socket(self) -> socket.socket:
        """Create and configure the capture socket.

        On Linux, ``AF_INET``/``SOCK_RAW`` with ``IPPROTO_IP`` is not a valid
        *receiving* socket (the kernel returns "Protocol not supported"), and
        ``IPPROTO_RAW`` is send-only. To reliably observe every IP protocol
        (TCP/UDP/ICMP) we use an ``AF_PACKET`` socket bound to ``ETH_P_ALL``,
        which delivers complete link-layer (Ethernet) frames. The 14-byte
        Ethernet header is stripped in ``_live_source`` so the rest of the
        pipeline continues to operate on IP packets.

        On non-Linux platforms we fall back to an ``AF_INET`` raw socket.
        """
        if sys.platform.startswith("linux"):
            # ETH_P_ALL = 0x0003 — receive every protocol at the link layer.
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.ntohs(0x0003))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            self._link_layer = True
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.IPPROTO_IP)
            sock.bind((self.interface, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self._link_layer = False
        return sock

    # ------------------------------------------------------------------
    # Packet processing
    # ------------------------------------------------------------------

    def _process(self, raw: bytes) -> Optional[PacketRecord]:
        """Decode raw bytes into a PacketRecord; return None on failure."""
        ip = PacketDecoder.decode_ip(raw)
        if "error" in ip:
            return None

        proto_name = ip["protocol_name"]   # TCP / UDP / ICMP / OTHER
        ip_payload_offset = ip["payload_offset"]
        transport = raw[ip_payload_offset:]

        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        flags = None
        icmp_type: Optional[int] = None
        icmp_code: Optional[int] = None

        if proto_name == "TCP":
            tcp = PacketDecoder.decode_tcp(transport)
            if "error" not in tcp:
                src_port = tcp["src_port"]
                dst_port = tcp["dst_port"]
                flags = tcp["flags"]
        elif proto_name == "UDP":
            udp = PacketDecoder.decode_udp(transport)
            if "error" not in udp:
                src_port = udp["src_port"]
                dst_port = udp["dst_port"]
        elif proto_name == "ICMP":
            icmp = PacketDecoder.decode_icmp(transport)
            if "error" not in icmp:
                icmp_type = icmp["type"]
                icmp_code = icmp["code"]

        raw_payload: Optional[bytes] = None
        if self.verbose:
            raw_payload = raw[ip_payload_offset: ip_payload_offset + 64]

        return PacketRecord(
            timestamp=time.time(),
            protocol=proto_name,
            src_ip=ip["src_ip"],
            dst_ip=ip["dst_ip"],
            size=ip["total_length"],
            ttl=ip["ttl"],
            src_port=src_port,
            dst_port=dst_port,
            flags=flags,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            raw_payload=raw_payload,
        )

    # ------------------------------------------------------------------
    # Capture loop
    # ------------------------------------------------------------------

    def start(self, callback: Optional[Callable[[PacketRecord], None]] = None) -> None:
        """Run the capture loop (Requirements 9.1–9.8).

        Packets are read either from the live socket or from the injected
        ``_packet_source`` (an iterable of raw ``bytes`` objects, used in
        tests to avoid requiring a live socket or root privileges).
        """
        self._running = True
        self._retained = 0

        if self._packet_source is None:
            self._sock = self._create_socket()

        try:
            source = self._live_source() if self._packet_source is None else self._packet_source
            for raw in source:
                if not self._running:
                    break
                try:
                    record = self._process(raw)
                    if record is None:
                        continue

                    # Protocol filtering (Requirement 9.2, 9.3)
                    if self.protocol != "all" and record.protocol.lower() != self.protocol:
                        continue

                    # Dispatch (Requirement 9.4, 9.5)
                    self._stats.update(record)
                    self._retained += 1
                    if callback is not None:
                        callback(record)
                    else:
                        print(record)

                    # Count termination (Requirement 8.5)
                    if self.count > 0 and self._retained >= self.count:
                        break

                except (struct.error, ValueError, OSError):
                    continue  # Requirement 9.6
        finally:
            if self._sock is not None:
                self._sock.close()
                self._sock = None

    def _live_source(self):
        """Yield raw IP packet bytes from the live socket indefinitely.

        When using an ``AF_PACKET`` socket (Linux), each received frame
        includes a 14-byte Ethernet header. Non-IPv4 frames (EtherType !=
        0x0800) are skipped, and the Ethernet header is stripped so the rest
        of the pipeline receives IP packets starting at the IP header.
        """
        while self._running:
            try:
                raw, _ = self._sock.recvfrom(65535)
            except OSError:
                break
            if self._link_layer:
                if len(raw) < 14:
                    continue
                ethertype = (raw[12] << 8) | raw[13]
                if ethertype != 0x0800:  # only IPv4
                    continue
                raw = raw[14:]
            yield raw

    def stop(self) -> None:
        """Stop the capture loop and close the socket (Requirement 8.6)."""
        self._running = False
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def get_stats(self) -> TrafficStats:
        """Return the accumulated traffic statistics."""
        return self._stats
