"""Stateless packet decoder for the PacketSniffer application.

This module defines the low-level binary parsing layer:

- :class:`IPHeader` -- a ``ctypes.Structure`` describing the 20-byte IPv4
  fixed header, used as a deliberate low-level demonstration in place of
  ``struct.unpack`` for the IP layer.
- :class:`PacketDecoder` -- a stateless collection of ``@staticmethod``
  parsers (and the ``format_mac`` helper) that turn raw byte strings into
  plain dictionaries. The class holds no instance state, so every method is
  a pure function over its input bytes.

Standard library only; no third-party dependencies. Python 3.8+ compatible.
"""

import ctypes
import socket
import struct


class IPHeader(ctypes.Structure):
    """ctypes mapping of the 20-byte fixed IPv4 header.

    ``_pack_ = 1`` disables alignment padding so the structure maps the wire
    bytes one-for-one.

    Bitfield ordering caveat: in the IPv4 wire format byte 0 holds the
    version in the high nibble and the IHL (internet header length) in the
    low nibble. On a little-endian host ctypes allocates bitfields from the
    least-significant bit upward, so ``ihl`` MUST be declared BEFORE
    ``version`` for the structure to map byte 0 correctly. This ordering is
    intentional. Multi-byte fields (``total_length``, ``checksum``, ``src``,
    ``dst``) remain in network byte order on the wire and are converted
    explicitly by the decoder rather than trusting host-order ctypes reads.
    """

    _pack_ = 1
    _fields_ = [
        ("ihl",          ctypes.c_ubyte, 4),
        ("version",      ctypes.c_ubyte, 4),
        ("tos",          ctypes.c_ubyte),
        ("total_length", ctypes.c_ushort),
        ("identifier",   ctypes.c_ushort),
        ("frag_offset",  ctypes.c_ushort),
        ("ttl",          ctypes.c_ubyte),
        ("protocol_num", ctypes.c_ubyte),
        ("checksum",     ctypes.c_ushort),
        ("src",          ctypes.c_uint32),
        ("dst",          ctypes.c_uint32),
    ]


class PacketDecoder:
    """Stateless decoder for Ethernet/IPv4/TCP/UDP/ICMP headers.

    The class holds no instance state; every parsing method is a
    ``@staticmethod`` and behaves as a pure function over its input bytes.
    """

    @staticmethod
    def format_mac(raw: bytes) -> str:
        """Convert raw MAC bytes to an uppercase colon-separated string.

        For the standard six-byte input ``b"\\xAA\\xBB\\xCC\\xDD\\xEE\\xFF"``
        this returns ``"AA:BB:CC:DD:EE:FF"``.
        """
        return ":".join(f"{b:02X}" for b in raw)

    @staticmethod
    def decode_ethernet(data: bytes) -> dict:
        """Decode a 14-byte Ethernet II frame header.

        Returns a dictionary with ``dst_mac``, ``src_mac``, ``ethertype``,
        ``ethertype_name`` and ``payload_offset`` on success. The EtherType is
        mapped to a human-readable name: ``0x0800`` -> ``"IPv4"``,
        ``0x0806`` -> ``"ARP"``, ``0x86DD`` -> ``"IPv6"``, anything else ->
        ``"OTHER"``. ``payload_offset`` is always 14.

        If fewer than 14 bytes are supplied the frame is too short to parse and
        a dictionary containing only an ``"error"`` key is returned instead of
        raising. Any ``struct.error``/``ValueError`` raised during parsing is
        likewise converted to an error dictionary.
        """
        if len(data) < 14:
            return {"error": f"ethernet header too short: {len(data)} bytes"}
        try:
            ethertype = struct.unpack("!H", data[12:14])[0]
            ethertype_name = {
                0x0800: "IPv4",
                0x0806: "ARP",
                0x86DD: "IPv6",
            }.get(ethertype, "OTHER")
            return {
                "dst_mac": PacketDecoder.format_mac(data[0:6]),
                "src_mac": PacketDecoder.format_mac(data[6:12]),
                "ethertype": ethertype,
                "ethertype_name": ethertype_name,
                "payload_offset": 14,
            }
        except (struct.error, ValueError) as exc:
            return {"error": f"ethernet decode failed: {exc}"}

    @staticmethod
    def decode_ip(data: bytes) -> dict:
        """Decode a 20-byte IPv4 header using the ctypes IPHeader structure.

        Returns a dictionary with ``version``, ``ihl``, ``tos``,
        ``total_length``, ``ttl``, ``protocol_num``, ``protocol_name``,
        ``src_ip``, ``dst_ip``, and ``payload_offset`` on success.

        The protocol number is mapped to a human-readable name:
        ``1`` -> ``"ICMP"``, ``6`` -> ``"TCP"``, ``17`` -> ``"UDP"``,
        anything else -> ``"OTHER"``.

        ``payload_offset`` is computed as ``ihl * 4`` (IHL counts 32-bit words).

        IP addresses are rendered as dotted-decimal strings via
        ``socket.inet_ntoa``. Multi-byte fields (``total_length``, IP addresses)
        are read in network byte order and converted explicitly rather than
        trusting host-order ctypes reads.

        If fewer than 20 bytes are supplied the header is too short to parse
        and a dictionary containing only an ``"error"`` key is returned instead
        of raising. Any ``struct.error``/``ValueError`` raised during parsing
        is likewise converted to an error dictionary.
        """
        if len(data) < 20:
            return {"error": f"ip header too short: {len(data)} bytes"}
        try:
            hdr = IPHeader.from_buffer_copy(data[:20])
            protocol_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(
                hdr.protocol_num, "OTHER"
            )
            # Read IP addresses directly from the raw bytes in network byte order
            # (bytes 12-16 for src, 16-20 for dst) rather than using the ctypes
            # structure's src/dst fields which are in host byte order.
            src_ip_int = struct.unpack("!I", data[12:16])[0]
            dst_ip_int = struct.unpack("!I", data[16:20])[0]
            return {
                "version": hdr.version,
                "ihl": hdr.ihl,
                "tos": hdr.tos,
                "total_length": socket.ntohs(hdr.total_length),
                "ttl": hdr.ttl,
                "protocol_num": hdr.protocol_num,
                "protocol_name": protocol_name,
                "src_ip": socket.inet_ntoa(struct.pack("!I", src_ip_int)),
                "dst_ip": socket.inet_ntoa(struct.pack("!I", dst_ip_int)),
                "payload_offset": hdr.ihl * 4,
            }
        except (struct.error, ValueError) as exc:
            return {"error": f"ip decode failed: {exc}"}

    @staticmethod
    def decode_tcp(data: bytes) -> dict:
        """Decode a 20-byte TCP header with control flags.

        Returns a dictionary with ``src_port``, ``dst_port``, ``seq_num``,
        ``ack_num``, ``data_offset``, ``flags``, ``flag_string``,
        ``window_size``, ``checksum``, and ``urgent_ptr`` on success.

        The ``flags`` dictionary contains boolean entries for SYN, ACK, FIN,
        RST, PSH, and URG. Each flag is true if its corresponding control bit
        is set in the header, false otherwise.

        The ``flag_string`` contains only the names of set flags separated by
        single spaces in the fixed order: SYN ACK FIN RST PSH URG.

        ``data_offset`` is computed as ``(offset_byte >> 4) * 4`` where
        offset_byte is the high nibble of byte 12.

        TCP flag bit masks:
        - FIN: 0x01
        - SYN: 0x02
        - RST: 0x04
        - PSH: 0x08
        - ACK: 0x10
        - URG: 0x20

        If fewer than 20 bytes are supplied the header is too short to parse
        and a dictionary containing only an ``"error"`` key is returned instead
        of raising. Any ``struct.error``/``ValueError`` raised during parsing
        is likewise converted to an error dictionary.
        """
        if len(data) < 20:
            return {"error": f"tcp header too short: {len(data)} bytes"}
        try:
            # Unpack the 20-byte TCP header
            # Format: !HHLLBBHHH
            # H = unsigned short (2 bytes) for src_port, dst_port
            # L = unsigned long (4 bytes) for seq_num, ack_num
            # B = unsigned char (1 byte) for offset_byte, flags_byte
            # H = unsigned short (2 bytes) for window_size, checksum, urgent_ptr
            (
                src_port,
                dst_port,
                seq_num,
                ack_num,
                offset_byte,
                flags_byte,
                window_size,
                checksum,
                urgent_ptr,
            ) = struct.unpack("!HHLLBBHHH", data[:20])

            # Compute data_offset from the high nibble of offset_byte
            data_offset = (offset_byte >> 4) * 4

            # Build flags dictionary using bit masks
            flags = {
                "FIN": bool(flags_byte & 0x01),
                "SYN": bool(flags_byte & 0x02),
                "RST": bool(flags_byte & 0x04),
                "PSH": bool(flags_byte & 0x08),
                "ACK": bool(flags_byte & 0x10),
                "URG": bool(flags_byte & 0x20),
            }

            # Build flag_string by joining set flags in fixed order
            flag_order = ["SYN", "ACK", "FIN", "RST", "PSH", "URG"]
            flag_string = " ".join(flag for flag in flag_order if flags[flag])

            return {
                "src_port": src_port,
                "dst_port": dst_port,
                "seq_num": seq_num,
                "ack_num": ack_num,
                "data_offset": data_offset,
                "flags": flags,
                "flag_string": flag_string,
                "window_size": window_size,
                "checksum": checksum,
                "urgent_ptr": urgent_ptr,
            }
        except (struct.error, ValueError) as exc:
            return {"error": f"tcp decode failed: {exc}"}

    @staticmethod
    def decode_udp(data: bytes) -> dict:
        """Decode an 8-byte UDP header.

        Returns a dictionary with ``src_port``, ``dst_port``, ``length``, and
        ``checksum`` on success.

        If fewer than 8 bytes are supplied the header is too short to parse
        and a dictionary containing only an ``"error"`` key is returned instead
        of raising. Any ``struct.error``/``ValueError`` raised during parsing
        is likewise converted to an error dictionary.
        """
        if len(data) < 8:
            return {"error": f"udp header too short: {len(data)} bytes"}
        try:
            # Unpack the 8-byte UDP header
            # Format: !HHHH
            # H = unsigned short (2 bytes) for src_port, dst_port, length, checksum
            src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:8])
            return {
                "src_port": src_port,
                "dst_port": dst_port,
                "length": length,
                "checksum": checksum,
            }
        except (struct.error, ValueError) as exc:
            return {"error": f"udp decode failed: {exc}"}

    @staticmethod
    def decode_icmp(data: bytes) -> dict:
        """Decode a 4-byte ICMP header with human-readable type names.

        Returns a dictionary with ``type``, ``code``, ``checksum``, and
        ``type_name`` on success.

        The ICMP type is mapped to a human-readable name:
        - ``0`` -> ``"Echo Reply"``
        - ``3`` -> ``"Destination Unreachable"``
        - ``8`` -> ``"Echo Request"``
        - ``11`` -> ``"Time Exceeded"``
        - anything else -> ``"Type <n>"``

        If fewer than 4 bytes are supplied the header is too short to parse
        and a dictionary containing only an ``"error"`` key is returned instead
        of raising. Any ``struct.error``/``ValueError`` raised during parsing
        is likewise converted to an error dictionary.
        """
        if len(data) < 4:
            return {"error": f"icmp header too short: {len(data)} bytes"}
        try:
            # Unpack the 4-byte ICMP header
            # Format: !BBH
            # B = unsigned char (1 byte) for type, code
            # H = unsigned short (2 bytes) for checksum
            icmp_type, code, checksum = struct.unpack("!BBH", data[:4])

            # Map ICMP type to human-readable name
            type_name = {
                0: "Echo Reply",
                3: "Destination Unreachable",
                8: "Echo Request",
                11: "Time Exceeded",
            }.get(icmp_type, f"Type {icmp_type}")

            return {
                "type": icmp_type,
                "code": code,
                "checksum": checksum,
                "type_name": type_name,
            }
        except (struct.error, ValueError) as exc:
            return {"error": f"icmp decode failed: {exc}"}
