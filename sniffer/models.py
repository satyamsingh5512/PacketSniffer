"""Data model for a single decoded packet.

Defines :class:`PacketRecord`, the immutable structure produced by the capture
pipeline for every retained packet. The record is intentionally self-contained:
``__str__`` renders a single-line console view and ``to_dict`` produces a
JSON/CSV-serializable mapping, neither of which imports the decoder (avoids
circular imports).

Standard library only (Requirement 1); Python 3.8+ compatible, so optional
annotations use ``typing.Optional`` rather than the ``X | None`` syntax.
"""

import time
from dataclasses import dataclass
from typing import Optional, Dict


# Fixed display order for TCP flags in the single-line rendering.
_FLAG_ORDER = ("SYN", "ACK", "FIN", "RST", "PSH", "URG")

# Human-readable ICMP type names for the console suffix. Kept local so the
# model stays independent of the decoder module (no circular import).
_ICMP_TYPE_NAMES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    8: "Echo Request",
    11: "Time Exceeded",
}


@dataclass
class PacketRecord:
    """One decoded packet (Requirement 10).

    Fields are ordered so that all non-default fields precede the defaulted
    optional fields, as required by dataclass semantics.
    """

    timestamp: float
    protocol: str                       # constrained to "TCP"/"UDP"/"ICMP"/"OTHER" (Req 10.2)
    src_ip: str
    dst_ip: str
    size: int                           # total IPv4 length (Req 10.4)
    ttl: int
    src_port: Optional[int] = None      # None when no transport ports (Req 10.3)
    dst_port: Optional[int] = None
    flags: Optional[Dict[str, bool]] = None     # TCP only
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    raw_payload: Optional[bytes] = None  # None unless verbose (Reqs 9.7, 9.8)

    def _format_timestamp(self) -> str:
        """Render the epoch timestamp as ``HH:MM:SS.mmm`` (local time)."""
        seconds = int(self.timestamp)
        millis = int(round((self.timestamp - seconds) * 1000))
        # Guard against rounding 999.6ms -> 1000ms rolling into the next second.
        if millis >= 1000:
            seconds += 1
            millis -= 1000
        return time.strftime("%H:%M:%S", time.localtime(seconds)) + ".{:03d}".format(millis)

    def _format_endpoint(self, ip: str, port: Optional[int]) -> str:
        """Render ``ip:port`` when a port is present, otherwise the bare IP."""
        if port is not None:
            return "{}:{}".format(ip, port)
        return ip

    def _protocol_suffix(self) -> str:
        """Build the protocol-specific trailing detail for the console line."""
        if self.protocol == "TCP" and self.flags:
            set_flags = [name for name in _FLAG_ORDER if self.flags.get(name)]
            return "[{}]".format(" ".join(set_flags))
        if self.protocol == "ICMP" and self.icmp_type is not None:
            name = _ICMP_TYPE_NAMES.get(self.icmp_type, "Type {}".format(self.icmp_type))
            if self.icmp_code:
                return "{} (code {})".format(name, self.icmp_code)
            return name
        return ""

    def __str__(self) -> str:
        """Return a single-line console string (Requirement 10.5, Property 13)."""
        src = self._format_endpoint(self.src_ip, self.src_port)
        dst = self._format_endpoint(self.dst_ip, self.dst_port)
        line = "{ts} {proto:<4} {src} -> {dst}   ttl={ttl} size={size}".format(
            ts=self._format_timestamp(),
            proto=self.protocol,
            src=src,
            dst=dst,
            ttl=self.ttl,
            size=self.size,
        )
        suffix = self._protocol_suffix()
        if suffix:
            line = "{} {}".format(line, suffix)
        return line

    def to_dict(self) -> dict:
        """Return a JSON/CSV-serializable mapping of all fields (Req 10, 11.5, 12.3, 12.4)."""
        return {
            "timestamp": self.timestamp,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "size": self.size,
            "ttl": self.ttl,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "flags": self.flags,
            "icmp_type": self.icmp_type,
            "icmp_code": self.icmp_code,
            "raw_payload": self.raw_payload.hex() if self.raw_payload is not None else None,
        }
