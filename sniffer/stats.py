"""Rolling traffic statistics for captured packets.

Defines :class:`TrafficStats`, which accumulates per-protocol counts, source/
destination frequencies, and port histograms across a capture session. All
counters are maintained using ``collections.Counter``, and the class provides
methods to query top talkers, top ports, and a human-readable summary.

Standard library only (Requirement 1); Python 3.8+ compatible.
"""

from collections import Counter
from typing import TYPE_CHECKING

# Avoid circular import: models imports stats in its to_dict, but stats needs
# PacketRecord only for type hints. Use TYPE_CHECKING to restrict the import
# to static analysis time.
if TYPE_CHECKING:
    from .models import PacketRecord


class TrafficStats:
    """Accumulates rolling statistics across a capture session (Requirement 11).

    Maintains four counters: protocols (by name), sources (by src_ip),
    destinations (by dst_ip), and ports (by dst_port). The ``total`` field
    tracks the overall number of packets processed.
    """

    def __init__(self) -> None:
        """Initialize empty counters and zero total."""
        self.protocols: Counter = Counter()
        self.sources: Counter = Counter()
        self.destinations: Counter = Counter()
        self.ports: Counter = Counter()
        self.total: int = 0

    def update(self, record: "PacketRecord") -> None:
        """Increment counters for the given record (Requirement 11.1).

        Increments the protocol counter, source IP counter, destination IP
        counter, and (when dst_port is not None) the destination port counter.
        Also increments the total packet count.

        Args:
            record: The :class:`PacketRecord` to incorporate.
        """
        self.protocols[record.protocol] += 1
        self.sources[record.src_ip] += 1
        self.destinations[record.dst_ip] += 1
        if record.dst_port is not None:
            self.ports[record.dst_port] += 1
        self.total += 1

    def top_talkers(self, n: int = 10) -> list:
        """Return the N source IPs with the highest counts (Requirement 11.2).

        Args:
            n: The number of top talkers to return (default 10).

        Returns:
            A list of (src_ip, count) tuples in descending order of count.
        """
        return self.sources.most_common(n)

    def top_ports(self, n: int = 10) -> list:
        """Return the N destination ports with the highest counts (Requirement 11.3).

        Args:
            n: The number of top ports to return (default 10).

        Returns:
            A list of (dst_port, count) tuples in descending order of count.
        """
        return self.ports.most_common(n)

    def summary(self) -> str:
        """Return a multi-line human-readable summary (Requirement 11.4).

        The summary includes per-protocol counts (for every protocol seen),
        the total packet count, and the top talkers and top ports.

        Returns:
            A multi-line string containing the statistics summary.
        """
        lines = []
        lines.append("=== Traffic Statistics ===")
        lines.append("")
        
        # Per-protocol counts (Requirement 11.4, Property 16)
        lines.append("Protocol Counts:")
        if self.protocols:
            for proto, count in sorted(self.protocols.items()):
                lines.append("  {}: {}".format(proto, count))
        else:
            lines.append("  (none)")
        lines.append("")
        
        # Total packets
        lines.append("Total Packets: {}".format(self.total))
        lines.append("")
        
        # Top talkers (default to 10)
        lines.append("Top Talkers (by source IP):")
        talkers = self.top_talkers(10)
        if talkers:
            for ip, count in talkers:
                lines.append("  {}: {}".format(ip, count))
        else:
            lines.append("  (none)")
        lines.append("")
        
        # Top ports (default to 10)
        lines.append("Top Ports (by destination port):")
        ports = self.top_ports(10)
        if ports:
            for port, count in ports:
                lines.append("  {}: {}".format(port, count))
        else:
            lines.append("  (none)")
        
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Return a JSON-serializable dictionary of all counters (Requirement 11.5).

        Returns:
            A dictionary containing:
            - protocols: dict mapping protocol names to counts
            - sources: dict mapping source IPs to counts
            - destinations: dict mapping destination IPs to counts
            - ports: dict mapping destination ports to counts
            - total: the total packet count
        """
        return {
            "protocols": dict(self.protocols),
            "sources": dict(self.sources),
            "destinations": dict(self.destinations),
            "ports": dict(self.ports),
            "total": self.total,
        }
