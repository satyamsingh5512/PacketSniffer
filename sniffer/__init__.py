"""PacketSniffer package.

A standard-library-only network packet analyzer. This package exposes the five
public domain classes that make up the application:

- ``PacketRecord``  -- the decoded-packet data model (``sniffer.models``)
- ``PacketDecoder`` -- the stateless L2/L3/L4 header decoder (``sniffer.decoder``)
- ``TrafficStats``  -- rolling traffic statistics (``sniffer.stats``)
- ``OutputHandler`` -- console/NDJSON/CSV output (``sniffer.output``)
- ``PacketSniffer``  -- the raw-socket capture loop (``sniffer.capture``)

The implementation targets Python 3.8+ and imports only Stdlib modules; no
third-party packages are used anywhere in this package.
"""

from .models import PacketRecord
from .decoder import PacketDecoder
from .stats import TrafficStats
from .output import OutputHandler
from .capture import PacketSniffer

__all__ = [
    "PacketRecord",
    "PacketDecoder",
    "TrafficStats",
    "OutputHandler",
    "PacketSniffer",
]
