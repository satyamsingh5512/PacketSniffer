"""PacketSniffer CLI entrypoint.

Usage:
    sudo python main.py [-i INTERFACE] [-p PROTOCOL] [-n COUNT]
                        [-o OUTPUT] [-f FORMAT] [-v] [--stats-interval N]
"""

import argparse
import os
import sys

from sniffer import OutputHandler, PacketSniffer


def build_parser() -> argparse.ArgumentParser:
    """Return the configured argument parser (Requirements 13.1–13.7)."""
    p = argparse.ArgumentParser(
        prog="packetsniffer",
        description="Raw-socket network packet analyzer (stdlib only, no Scapy).",
    )
    p.add_argument("-i", "--interface", default="0.0.0.0",
                   help="Bind interface (default: 0.0.0.0)")
    p.add_argument("-p", "--protocol", default="all",
                   choices=["all", "tcp", "udp", "icmp"],
                   help="Protocol filter (default: all)")
    p.add_argument("-n", "--count", type=int, default=0,
                   help="Packets to capture; 0 = unbounded (default: 0)")
    p.add_argument("-o", "--output", default=None,
                   help="Output file path (for json/csv formats)")
    p.add_argument("-f", "--format", default="console",
                   choices=["console", "json", "csv"],
                   help="Output format (default: console)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Capture raw payload (first 64 bytes)")
    p.add_argument("--stats-interval", type=int, default=50,
                   help="Print stats every N retained packets (default: 50)")
    return p


def main() -> None:
    args = build_parser().parse_args()

    # Startup banner (Requirement 13.8)
    print(
        f"[PacketSniffer] interface={args.interface} protocol={args.protocol} "
        f"format={args.format} pid={os.getpid()}"
    )

    output = OutputHandler(output_file=args.output, format=args.format)

    try:
        sniffer = PacketSniffer(
            interface=args.interface,
            protocol=args.protocol,
            verbose=args.verbose,
            count=args.count,
        )
    except (PermissionError, OSError) as exc:
        print(f"[error] Cannot open raw socket: {exc}", file=sys.stderr)
        print("[error] Raw sockets require root; rerun with sudo.", file=sys.stderr)
        sys.exit(1)

    retained = [0]

    def callback(record):
        output.write(record)
        retained[0] += 1
        if args.stats_interval > 0 and retained[0] % args.stats_interval == 0:
            print(sniffer.get_stats().summary())

    try:
        sniffer.start(callback)
    except KeyboardInterrupt:
        pass
    finally:
        # Print final stats on exit (Requirement 13.9)
        print("\n" + sniffer.get_stats().summary())
        sniffer.stop()
        output.close()


if __name__ == "__main__":
    main()
