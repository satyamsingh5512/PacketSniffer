"""Output handler for packet records.

This module provides the :class:`OutputHandler` that writes
:class:`PacketRecord` instances to the console (with ANSI color), an NDJSON
file, or a CSV file.

Standard library only; no third-party dependencies. Python 3.8+ compatible.
"""

import csv
import json
from typing import Optional


class OutputHandler:
    """Writes PacketRecord instances to console, JSON, or CSV (Requirement 12).

    The handler is configured at construction with an output format and an
    optional file path. Console output uses raw ANSI escape codes for color
    (no third-party color library). JSON output writes one NDJSON line per
    record. CSV output writes a header row once, then one row per record.
    """

    # Raw ANSI escape codes for console coloring (Requirement 12.1, 12.2)
    COLORS = {
        "TCP": "\033[36m",    # cyan
        "UDP": "\033[32m",    # green
        "ICMP": "\033[33m",   # yellow
        "OTHER": "\033[37m",  # white
    }
    RESET = "\033[0m"

    def __init__(self, output_file: Optional[str] = None, format: str = "console") -> None:
        """Initialize the output handler.

        Args:
            output_file: Path to output file (used for "json"/"csv" formats).
            format: Output format; one of "console", "json", or "csv".
        """
        self.format = format
        self.output_file = output_file
        self._file = None
        self._csv_writer = None
        self._header_written = False

        # Open output file for json or csv format
        if self.format in ("json", "csv") and self.output_file:
            self._file = open(self.output_file, "w", encoding="utf-8")
            if self.format == "csv":
                self._csv_writer = csv.writer(self._file)

    def write(self, record) -> None:
        """Write a PacketRecord to the configured output.

        Args:
            record: A PacketRecord instance to write.
        """
        if self.format == "console":
            # Console: print with ANSI color (Requirement 12.1, 12.2)
            color = self.COLORS.get(record.protocol, self.COLORS["OTHER"])
            print(f"{color}{record}{self.RESET}")

        elif self.format == "json":
            # JSON: append one NDJSON line (Requirement 12.3)
            if self._file:
                self._file.write(json.dumps(record.to_dict()) + "\n")

        elif self.format == "csv":
            # CSV: write header row once, then one row per record (Requirement 12.4)
            if self._csv_writer:
                if not self._header_written:
                    # Write header row from the record's dictionary keys
                    record_dict = record.to_dict()
                    self._csv_writer.writerow(record_dict.keys())
                    self._header_written = True

                # Write data row
                record_dict = record.to_dict()
                # Convert complex types to strings for CSV
                values = []
                for value in record_dict.values():
                    if isinstance(value, dict):
                        values.append(json.dumps(value))
                    else:
                        values.append(value)
                self._csv_writer.writerow(values)

    def close(self) -> None:
        """Flush and close any open output file (Requirement 12.5)."""
        if self._file:
            self._file.flush()
            self._file.close()
            self._file = None
            self._csv_writer = None
