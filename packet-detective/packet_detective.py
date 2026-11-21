#!/usr/bin/env python3
"""Packet Detective - CLI Network Forensics & CTF Analysis Toolkit."""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    sys.stderr.write(
        f"Error: Packet Detective requires Python 3.11+ (running {sys.version.split()[0]}).\n"
    )
    sys.exit(2)

import argparse
import logging
from pathlib import Path
from typing import Sequence

# Ensure local package imports resolve regardless of current working directory
PACKAGE_ROOT = Path(__file__).resolve().parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from core.analyzer import PacketDetectiveAnalyzer
from core.tshark import CaptureFileError, TSharkError, TSharkNotFoundError
from reporting.console import render_flag_section, render_report_text, supports_color
from reporting.exporters import export_all_reports
from utils.regex_patterns import DEFAULT_FLAG_PREFIX, DEFAULT_MAX_FLAG_LENGTH


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packet_detective.py",
        description="Packet Detective: Offline PCAP/PCAPNG Network Forensics & HTH3 Flag Hunting Toolkit",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_cmd = subparsers.add_parser(
        "analyze",
        help="Analyze a PCAP or PCAPNG file for network intelligence, suspicious patterns, and CTF flags.",
    )
    analyze_cmd.add_argument(
        "capture",
        help="Path to the .pcap or .pcapng capture file to analyze.",
    )
    analyze_cmd.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Directory to write report.txt, report.json, urls.csv, domains.csv, flags.txt, and extracted_objects/.",
    )
    analyze_cmd.add_argument(
        "--max-flag-length",
        type=int,
        default=DEFAULT_MAX_FLAG_LENGTH,
        help=f"Maximum flag body length inside braces (default: {DEFAULT_MAX_FLAG_LENGTH}).",
    )
    analyze_cmd.add_argument(
        "--flag-prefix",
        type=str,
        default=DEFAULT_FLAG_PREFIX,
        help=f"Case-insensitive flag prefix to search for (default: {DEFAULT_FLAG_PREFIX}).",
    )
    analyze_cmd.add_argument(
        "--tshark-path",
        type=str,
        default=None,
        help="Optional explicit path to the tshark binary.",
    )
    analyze_cmd.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Timeout in seconds for individual TShark operations (default: 300).",
    )
    analyze_cmd.add_argument(
        "--flags-only",
        action="store_true",
        help="Print only the dedicated Flag Intelligence section to stdout (all exports still include full data).",
    )
    analyze_cmd.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in terminal output.",
    )
    analyze_cmd.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose diagnostic logging to stderr.",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="[%(levelname)s] %(name)s: %(message)s",
    )

    if args.command == "analyze":
        if args.max_flag_length < 1:
            sys.stderr.write("Error: --max-flag-length must be >= 1.\n")
            return 2

        try:
            analyzer = PacketDetectiveAnalyzer(
                tshark_path=args.tshark_path,
                max_flag_length=args.max_flag_length,
                flag_prefix=args.flag_prefix,
                timeout=args.timeout,
            )
            report = analyzer.analyze(args.capture, output_dir=args.output)
        except TSharkNotFoundError as exc:
            sys.stderr.write(f"Error: {exc}\n")
            return 3
        except CaptureFileError as exc:
            sys.stderr.write(f"Error: {exc}\n")
            return 4
        except TSharkError as exc:
            sys.stderr.write(f"TShark error: {exc}\n")
            return 5
        except ValueError as exc:
            sys.stderr.write(f"Configuration error: {exc}\n")
            return 2

        use_color = supports_color(sys.stdout, no_color=args.no_color)
        if args.flags_only:
            print(render_flag_section(report, use_color=use_color))
        else:
            print(render_report_text(report, use_color=use_color))

        if args.output is not None:
            exported = export_all_reports(report, args.output)
            print("\n[+] Reports exported:")
            for label, path in exported.items():
                print(f"    - {label}: {path}")

        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
