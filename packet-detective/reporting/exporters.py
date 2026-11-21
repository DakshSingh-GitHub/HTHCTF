"""TXT, CSV, and standalone flag report exporters for Packet Detective."""

from __future__ import annotations

import csv
from pathlib import Path

from core.models import AnalysisReport
from reporting.console import render_flag_section, render_report_text
from reporting.json_report import write_json_report
from utils.helpers import format_packet_ranges


def write_text_report(report: AnalysisReport, destination: Path) -> Path:
    """Write the full human-readable report to a plain-text file."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_report_text(report, use_color=False, max_items=1000) + "\n", encoding="utf-8")
    return destination


def write_flags_report(report: AnalysisReport, destination: Path) -> Path:
    """Write the standalone flag intelligence report to flags.txt."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "PACKET DETECTIVE - FLAG INTELLIGENCE REPORT\n"
        f"Capture: {report.summary.file_path}\n"
        + "=" * 50
        + "\n"
    )
    body = render_flag_section(report, use_color=False)
    destination.write_text(header + body + "\n", encoding="utf-8")
    return destination


def write_urls_csv(report: AnalysisReport, destination: Path) -> Path:
    """Export deduplicated HTTP URL intelligence to CSV."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "method",
        "full_url",
        "host",
        "uri",
        "query_params",
        "referer",
        "user_agent",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "status_codes",
        "count",
        "packets",
        "timestamps",
    ]
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for rec in report.http_records:
            writer.writerow(
                {
                    "method": rec.method,
                    "full_url": rec.full_url,
                    "host": rec.host,
                    "uri": rec.uri,
                    "query_params": str(rec.query_params) if rec.query_params else "",
                    "referer": rec.referer,
                    "user_agent": rec.user_agent,
                    "src_ip": rec.src_ip,
                    "src_port": rec.src_port,
                    "dst_ip": rec.dst_ip,
                    "dst_port": rec.dst_port,
                    "protocol": rec.protocol,
                    "status_codes": ";".join(rec.status_codes),
                    "count": rec.count,
                    "packets": format_packet_ranges(rec.packet_numbers),
                    "timestamps": ";".join(rec.timestamps),
                }
            )
    return destination


def write_domains_csv(report: AnalysisReport, destination: Path) -> Path:
    """Export DNS and TLS SNI domain intelligence to CSV."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "domain",
        "source_type",
        "query_types",
        "resolved_ips",
        "cname_targets",
        "txt_records",
        "src_ips",
        "dst_ips",
        "ports",
        "protocols",
        "count",
        "packets",
        "timestamps",
        "notes",
    ]
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for rec in report.dns_records:
            writer.writerow(
                {
                    "domain": rec.query_name,
                    "source_type": "DNS",
                    "query_types": ";".join(rec.query_types),
                    "resolved_ips": ";".join(rec.resolved_ips),
                    "cname_targets": ";".join(rec.cname_targets),
                    "txt_records": ";".join(rec.txt_records),
                    "src_ips": ";".join(rec.src_ips),
                    "dst_ips": ";".join(rec.dst_ips),
                    "ports": ";".join(str(p) for p in rec.ports),
                    "protocols": ";".join(rec.protocols),
                    "count": rec.count,
                    "packets": format_packet_ranges(rec.packet_numbers),
                    "timestamps": ";".join(rec.timestamps),
                    "notes": "",
                }
            )
        for rec in report.tls_records:
            writer.writerow(
                {
                    "domain": rec.sni,
                    "source_type": "TLS_SNI",
                    "query_types": "",
                    "resolved_ips": ";".join(rec.dst_ips),
                    "cname_targets": "",
                    "txt_records": "",
                    "src_ips": ";".join(rec.src_ips),
                    "dst_ips": ";".join(rec.dst_ips),
                    "ports": ";".join(str(p) for p in rec.dst_ports),
                    "protocols": ";".join(rec.handshake_versions or [rec.protocol]),
                    "count": rec.count,
                    "packets": format_packet_ranges(rec.packet_numbers),
                    "timestamps": ";".join(rec.timestamps),
                    "notes": rec.note,
                }
            )
    return destination


def export_all_reports(report: AnalysisReport, output_dir: Path) -> dict[str, Path]:
    """Export report.txt, report.json, urls.csv, domains.csv, and flags.txt."""
    output_dir.mkdir(parents=True, exist_ok=True)
    extracted_dir = output_dir / "extracted_objects"
    extracted_dir.mkdir(parents=True, exist_ok=True)

    return {
        "report_txt": write_text_report(report, output_dir / "report.txt"),
        "report_json": write_json_report(report, output_dir / "report.json"),
        "urls_csv": write_urls_csv(report, output_dir / "urls.csv"),
        "domains_csv": write_domains_csv(report, output_dir / "domains.csv"),
        "flags_txt": write_flags_report(report, output_dir / "flags.txt"),
        "extracted_objects": extracted_dir,
    }
