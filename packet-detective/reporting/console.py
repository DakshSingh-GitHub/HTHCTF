"""Terminal and plain-text report formatting for Packet Detective."""

from __future__ import annotations

import os
import sys
from typing import TextIO

from core.models import AnalysisReport
from utils.helpers import format_bytes, format_packet_ranges


class _Palette:
    """ANSI color helper with clean fallback when color is unsupported or disabled."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def magenta(self, text: str) -> str:
        return self._wrap("35", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)


def supports_color(stream: TextIO | None = None, no_color: bool = False) -> bool:
    """Detect whether ANSI terminal colors should be used."""
    if no_color or os.environ.get("NO_COLOR") is not None:
        return False
    target = stream or sys.stdout
    if not hasattr(target, "isatty") or not target.isatty():
        return False
    term = os.environ.get("TERM", "")
    return term.lower() != "dumb"


def render_report_text(report: AnalysisReport, use_color: bool = False, max_items: int = 25) -> str:
    """Render the full forensics report as formatted console or plain text."""
    p = _Palette(use_color)
    lines: list[str] = []
    s = report.summary

    banner = (
        "╔══════════════════════════════════════════════╗\n"
        "║              PACKET DETECTIVE                ║\n"
        "║          Network Forensics Toolkit           ║\n"
        "╚══════════════════════════════════════════════╝"
    )
    lines.append(p.bold(p.cyan(banner)))
    lines.append("")
    lines.append(f"{p.green('[+]')} Capture loaded successfully: {s.file_path} ({format_bytes(s.file_size_bytes)})")
    lines.append(f"{p.green('[+]')} Total packets: {s.total_packets:,}")
    lines.append(f"{p.green('[+]')} Protocols identified: {len(s.protocols)}")
    lines.append(f"{p.green('[+]')} HTTP requests: {s.http_requests_count:,}")
    lines.append(f"{p.green('[+]')} DNS queries: {s.dns_queries_count:,}")
    lines.append(f"{p.green('[+]')} TLS hostnames: {s.tls_hostnames_count:,}")
    lines.append(f"{p.green('[+]')} Unique IP addresses: {s.unique_ip_count:,}")

    if s.warnings:
        lines.append("")
        for warn in s.warnings:
            lines.append(f"{p.yellow('[!]')} Warning: {warn}")

    # [1] URL & DOMAIN INTELLIGENCE
    lines.append("")
    lines.append(p.bold(p.cyan("[1] URL & DOMAIN INTELLIGENCE")))
    lines.append("-" * 50)

    lines.append(p.bold("HTTP Requests:"))
    if not report.http_records:
        lines.append("  No HTTP requests observed.")
    else:
        for rec in report.http_records[:max_items]:
            status_part = f" [status: {', '.join(rec.status_codes)}]" if rec.status_codes else ""
            lines.append(f"  - {rec.method} {rec.full_url}{status_part} (count: {rec.count})")
            lines.append(
                f"    Flow: {rec.src_ip}:{rec.src_port} -> {rec.dst_ip}:{rec.dst_port} ({rec.protocol}) "
                f"| Packets: {format_packet_ranges(rec.packet_numbers)}"
            )
            if rec.host:
                lines.append(f"    Host: {rec.host} | URI: {rec.uri}")
            if rec.query_params:
                lines.append(f"    Query Params: {rec.query_params}")
            if rec.referer:
                lines.append(f"    Referer: {rec.referer}")
            if rec.user_agent:
                lines.append(f"    User-Agent: {rec.user_agent}")
            if rec.timestamps:
                lines.append(f"    Timestamps: {', '.join(rec.timestamps[:3])}")
        if len(report.http_records) > max_items:
            lines.append(f"  ... ({len(report.http_records) - max_items} more HTTP entries in exported reports)")

    lines.append("")
    lines.append(p.bold("DNS Queries & Resolved Domains:"))
    if not report.dns_records:
        lines.append("  No DNS queries observed.")
    else:
        for rec in report.dns_records[:max_items]:
            qtypes = ", ".join(rec.query_types) if rec.query_types else "UNKNOWN"
            resolved = ", ".join(rec.resolved_ips) if rec.resolved_ips else "unresolved"
            lines.append(f"  - {rec.query_name} [{qtypes}] -> {resolved} (queries: {rec.count})")
            extra: list[str] = []
            if rec.cname_targets:
                extra.append(f"CNAME={', '.join(rec.cname_targets)}")
            if rec.txt_records:
                extra.append(f"TXT={', '.join(rec.txt_records[:3])}")
            if rec.src_ips:
                extra.append(f"queried_by={', '.join(rec.src_ips[:3])}")
            if rec.ports:
                extra.append(f"ports={rec.ports}")
            if rec.protocols:
                extra.append(f"proto={'/'.join(rec.protocols)}")
            extra.append(f"packets={format_packet_ranges(rec.packet_numbers[:10])}")
            lines.append(f"    {'; '.join(extra)}")
        if len(report.dns_records) > max_items:
            lines.append(f"  ... ({len(report.dns_records) - max_items} more DNS entries in exported reports)")

    lines.append("")
    lines.append(p.bold("TLS Hostnames (SNI):"))
    lines.append(f"  {p.dim(s.tls_encryption_note)}")
    if not report.tls_records:
        lines.append("  No TLS SNI hostnames observed.")
    else:
        for rec in report.tls_records[:max_items]:
            vers = ", ".join(rec.handshake_versions or rec.record_versions) or "TLS"
            dsts = ", ".join(rec.dst_ips[:3]) or "unknown"
            ports = ", ".join(str(pt) for pt in rec.dst_ports) or "443"
            lines.append(f"  - https://{rec.sni} ({vers}, count: {rec.count})")
            lines.append(
                f"    Server IP(s): {dsts} | Port(s): {ports} | Packets: {format_packet_ranges(rec.packet_numbers[:10])}"
            )
        if len(report.tls_records) > max_items:
            lines.append(f"  ... ({len(report.tls_records) - max_items} more TLS entries in exported reports)")

    # [2] NETWORK INTELLIGENCE
    lines.append("")
    lines.append(p.bold(p.cyan("[2] NETWORK INTELLIGENCE")))
    lines.append("-" * 50)
    net = report.network
    if net.protocol_distribution:
        proto_str = ", ".join(f"{k}: {v}" for k, v in net.protocol_distribution.items())
        lines.append(f"Protocol Distribution: {proto_str}")
    else:
        lines.append("Protocol Distribution: none")

    lines.append("")
    lines.append(p.bold("Top Source IPs:"))
    if not net.top_source_ips:
        lines.append("  None")
    else:
        for stat in net.top_source_ips[:10]:
            lines.append(
                f"  - {stat.ip:<18} sent={stat.packets_sent} pkts ({format_bytes(stat.bytes_sent)}) "
                f"| peers={stat.unique_peers}"
            )

    lines.append("")
    lines.append(p.bold("Top Destination IPs:"))
    if not net.top_destination_ips:
        lines.append("  None")
    else:
        for stat in net.top_destination_ips[:10]:
            lines.append(
                f"  - {stat.ip:<18} recv={stat.packets_received} pkts ({format_bytes(stat.bytes_received)}) "
                f"| peers={stat.unique_peers}"
            )

    if net.top_destination_ports:
        ports_str = ", ".join(f"{port} ({cnt})" for port, cnt in net.top_destination_ports[:10])
        lines.append(f"\nTop Destination Ports: {ports_str}")
    if net.top_source_ports:
        sports_str = ", ".join(f"{port} ({cnt})" for port, cnt in net.top_source_ports[:10])
        lines.append(f"Top Source Ports:      {sports_str}")

    tcp = net.tcp_summary
    lines.append("")
    lines.append(p.bold("TCP / UDP Diagnostics:"))
    lines.append(
        f"  TCP Packets: {tcp.total_tcp_packets:,} | UDP Packets: {tcp.total_udp_packets:,} | "
        f"TCP Streams: {tcp.unique_tcp_streams:,}"
    )
    lines.append(
        f"  SYN: {tcp.syn_packets} | SYN-ACK: {tcp.syn_ack_packets} | "
        f"Retransmissions: {tcp.retransmissions} | Dup ACKs: {tcp.duplicate_acks} | Resets: {tcp.resets}"
    )
    for pat in tcp.unusual_patterns:
        lines.append(f"  {p.yellow('*')} {pat}")

    if net.tcp_conversations:
        lines.append("")
        lines.append(p.bold("Top TCP Conversations:"))
        for conv in net.tcp_conversations[:10]:
            stream_info = f" [stream {conv.stream_id}]" if conv.stream_id is not None else ""
            lines.append(
                f"  - {conv.src_ip}:{conv.src_port} <-> {conv.dst_ip}:{conv.dst_port}{stream_info}: "
                f"{conv.packets} pkts, {format_bytes(conv.bytes)}"
            )

    if net.udp_conversations:
        lines.append("")
        lines.append(p.bold("Top UDP Conversations:"))
        for conv in net.udp_conversations[:10]:
            lines.append(
                f"  - {conv.src_ip}:{conv.src_port} <-> {conv.dst_ip}:{conv.dst_port}: "
                f"{conv.packets} pkts, {format_bytes(conv.bytes)}"
            )

    # [3] SUSPICIOUS TRAFFIC
    lines.append("")
    lines.append(p.bold(p.cyan("[3] SUSPICIOUS TRAFFIC (Heuristic Observations)")))
    lines.append("-" * 50)
    if not report.suspicious_findings:
        lines.append("  No heuristic suspicious traffic indicators triggered.")
    else:
        for idx, finding in enumerate(report.suspicious_findings, start=1):
            sev = finding.severity.upper()
            sev_badge = p.red(f"[{sev}]") if sev == "HIGH" else p.yellow(f"[{sev}]")
            lines.append(f"  {idx}. {sev_badge} {finding.category}: {finding.title}")
            lines.append(f"     {finding.description}")
            if finding.indicators:
                lines.append(f"     Indicators: {', '.join(finding.indicators)}")

    # [4] FILE EXTRACTION
    lines.append("")
    lines.append(p.bold(p.cyan("[4] FILE EXTRACTION")))
    lines.append("-" * 50)
    if not report.extracted_objects:
        lines.append("  No HTTP objects extracted.")
    else:
        for idx, obj in enumerate(report.extracted_objects, start=1):
            pkt_part = f" | Packet: {obj.packet_number}" if obj.packet_number else ""
            lines.append(
                f"  [{idx}] {obj.filename} ({format_bytes(obj.size_bytes)}) | Host: {obj.host}{pkt_part}"
            )
            lines.append(f"      Location: {obj.output_path}")

    # [5] FLAG INTELLIGENCE (DEDICATED SECTION)
    lines.append("")
    lines.append(p.bold(p.magenta("[5] FLAG INTELLIGENCE")))
    lines.append("=" * 50)
    lines.append(render_flag_section(report, use_color=use_color))

    return "\n".join(lines)


def render_flag_section(report: AnalysisReport, use_color: bool = False) -> str:
    """Render the dedicated, standalone Flag Intelligence section."""
    p = _Palette(use_color)
    lines: list[str] = []
    candidates = report.flag_candidates

    lines.append(f"{p.green('[+]')} Flag candidates discovered: {len(candidates)}")
    lines.append("")

    if not candidates:
        lines.append("No matching flag candidates were discovered in the inspectable data.")
        lines.append(
            "Note: Encrypted payloads (such as TLS/HTTPS application data) are not decrypted "
            "and were not inspected as plaintext."
        )
        lines.append("")
        lines.append("=" * 50)
        return "\n".join(lines)

    for idx, cand in enumerate(candidates, start=1):
        lines.append(f"{p.bold(p.green(f'[{idx}]'))} {p.bold(cand.value)}")
        lines.append(f"Source: {cand.source}")
        pkt_label = "Packets" if ("-" in cand.packet_ref or "," in cand.packet_ref) else "Packet"
        lines.append(f"{pkt_label}: {cand.packet_ref}")
        lines.append(f"Confidence: {cand.confidence}")
        if cand.occurrences > 1:
            lines.append(f"Occurrences: {cand.occurrences}")
        if len(cand.sources) > 1:
            lines.append(f"Additional Sources: {', '.join(cand.sources[1:])}")
        if cand.reconstructed:
            lines.append("Detection Method: Reconstructed TCP Stream")
        lines.append("")

    lines.append("=" * 50)
    return "\n".join(lines)
