"""TLS Server Name Indication (SNI) and handshake metadata analyzer."""

from __future__ import annotations

from pathlib import Path

from core.models import TlsRecord
from core.tshark import TSharkRunner
from utils.helpers import (
    first_non_empty,
    format_epoch_timestamp,
    parse_int,
    split_aggregated,
)

TLS_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.dstport",
    "tls.handshake.extensions_server_name",
    "tls.handshake.version",
    "tls.record.version",
]

TLS_VERSION_NAMES: dict[str, str] = {
    "0x0300": "SSL 3.0",
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
}


def _format_tls_version(raw: str) -> str:
    cleaned = raw.strip().lower()
    if not cleaned:
        return ""
    return TLS_VERSION_NAMES.get(cleaned, raw.strip())


def extract_tls_records(
    runner: TSharkRunner,
    pcap_path: str | Path,
    warnings: list[str] | None = None,
) -> tuple[list[TlsRecord], int]:
    """Extract TLS SNI hostnames and handshake version metadata.

    HTTPS URL paths and query parameters remain encrypted and are not inferred
    or claimed as plaintext.
    """
    dedup: dict[str, TlsRecord] = {}
    total_sni_events = 0

    for row in runner.stream_fields(
        pcap_path,
        TLS_FIELDS,
        display_filter="tls.handshake.extensions_server_name",
        warnings_out=warnings,
    ):
        frame_num = parse_int(row[0], 0)
        timestamp = format_epoch_timestamp(row[1])
        src_ip = first_non_empty(row[2], row[3])
        dst_ip = first_non_empty(row[4], row[5])
        dst_port = parse_int(row[6], 443)
        sni_values = split_aggregated(row[7])
        hs_versions = [_format_tls_version(v) for v in split_aggregated(row[8])]
        rec_versions = [_format_tls_version(v) for v in split_aggregated(row[9])]

        for sni in sni_values:
            normalized = sni.lower()
            total_sni_events += 1
            rec = dedup.get(normalized)
            if rec is None:
                rec = TlsRecord(sni=sni)
                dedup[normalized] = rec
                rec.count = 0
            rec.count += 1

            for ver in hs_versions:
                if ver and ver not in rec.handshake_versions:
                    rec.handshake_versions.append(ver)
            for ver in rec_versions:
                if ver and ver not in rec.record_versions:
                    rec.record_versions.append(ver)
            if src_ip and src_ip not in rec.src_ips:
                rec.src_ips.append(src_ip)
            if dst_ip and dst_ip not in rec.dst_ips:
                rec.dst_ips.append(dst_ip)
            if dst_port > 0 and dst_port not in rec.dst_ports:
                rec.dst_ports.append(dst_port)
            if frame_num > 0 and frame_num not in rec.packet_numbers:
                rec.packet_numbers.append(frame_num)
            if timestamp and timestamp not in rec.timestamps:
                rec.timestamps.append(timestamp)

    records = sorted(
        dedup.values(),
        key=lambda r: (r.packet_numbers[0] if r.packet_numbers else 0, r.sni),
    )
    return records, total_sni_events
