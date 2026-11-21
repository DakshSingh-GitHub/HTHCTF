"""DNS query and domain resolution analyzer."""

from __future__ import annotations

from pathlib import Path

from core.models import DnsRecord
from core.tshark import TSharkRunner
from utils.helpers import (
    first_non_empty,
    format_epoch_timestamp,
    is_truthy_field,
    parse_int,
    split_aggregated,
)

DNS_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "udp.srcport",
    "udp.dstport",
    "tcp.srcport",
    "tcp.dstport",
    "dns.flags.response",
    "dns.qry.name",
    "dns.qry.type",
    "dns.a",
    "dns.aaaa",
    "dns.cname",
    "dns.txt",
    "dns.flags.rcode",
    "frame.protocols",
]

DNS_QTYPE_NAMES: dict[str, str] = {
    "1": "A",
    "2": "NS",
    "5": "CNAME",
    "6": "SOA",
    "12": "PTR",
    "15": "MX",
    "16": "TXT",
    "28": "AAAA",
    "33": "SRV",
    "65": "HTTPS",
    "255": "ANY",
}


def _normalize_qtype(raw_qtype: str) -> str:
    cleaned = raw_qtype.strip()
    return DNS_QTYPE_NAMES.get(cleaned, cleaned)


def extract_dns_records(
    runner: TSharkRunner,
    pcap_path: str | Path,
    warnings: list[str] | None = None,
) -> tuple[list[DnsRecord], int]:
    """Extract DNS queries, resolved IPs, CNAMEs, and TXT records.

    Returns ``(deduplicated_records, total_dns_queries)``.
    """
    dedup: dict[str, DnsRecord] = {}
    total_queries = 0

    for row in runner.stream_fields(
        pcap_path,
        DNS_FIELDS,
        display_filter="dns",
        warnings_out=warnings,
    ):
        frame_num = parse_int(row[0], 0)
        timestamp = format_epoch_timestamp(row[1])
        src_ip = first_non_empty(row[2], row[3])
        dst_ip = first_non_empty(row[4], row[5])
        udp_sport = parse_int(row[6], 0)
        udp_dport = parse_int(row[7], 0)
        tcp_sport = parse_int(row[8], 0)
        tcp_dport = parse_int(row[9], 0)
        is_response = is_truthy_field(row[10])
        qry_names = split_aggregated(row[11])
        qry_types = [_normalize_qtype(qt) for qt in split_aggregated(row[12])]
        a_records = split_aggregated(row[13])
        aaaa_records = split_aggregated(row[14])
        cnames = split_aggregated(row[15])
        txt_records = split_aggregated(row[16])
        rcode = row[17].strip()
        protocols_str = row[18].lower()

        if not qry_names:
            continue

        proto_label = "MDNS" if "mdns" in protocols_str else ("DNS/TCP" if tcp_dport or tcp_sport else "DNS/UDP")
        port_candidates = [p for p in (udp_dport, tcp_dport, udp_sport, tcp_sport) if p in {53, 5353}]
        if not port_candidates:
            port_candidates = [p for p in (udp_dport, tcp_dport) if p > 0]

        for domain in qry_names:
            normalized_domain = domain.rstrip(".").lower() or domain
            if not is_response:
                total_queries += 1

            rec = dedup.get(normalized_domain)
            if rec is None:
                rec = DnsRecord(query_name=domain.rstrip(".") or domain)
                dedup[normalized_domain] = rec
                rec.count = 0

            if not is_response:
                rec.count += 1
            elif rec.count == 0:
                rec.count = 1

            for qt in qry_types:
                if qt and qt not in rec.query_types:
                    rec.query_types.append(qt)
            for ip_addr in (*a_records, *aaaa_records):
                if ip_addr and ip_addr not in rec.resolved_ips:
                    rec.resolved_ips.append(ip_addr)
            for cname in cnames:
                if cname and cname not in rec.cname_targets:
                    rec.cname_targets.append(cname)
            for txt in txt_records:
                if txt and txt not in rec.txt_records:
                    rec.txt_records.append(txt)
            if is_response and rcode and rcode not in rec.response_codes:
                rec.response_codes.append(rcode)
            if src_ip and not is_response and src_ip not in rec.src_ips:
                rec.src_ips.append(src_ip)
            if dst_ip and not is_response and dst_ip not in rec.dst_ips:
                rec.dst_ips.append(dst_ip)
            for port in port_candidates:
                if port not in rec.ports:
                    rec.ports.append(port)
            if proto_label not in rec.protocols:
                rec.protocols.append(proto_label)
            if frame_num > 0 and frame_num not in rec.packet_numbers:
                rec.packet_numbers.append(frame_num)
            if timestamp and timestamp not in rec.timestamps:
                rec.timestamps.append(timestamp)

    records = sorted(
        dedup.values(),
        key=lambda r: (r.packet_numbers[0] if r.packet_numbers else 0, r.query_name),
    )
    return records, total_queries
