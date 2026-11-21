"""Heuristic suspicious network traffic detector."""

from __future__ import annotations

from collections import Counter
from ipaddress import ip_address

from core.models import DnsRecord, SuspiciousFinding
from modules.ip_analyzer import NetworkTelemetry
from utils.helpers import format_bytes, format_packet_ranges

SUSPICIOUS_DNS_LABEL_LEN = 40
SUSPICIOUS_DNS_FQDN_LEN = 80
PORT_SCAN_UNIQUE_PORTS_THRESHOLD = 10
FREQUENT_DST_RATIO_THRESHOLD = 0.50
FREQUENT_DST_MIN_PACKETS = 50
HIGH_OUTBOUND_BYTES_THRESHOLD = 1_000_000
UNEXPECTED_PORT_ALLOWLIST = {20, 21, 22, 25, 53, 67, 68, 80, 123, 143, 443, 465, 587, 993, 995, 5353, 8080, 8443}


def _is_private_or_local(ip_str: str) -> bool:
    try:
        addr = ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
    except ValueError:
        return False


def detect_suspicious_traffic(
    telemetry: NetworkTelemetry,
    dns_records: list[DnsRecord],
) -> list[SuspiciousFinding]:
    """Run non-definitive heuristic detectors over network and DNS telemetry."""
    findings: list[SuspiciousFinding] = []
    total_packets = telemetry.total_packets
    tcp_acc = telemetry.tcp_accumulator

    # 1. Unusually frequent connections to a destination
    if total_packets >= FREQUENT_DST_MIN_PACKETS:
        for dst_ip, pkt_count in telemetry.dst_ip_packet_counts.most_common(5):
            ratio = pkt_count / total_packets
            if pkt_count >= FREQUENT_DST_MIN_PACKETS and ratio >= FREQUENT_DST_RATIO_THRESHOLD:
                findings.append(
                    SuspiciousFinding(
                        category="Frequent Destination",
                        severity="medium",
                        title=f"High concentration of traffic to {dst_ip}",
                        description=(
                            f"Heuristic observation: {pkt_count} packets ({ratio:.1%} of capture) "
                            f"are directed to destination IP {dst_ip}."
                        ),
                        indicators=[f"dst_ip={dst_ip}", f"packets={pkt_count}", f"share={ratio:.1%}"],
                    )
                )

    # 2. Possible port scanning (multi-port SYN fan-out, or single-port sweep on non-web ports)
    for src_ip, targets in tcp_acc.syn_targets_by_src.items():
        unique_ports = {port for _, port in targets}
        unique_hosts = {host for host, _ in targets}
        non_web_hosts = {host for host, port in targets if port not in {80, 443}}
        if len(unique_ports) >= PORT_SCAN_UNIQUE_PORTS_THRESHOLD:
            pkts = tcp_acc.syn_packets_by_src.get(src_ip, [])
            findings.append(
                SuspiciousFinding(
                    category="Port Scan Heuristic",
                    severity="high",
                    title=f"Possible port scan originating from {src_ip}",
                    description=(
                        f"Heuristic observation: {src_ip} initiated TCP SYN connections to "
                        f"{len(unique_ports)} distinct destination port(s) across {len(unique_hosts)} host(s)."
                    ),
                    indicators=[
                        f"src_ip={src_ip}",
                        f"unique_dst_ports={len(unique_ports)}",
                        f"unique_dst_hosts={len(unique_hosts)}",
                        f"sample_ports={sorted(unique_ports)[:15]}",
                    ],
                    packet_refs=pkts[:50],
                )
            )
        elif len(non_web_hosts) >= PORT_SCAN_UNIQUE_PORTS_THRESHOLD:
            pkts = tcp_acc.syn_packets_by_src.get(src_ip, [])
            findings.append(
                SuspiciousFinding(
                    category="Host Sweep Heuristic",
                    severity="medium",
                    title=f"Possible host sweep originating from {src_ip}",
                    description=(
                        f"Heuristic observation: {src_ip} initiated TCP SYN connections to "
                        f"{len(non_web_hosts)} distinct non-web host(s) on port(s) {sorted(unique_ports)[:10]}."
                    ),
                    indicators=[
                        f"src_ip={src_ip}",
                        f"unique_dst_hosts={len(non_web_hosts)}",
                        f"ports={sorted(unique_ports)[:10]}",
                    ],
                    packet_refs=pkts[:50],
                )
            )

    # Fallback port-sweep check for UDP/ACK probing without pure SYN flags
    for src_ip, ports in telemetry.ip_dst_ports.items():
        if src_ip not in tcp_acc.syn_targets_by_src and len(ports) >= PORT_SCAN_UNIQUE_PORTS_THRESHOLD * 2:
            findings.append(
                SuspiciousFinding(
                    category="Port Scan Heuristic",
                    severity="medium",
                    title=f"Broad destination port fan-out from {src_ip}",
                    description=(
                        f"Heuristic observation: {src_ip} communicated with {len(ports)} distinct "
                        "destination ports, which may indicate scanning or service enumeration."
                    ),
                    indicators=[f"src_ip={src_ip}", f"unique_dst_ports={len(ports)}"],
                )
            )

    # 3. Excessive TCP retransmissions
    if tcp_acc.total_tcp_packets >= 20:
        retrans_ratio = tcp_acc.retransmissions / tcp_acc.total_tcp_packets
        if tcp_acc.retransmissions >= 15 or (tcp_acc.retransmissions >= 5 and retrans_ratio >= 0.05):
            findings.append(
                SuspiciousFinding(
                    category="TCP Anomalies",
                    severity="medium",
                    title="Excessive TCP retransmissions detected",
                    description=(
                        f"Heuristic observation: {tcp_acc.retransmissions} TCP retransmission(s) "
                        f"({retrans_ratio:.1%} of TCP packets), suggesting packet loss, congestion, "
                        "or interrupted connections."
                    ),
                    indicators=[
                        f"retransmissions={tcp_acc.retransmissions}",
                        f"dup_acks={tcp_acc.duplicate_acks}",
                        f"resets={tcp_acc.resets}",
                        f"frames={format_packet_ranges(tcp_acc.retransmission_packets[:20])}",
                    ],
                    packet_refs=tcp_acc.retransmission_packets[:50],
                )
            )

    # 4 & 5. Unusual DNS query patterns & suspiciously long DNS labels
    nxdomain_domains: list[str] = []
    txt_or_high_query_domains: list[str] = []
    for rec in dns_records:
        labels = [lbl for lbl in rec.query_name.split(".") if lbl]
        max_label = max((len(lbl) for lbl in labels), default=0)
        if max_label >= SUSPICIOUS_DNS_LABEL_LEN or len(rec.query_name) >= SUSPICIOUS_DNS_FQDN_LEN:
            findings.append(
                SuspiciousFinding(
                    category="Suspicious DNS",
                    severity="high" if max_label >= 52 else "medium",
                    title=f"Suspiciously long DNS name/label: {rec.query_name[:80]}",
                    description=(
                        f"Heuristic observation: DNS query '{rec.query_name}' has max label length "
                        f"{max_label} (total length {len(rec.query_name)}), a common indicator of "
                        "DNS tunneling or encoded payload exfiltration."
                    ),
                    indicators=[
                        f"domain={rec.query_name}",
                        f"max_label_len={max_label}",
                        f"query_count={rec.count}",
                    ],
                    packet_refs=rec.packet_numbers[:25],
                )
            )
        if "3" in rec.response_codes:  # NXDOMAIN
            nxdomain_domains.append(rec.query_name)
        if "TXT" in rec.query_types or rec.count >= 25:
            txt_or_high_query_domains.append(f"{rec.query_name} ({rec.count}x)")

    if len(nxdomain_domains) >= 10:
        findings.append(
            SuspiciousFinding(
                category="Unusual DNS Pattern",
                severity="medium",
                title=f"High number of NXDOMAIN DNS responses ({len(nxdomain_domains)} domains)",
                description=(
                    "Heuristic observation: Many queried domains failed to resolve (NXDOMAIN), "
                    "which can indicate DGA activity, misconfigured services, or DNS probing."
                ),
                indicators=[f"sample_domains={nxdomain_domains[:10]}"],
            )
        )

    if txt_or_high_query_domains:
        findings.append(
            SuspiciousFinding(
                category="Unusual DNS Pattern",
                severity="low",
                title="TXT or high-frequency DNS queries observed",
                description=(
                    "Heuristic observation: DNS TXT lookups or repeated queries to the same domain "
                    "were detected; TXT records are occasionally used for C2/data staging in CTFs."
                ),
                indicators=txt_or_high_query_domains[:10],
            )
        )

    # 6 & 7. Unexpected outbound communication & potential data exfiltration indicators
    conv_list = [*telemetry.network.tcp_conversations, *telemetry.network.udp_conversations]
    unusual_outbound_ports: Counter[int] = Counter()
    for conv in conv_list:
        src_priv = _is_private_or_local(conv.src_ip)
        dst_priv = _is_private_or_local(conv.dst_ip)
        if src_priv and not dst_priv:
            if conv.dst_port > 0 and conv.dst_port not in UNEXPECTED_PORT_ALLOWLIST and conv.packets >= 5:
                unusual_outbound_ports[conv.dst_port] += conv.packets
            if conv.bytes >= HIGH_OUTBOUND_BYTES_THRESHOLD:
                findings.append(
                    SuspiciousFinding(
                        category="High-Volume External Conversation",
                        severity="medium",
                        title=f"High-volume transfer with external IP {conv.dst_ip}:{conv.dst_port}",
                        description=(
                            f"Heuristic observation: {format_bytes(conv.bytes)} total transferred in conversation "
                            f"between internal host {conv.src_ip} and external host {conv.dst_ip}:{conv.dst_port}."
                        ),
                        indicators=[
                            f"src={conv.src_ip}:{conv.src_port}",
                            f"dst={conv.dst_ip}:{conv.dst_port}",
                            f"bytes={conv.bytes}",
                            f"packets={conv.packets}",
                        ],
                    )
                )

    if unusual_outbound_ports:
        top_ports = [f"{port} ({cnt} pkts)" for port, cnt in unusual_outbound_ports.most_common(10)]
        findings.append(
            SuspiciousFinding(
                category="Unexpected Outbound Traffic",
                severity="low",
                title="Outbound traffic on non-standard destination ports",
                description=(
                    "Heuristic observation: Internal IP(s) communicated externally over ports outside "
                    "common web/DNS/mail defaults."
                ),
                indicators=top_ports,
            )
        )

    return findings
