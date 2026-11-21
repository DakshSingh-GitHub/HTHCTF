"""IP endpoint, port, protocol distribution, and conversation analyzer."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from core.models import IpEndpointStat, NetworkIntelligence
from core.tshark import TSharkRunner
from modules.tcp_analyzer import TcpTelemetryAccumulator
from utils.helpers import first_non_empty, format_epoch_timestamp, is_truthy_field, parse_int

TELEMETRY_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.reset",
    "tcp.analysis.retransmission",
    "tcp.analysis.duplicate_ack",
]

GENERIC_LAYER_TOKENS = {
    "frame",
    "eth",
    "ethertype",
    "sll",
    "raw",
    "null",
    "ip",
    "ipv6",
    "vlan",
    "data",
    "data-text-lines",
    "media",
    "urlencoded-form",
    "json",
    "xml",
    "line-based-text-data",
    "mime_multipart",
    "x509sat",
    "x509ce",
    "x509af",
    "pkcs-1",
    "image-gif",
    "image-jfif",
    "png",
}


def classify_protocol(frame_protocols: str) -> str:
    """Identify the highest meaningful protocol layer from `frame.protocols`."""
    if not frame_protocols:
        return "UNKNOWN"
    tokens = [tok.strip().lower() for tok in frame_protocols.split(":") if tok.strip()]
    for tok in reversed(tokens):
        if tok not in GENERIC_LAYER_TOKENS:
            if tok == "ssl":
                return "TLS"
            return tok.upper()
    if "ipv6" in tokens:
        return "IPV6"
    if "ip" in tokens:
        return "IP"
    return tokens[-1].upper() if tokens else "UNKNOWN"


@dataclass
class NetworkTelemetry:
    """Combined network intelligence and streaming accumulators for downstream detectors."""

    total_packets: int
    network: NetworkIntelligence
    tcp_accumulator: TcpTelemetryAccumulator
    src_dst_pair_counts: Counter[tuple[str, str]] = field(default_factory=Counter)
    dst_ip_packet_counts: Counter[str] = field(default_factory=Counter)
    dst_ip_bytes: Counter[str] = field(default_factory=Counter)
    src_ip_bytes: Counter[str] = field(default_factory=Counter)
    ip_peers: dict[str, set[str]] = field(default_factory=dict)
    ip_dst_ports: dict[str, set[int]] = field(default_factory=dict)


def analyze_network_traffic(
    runner: TSharkRunner,
    pcap_path: str | Path,
    warnings: list[str] | None = None,
) -> NetworkTelemetry:
    """Perform a single streaming pass to extract IP, port, protocol, and TCP/UDP telemetry."""
    total_packets = 0
    protocol_counts: Counter[str] = Counter()
    ip_stats: dict[str, IpEndpointStat] = {}
    ip_peers: dict[str, set[str]] = {}
    ip_dst_ports: dict[str, set[int]] = {}
    src_port_counts: Counter[int] = Counter()
    dst_port_counts: Counter[int] = Counter()
    src_dst_pair_counts: Counter[tuple[str, str]] = Counter()
    dst_ip_packet_counts: Counter[str] = Counter()
    dst_ip_bytes: Counter[str] = Counter()
    src_ip_bytes: Counter[str] = Counter()
    tcp_acc = TcpTelemetryAccumulator()

    def _get_ip(ip_addr: str) -> IpEndpointStat:
        stat = ip_stats.get(ip_addr)
        if stat is None:
            stat = IpEndpointStat(ip=ip_addr)
            ip_stats[ip_addr] = stat
        return stat

    for row in runner.stream_fields(
        pcap_path,
        TELEMETRY_FIELDS,
        warnings_out=warnings,
    ):
        total_packets += 1
        frame_num = parse_int(row[0], total_packets)
        timestamp = format_epoch_timestamp(row[1])
        frame_len = parse_int(row[2], 0)
        protocols_raw = row[3].strip()
        src_ip = first_non_empty(row[4], row[5])
        dst_ip = first_non_empty(row[6], row[7])
        tcp_sport = parse_int(row[8], 0)
        tcp_dport = parse_int(row[9], 0)
        tcp_stream_raw = row[10].strip()
        tcp_stream = parse_int(tcp_stream_raw, -1) if tcp_stream_raw else None
        if tcp_stream is not None and tcp_stream < 0:
            tcp_stream = None
        udp_sport = parse_int(row[11], 0)
        udp_dport = parse_int(row[12], 0)
        is_syn = is_truthy_field(row[13])
        is_ack = is_truthy_field(row[14])
        is_reset = is_truthy_field(row[15])
        is_retrans = is_truthy_field(row[16])
        is_dup_ack = is_truthy_field(row[17])

        proto = classify_protocol(protocols_raw)
        protocol_counts[proto] += 1

        if src_ip:
            s_stat = _get_ip(src_ip)
            s_stat.packets_sent += 1
            s_stat.total_packets += 1
            s_stat.bytes_sent += frame_len
            src_ip_bytes[src_ip] += frame_len
        if dst_ip:
            d_stat = _get_ip(dst_ip)
            d_stat.packets_received += 1
            d_stat.total_packets += 1
            d_stat.bytes_received += frame_len
            dst_ip_packet_counts[dst_ip] += 1
            dst_ip_bytes[dst_ip] += frame_len
        if src_ip and dst_ip:
            ip_peers.setdefault(src_ip, set()).add(dst_ip)
            ip_peers.setdefault(dst_ip, set()).add(src_ip)
            src_dst_pair_counts[(src_ip, dst_ip)] += 1

        is_tcp = tcp_sport > 0 or tcp_dport > 0 or tcp_stream is not None or ":tcp" in protocols_raw.lower()
        is_udp = (not is_tcp) and (udp_sport > 0 or udp_dport > 0 or ":udp" in protocols_raw.lower())
        is_tls = ":tls" in protocols_raw.lower() or ":ssl" in protocols_raw.lower()

        if is_tcp:
            if tcp_sport > 0:
                src_port_counts[tcp_sport] += 1
            if tcp_dport > 0:
                dst_port_counts[tcp_dport] += 1
                if src_ip:
                    ip_dst_ports.setdefault(src_ip, set()).add(tcp_dport)
            tcp_acc.record_tcp_packet(
                frame_num=frame_num,
                timestamp=timestamp,
                length=frame_len,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=tcp_sport,
                dst_port=tcp_dport,
                stream_id=tcp_stream,
                is_syn=is_syn,
                is_ack=is_ack,
                is_reset=is_reset,
                is_retransmission=is_retrans,
                is_dup_ack=is_dup_ack,
                is_tls=is_tls,
            )
        elif is_udp:
            if udp_sport > 0:
                src_port_counts[udp_sport] += 1
            if udp_dport > 0:
                dst_port_counts[udp_dport] += 1
                if src_ip:
                    ip_dst_ports.setdefault(src_ip, set()).add(udp_dport)
            tcp_acc.record_udp_packet(
                timestamp=timestamp,
                length=frame_len,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=udp_sport,
                dst_port=udp_dport,
            )

    for ip_addr, stat in ip_stats.items():
        stat.unique_peers = len(ip_peers.get(ip_addr, set()))
        stat.dst_ports_contacted = sorted(ip_dst_ports.get(ip_addr, set()))[:50]

    top_sources = sorted(
        (s for s in ip_stats.values() if s.packets_sent > 0),
        key=lambda s: (s.packets_sent, s.bytes_sent),
        reverse=True,
    )[:20]
    top_destinations = sorted(
        (s for s in ip_stats.values() if s.packets_received > 0),
        key=lambda s: (s.packets_received, s.bytes_received),
        reverse=True,
    )[:20]

    tcp_convs = sorted(
        tcp_acc.tcp_conversations.values(),
        key=lambda c: (c.packets, c.bytes),
        reverse=True,
    )[:50]
    udp_convs = sorted(
        tcp_acc.udp_conversations.values(),
        key=lambda c: (c.packets, c.bytes),
        reverse=True,
    )[:50]

    network = NetworkIntelligence(
        unique_ips=sorted(ip_stats.keys()),
        top_source_ips=top_sources,
        top_destination_ips=top_destinations,
        top_source_ports=src_port_counts.most_common(15),
        top_destination_ports=dst_port_counts.most_common(15),
        tcp_conversations=tcp_convs,
        udp_conversations=udp_convs,
        protocol_distribution=dict(protocol_counts.most_common()),
        tcp_summary=tcp_acc.build_summary(),
    )

    return NetworkTelemetry(
        total_packets=total_packets,
        network=network,
        tcp_accumulator=tcp_acc,
        src_dst_pair_counts=src_dst_pair_counts,
        dst_ip_packet_counts=dst_ip_packet_counts,
        dst_ip_bytes=dst_ip_bytes,
        src_ip_bytes=src_ip_bytes,
        ip_peers=ip_peers,
        ip_dst_ports=ip_dst_ports,
    )
