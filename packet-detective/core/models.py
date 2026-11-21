"""Typed data models for Packet Detective analysis results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class HttpRecord:
    method: str
    host: str
    uri: str
    full_url: str
    query_params: dict[str, list[str]] = field(default_factory=dict)
    referer: str = ""
    user_agent: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "HTTP"
    status_codes: list[str] = field(default_factory=list)
    packet_numbers: list[int] = field(default_factory=list)
    timestamps: list[str] = field(default_factory=list)
    count: int = 1


@dataclass
class DnsRecord:
    query_name: str
    query_types: list[str] = field(default_factory=list)
    resolved_ips: list[str] = field(default_factory=list)
    cname_targets: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    response_codes: list[str] = field(default_factory=list)
    src_ips: list[str] = field(default_factory=list)
    dst_ips: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    packet_numbers: list[int] = field(default_factory=list)
    timestamps: list[str] = field(default_factory=list)
    count: int = 1


@dataclass
class TlsRecord:
    sni: str
    handshake_versions: list[str] = field(default_factory=list)
    record_versions: list[str] = field(default_factory=list)
    src_ips: list[str] = field(default_factory=list)
    dst_ips: list[str] = field(default_factory=list)
    dst_ports: list[int] = field(default_factory=list)
    protocol: str = "TLS"
    packet_numbers: list[int] = field(default_factory=list)
    timestamps: list[str] = field(default_factory=list)
    count: int = 1
    note: str = (
        "HTTPS URL paths and query parameters are encrypted and cannot be "
        "recovered from TLS metadata alone without TLS decryption keys."
    )


@dataclass
class IpEndpointStat:
    ip: str
    packets_sent: int = 0
    packets_received: int = 0
    total_packets: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    unique_peers: int = 0
    dst_ports_contacted: list[int] = field(default_factory=list)


@dataclass
class ConversationStat:
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    packets: int = 0
    bytes: int = 0
    stream_id: int | None = None
    first_seen: str = ""
    last_seen: str = ""


@dataclass
class TcpAnalysisSummary:
    total_tcp_packets: int = 0
    total_udp_packets: int = 0
    unique_tcp_streams: int = 0
    retransmissions: int = 0
    duplicate_acks: int = 0
    resets: int = 0
    syn_packets: int = 0
    syn_ack_packets: int = 0
    retransmission_packet_numbers: list[int] = field(default_factory=list)
    duplicate_ack_packet_numbers: list[int] = field(default_factory=list)
    reset_packet_numbers: list[int] = field(default_factory=list)
    syn_packet_numbers: list[int] = field(default_factory=list)
    unusual_patterns: list[str] = field(default_factory=list)


@dataclass
class NetworkIntelligence:
    unique_ips: list[str] = field(default_factory=list)
    top_source_ips: list[IpEndpointStat] = field(default_factory=list)
    top_destination_ips: list[IpEndpointStat] = field(default_factory=list)
    top_source_ports: list[tuple[int, int]] = field(default_factory=list)
    top_destination_ports: list[tuple[int, int]] = field(default_factory=list)
    tcp_conversations: list[ConversationStat] = field(default_factory=list)
    udp_conversations: list[ConversationStat] = field(default_factory=list)
    protocol_distribution: dict[str, int] = field(default_factory=dict)
    tcp_summary: TcpAnalysisSummary = field(default_factory=TcpAnalysisSummary)


@dataclass
class FlagCandidate:
    value: str
    source: str
    packet_ref: str
    confidence: str = "Candidate"
    reconstructed: bool = False
    stream_id: int | None = None
    occurrences: int = 1
    sources: list[str] = field(default_factory=list)
    details: str = ""


@dataclass
class SuspiciousFinding:
    category: str
    severity: str
    title: str
    description: str
    indicators: list[str] = field(default_factory=list)
    packet_refs: list[int] = field(default_factory=list)
    is_heuristic: bool = True


@dataclass
class ExtractedObject:
    filename: str
    size_bytes: int
    host: str
    output_path: str
    packet_number: int | None = None
    content_type: str = ""


@dataclass
class CaptureSummary:
    file_path: str
    file_size_bytes: int
    total_packets: int
    protocols: list[str] = field(default_factory=list)
    protocol_counts: dict[str, int] = field(default_factory=dict)
    http_requests_count: int = 0
    dns_queries_count: int = 0
    tls_hostnames_count: int = 0
    unique_ip_count: int = 0
    tls_encryption_note: str = (
        "TLS/HTTPS payloads remain encrypted; only unencrypted handshake metadata "
        "(such as SNI hostnames and version headers) is inspectable without session keys."
    )
    warnings: list[str] = field(default_factory=list)


@dataclass
class AnalysisReport:
    summary: CaptureSummary
    http_records: list[HttpRecord] = field(default_factory=list)
    dns_records: list[DnsRecord] = field(default_factory=list)
    tls_records: list[TlsRecord] = field(default_factory=list)
    network: NetworkIntelligence = field(default_factory=NetworkIntelligence)
    suspicious_findings: list[SuspiciousFinding] = field(default_factory=list)
    extracted_objects: list[ExtractedObject] = field(default_factory=list)
    flag_candidates: list[FlagCandidate] = field(default_factory=list)
    analysis_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
