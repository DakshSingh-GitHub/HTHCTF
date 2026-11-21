"""TCP/UDP stream tracking, connection patterns, and anomaly analysis."""

from __future__ import annotations

from dataclasses import dataclass, field

from core.models import ConversationStat, TcpAnalysisSummary
from utils.helpers import format_packet_ranges


@dataclass
class TcpTelemetryAccumulator:
    """Incremental accumulator for TCP and UDP metrics during packet streaming."""

    total_tcp_packets: int = 0
    total_udp_packets: int = 0
    retransmissions: int = 0
    duplicate_acks: int = 0
    resets: int = 0
    syn_packets: int = 0
    syn_ack_packets: int = 0
    retransmission_packets: list[int] = field(default_factory=list)
    duplicate_ack_packets: list[int] = field(default_factory=list)
    reset_packets: list[int] = field(default_factory=list)
    syn_packet_numbers: list[int] = field(default_factory=list)
    stream_packets: dict[int, list[int]] = field(default_factory=dict)
    stream_has_tls: set[int] = field(default_factory=set)
    stream_endpoints: dict[int, tuple[str, int, str, int]] = field(default_factory=dict)
    tcp_conversations: dict[tuple[str, int, str, int, int | None], ConversationStat] = field(default_factory=dict)
    udp_conversations: dict[tuple[str, int, str, int], ConversationStat] = field(default_factory=dict)
    syn_targets_by_src: dict[str, set[tuple[str, int]]] = field(default_factory=dict)
    syn_packets_by_src: dict[str, list[int]] = field(default_factory=dict)

    def record_tcp_packet(
        self,
        frame_num: int,
        timestamp: str,
        length: int,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        stream_id: int | None,
        is_syn: bool,
        is_ack: bool,
        is_reset: bool,
        is_retransmission: bool,
        is_dup_ack: bool,
        is_tls: bool,
    ) -> None:
        self.total_tcp_packets += 1

        if stream_id is not None:
            self.stream_packets.setdefault(stream_id, []).append(frame_num)
            if is_tls:
                self.stream_has_tls.add(stream_id)
            if stream_id not in self.stream_endpoints and src_ip and dst_ip:
                self.stream_endpoints[stream_id] = (src_ip, src_port, dst_ip, dst_port)

        if is_retransmission:
            self.retransmissions += 1
            self.retransmission_packets.append(frame_num)
        if is_dup_ack:
            self.duplicate_acks += 1
            self.duplicate_ack_packets.append(frame_num)
        if is_reset:
            self.resets += 1
            self.reset_packets.append(frame_num)
        if is_syn and not is_ack:
            self.syn_packets += 1
            self.syn_packet_numbers.append(frame_num)
            if src_ip and dst_ip and dst_port > 0:
                self.syn_targets_by_src.setdefault(src_ip, set()).add((dst_ip, dst_port))
                self.syn_packets_by_src.setdefault(src_ip, []).append(frame_num)
        elif is_syn and is_ack:
            self.syn_ack_packets += 1

        if src_ip and dst_ip:
            a = (src_ip, src_port)
            b = (dst_ip, dst_port)
            if a <= b:
                conv_key = (src_ip, src_port, dst_ip, dst_port, stream_id)
            else:
                conv_key = (dst_ip, dst_port, src_ip, src_port, stream_id)
            conv = self.tcp_conversations.get(conv_key)
            if conv is None:
                conv = ConversationStat(
                    protocol="TCP",
                    src_ip=conv_key[0],
                    src_port=conv_key[1],
                    dst_ip=conv_key[2],
                    dst_port=conv_key[3],
                    packets=0,
                    bytes=0,
                    stream_id=stream_id,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
                self.tcp_conversations[conv_key] = conv
            conv.packets += 1
            conv.bytes += length
            if timestamp:
                if not conv.first_seen:
                    conv.first_seen = timestamp
                conv.last_seen = timestamp

    def record_udp_packet(
        self,
        timestamp: str,
        length: int,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
    ) -> None:
        self.total_udp_packets += 1
        if src_ip and dst_ip:
            a = (src_ip, src_port)
            b = (dst_ip, dst_port)
            if a <= b:
                conv_key = (src_ip, src_port, dst_ip, dst_port)
            else:
                conv_key = (dst_ip, dst_port, src_ip, src_port)
            conv = self.udp_conversations.get(conv_key)
            if conv is None:
                conv = ConversationStat(
                    protocol="UDP",
                    src_ip=conv_key[0],
                    src_port=conv_key[1],
                    dst_ip=conv_key[2],
                    dst_port=conv_key[3],
                    packets=0,
                    bytes=0,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
                self.udp_conversations[conv_key] = conv
            conv.packets += 1
            conv.bytes += length
            if timestamp:
                if not conv.first_seen:
                    conv.first_seen = timestamp
                conv.last_seen = timestamp

    def build_summary(self) -> TcpAnalysisSummary:
        patterns: list[str] = []
        if self.total_tcp_packets > 0:
            retrans_ratio = self.retransmissions / self.total_tcp_packets
            if self.retransmissions >= 10 or (self.retransmissions >= 3 and retrans_ratio > 0.05):
                patterns.append(
                    f"Elevated TCP retransmissions: {self.retransmissions} "
                    f"({retrans_ratio:.1%} of TCP packets; frames {format_packet_ranges(self.retransmission_packets[:15])})"
                )
            rst_ratio = self.resets / self.total_tcp_packets
            if self.resets >= 10 or (self.resets >= 3 and rst_ratio > 0.10):
                patterns.append(
                    f"Frequent TCP RST packets: {self.resets} "
                    f"(frames {format_packet_ranges(self.reset_packets[:15])})"
                )
        if self.syn_packets > 0 and self.syn_ack_packets == 0 and self.syn_packets >= 5:
            patterns.append(
                f"Unanswered TCP connection attempts: {self.syn_packets} SYN packets with 0 SYN-ACK replies"
            )
        elif self.syn_packets >= 10 and self.syn_ack_packets > 0 and self.syn_packets > self.syn_ack_packets * 3:
            patterns.append(
                f"High SYN to SYN-ACK ratio ({self.syn_packets} SYN vs {self.syn_ack_packets} SYN-ACK), "
                "possible failed connections or scanning"
            )

        return TcpAnalysisSummary(
            total_tcp_packets=self.total_tcp_packets,
            total_udp_packets=self.total_udp_packets,
            unique_tcp_streams=len(self.stream_packets),
            retransmissions=self.retransmissions,
            duplicate_acks=self.duplicate_acks,
            resets=self.resets,
            syn_packets=self.syn_packets,
            syn_ack_packets=self.syn_ack_packets,
            retransmission_packet_numbers=self.retransmission_packets[:200],
            duplicate_ack_packet_numbers=self.duplicate_ack_packets[:200],
            reset_packet_numbers=self.reset_packets[:200],
            syn_packet_numbers=self.syn_packet_numbers[:200],
            unusual_patterns=patterns,
        )
