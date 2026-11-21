"""Dedicated HTH3{...} CTF flag hunting engine across packet layers and streams."""

from __future__ import annotations

import base64
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Pattern
from urllib.parse import unquote

from core.models import FlagCandidate
from core.tshark import TSharkRunner
from utils.helpers import (
    decode_hex_bytes,
    decode_payload_text,
    extract_printable_runs,
    format_packet_ranges,
    parse_int,
    split_aggregated,
)
from utils.regex_patterns import BASE64_CANDIDATE_REGEX, DEFAULT_FLAG_PREFIX, DEFAULT_MAX_FLAG_LENGTH, build_flag_regex

_HEX_CANDIDATE_REGEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")

HTTP_REQUEST_FLAG_FIELDS = [
    "frame.number",
    "tcp.stream",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.request.full_uri",
    "http.referer",
    "http.user_agent",
    "http.cookie",
    "http.authorization",
    "http.request.line",
    "http.file_data",
]

HTTP_RESPONSE_FLAG_FIELDS = [
    "frame.number",
    "tcp.stream",
    "http.response.code",
    "http.location",
    "http.set_cookie",
    "http.server",
    "http.response.line",
    "http.file_data",
]

DNS_FLAG_FIELDS = [
    "frame.number",
    "dns.qry.name",
    "dns.cname",
    "dns.txt",
]

TLS_METADATA_FLAG_FIELDS = [
    "frame.number",
    "tls.handshake.extensions_server_name",
    "x509sat.uTF8String",
    "x509sat.printableString",
    "x509ce.dNSName",
]

TCP_PAYLOAD_FIELDS = [
    "frame.number",
    "tcp.stream",
    "tcp.payload",
]

UDP_PAYLOAD_FIELDS = [
    "frame.number",
    "udp.payload",
]

OTHER_TEXT_FIELDS = [
    "frame.number",
    "frame.comment",
    "ftp.request.arg",
    "ftp.response.arg",
    "smtp.req.parameter",
    "telnet.data",
    "icmp.data",
    "data.data",
]


@dataclass
class _FlagAccumulator:
    value: str
    direct_sources: list[str] = field(default_factory=list)
    direct_packets: list[int] = field(default_factory=list)
    reconstructed_sources: list[str] = field(default_factory=list)
    reconstructed_packets: list[int] = field(default_factory=list)
    stream_ids: list[int] = field(default_factory=list)
    occurrences: int = 0

    def add_direct(self, source: str, packet_num: int | None = None, stream_id: int | None = None) -> None:
        self.occurrences += 1
        if source not in self.direct_sources:
            self.direct_sources.append(source)
        if packet_num and packet_num > 0 and packet_num not in self.direct_packets:
            self.direct_packets.append(packet_num)
        if stream_id is not None and stream_id not in self.stream_ids:
            self.stream_ids.append(stream_id)

    def add_reconstructed(
        self,
        source: str,
        packet_numbers: Iterable[int],
        stream_id: int,
    ) -> None:
        self.occurrences += 1
        if source not in self.reconstructed_sources:
            self.reconstructed_sources.append(source)
        for pkt in packet_numbers:
            if pkt > 0 and pkt not in self.reconstructed_packets:
                self.reconstructed_packets.append(pkt)
        if stream_id not in self.stream_ids:
            self.stream_ids.append(stream_id)

    def to_candidate(self) -> FlagCandidate:
        if self.direct_sources:
            primary_source = self.direct_sources[0]
            all_sources = [*self.direct_sources, *(s for s in self.reconstructed_sources if s not in self.direct_sources)]
            pkt_ref = (
                format_packet_ranges(self.direct_packets)
                if self.direct_packets
                else format_packet_ranges(self.reconstructed_packets)
            )
            return FlagCandidate(
                value=self.value,
                source=primary_source,
                packet_ref=pkt_ref,
                confidence="Candidate",
                reconstructed=False,
                stream_id=self.stream_ids[0] if self.stream_ids else None,
                occurrences=self.occurrences,
                sources=all_sources,
                details="Directly observed in packet-derived content",
            )

        primary_source = self.reconstructed_sources[0] if self.reconstructed_sources else "Reconstructed Stream"
        pkt_ref = format_packet_ranges(self.reconstructed_packets)
        return FlagCandidate(
            value=self.value,
            source=primary_source,
            packet_ref=pkt_ref,
            confidence="Candidate",
            reconstructed=True,
            stream_id=self.stream_ids[0] if self.stream_ids else None,
            occurrences=self.occurrences,
            sources=list(self.reconstructed_sources),
            details="Assembled across multiple TCP segments via TShark stream reassembly",
        )


def _record_match(
    flag_text: str,
    results: dict[str, _FlagAccumulator],
    source: str,
    packet_num: int | None = None,
    stream_id: int | None = None,
    reconstructed: bool = False,
    stream_packets: Iterable[int] = (),
) -> None:
    acc = results.get(flag_text)
    if acc is None:
        acc = _FlagAccumulator(value=flag_text)
        results[flag_text] = acc
    if reconstructed:
        assert stream_id is not None
        acc.add_reconstructed(source=source, packet_numbers=stream_packets, stream_id=stream_id)
    else:
        acc.add_direct(source=source, packet_num=packet_num, stream_id=stream_id)


def _scan_text_for_flags(
    text: str,
    pattern: Pattern[str],
    results: dict[str, _FlagAccumulator],
    source: str,
    packet_num: int | None = None,
    stream_id: int | None = None,
    reconstructed: bool = False,
    stream_packets: Iterable[int] = (),
) -> None:
    if not text:
        return
    for match in pattern.finditer(text):
        _record_match(
            match.group(0),
            results,
            source=source,
            packet_num=packet_num,
            stream_id=stream_id,
            reconstructed=reconstructed,
            stream_packets=stream_packets,
        )

    # Protocol-aware URL decoding (e.g. HTH3%7B...%7D in HTTP URIs/params)
    if "%" in text:
        unquoted = unquote(text)
        if unquoted != text:
            for match in pattern.finditer(unquoted):
                _record_match(
                    match.group(0),
                    results,
                    source=f"{source} (URL-decoded)",
                    packet_num=packet_num,
                    stream_id=stream_id,
                    reconstructed=reconstructed,
                    stream_packets=stream_packets,
                )

    # Base64-encoded flag candidates inside protocol fields or reassembled streams
    for b64_match in BASE64_CANDIDATE_REGEX.finditer(text):
        token = b64_match.group(0)
        try:
            raw_decoded = base64.b64decode(token, validate=True)
            decoded_text = raw_decoded.decode("utf-8")
        except Exception:
            continue
        for match in pattern.finditer(decoded_text):
            _record_match(
                match.group(0),
                results,
                source=f"{source} (Base64-decoded)",
                packet_num=packet_num,
                stream_id=stream_id,
                reconstructed=reconstructed,
                stream_packets=stream_packets,
            )

    # Hex-encoded flag candidates inside protocol fields or DNS labels
    for hex_match in _HEX_CANDIDATE_REGEX.finditer(text):
        token = hex_match.group(0)
        try:
            raw_decoded = bytes.fromhex(token)
            decoded_text = raw_decoded.decode("utf-8")
        except Exception:
            continue
        for match in pattern.finditer(decoded_text):
            _record_match(
                match.group(0),
                results,
                source=f"{source} (Hex-decoded)",
                packet_num=packet_num,
                stream_id=stream_id,
                reconstructed=reconstructed,
                stream_packets=stream_packets,
            )


def _scan_bytes_for_flags(
    raw: bytes,
    pattern: Pattern[str],
    results: dict[str, _FlagAccumulator],
    source: str,
    packet_num: int | None = None,
    stream_id: int | None = None,
    reconstructed: bool = False,
    stream_packets: Iterable[int] = (),
) -> None:
    if not raw:
        return
    decoded = decode_payload_text(raw)
    _scan_text_for_flags(
        decoded,
        pattern,
        results,
        source=source,
        packet_num=packet_num,
        stream_id=stream_id,
        reconstructed=reconstructed,
        stream_packets=stream_packets,
    )
    # Also scan extracted printable runs in case binary delimiters break UTF-8 decoding
    for run in extract_printable_runs(raw):
        if "{" in run and "}" in run:
            for match in pattern.finditer(run):
                flag_text = match.group(0)
                if flag_text not in results:
                    _scan_text_for_flags(
                        run,
                        pattern,
                        results,
                        source=source,
                        packet_num=packet_num,
                        stream_id=stream_id,
                        reconstructed=reconstructed,
                        stream_packets=stream_packets,
                    )
                    break


def hunt_flags(
    runner: TSharkRunner,
    pcap_path: str | Path,
    stream_packets: dict[int, list[int]] | None = None,
    stream_has_tls: set[int] | None = None,
    exported_objects_dir: Path | None = None,
    max_flag_length: int = DEFAULT_MAX_FLAG_LENGTH,
    flag_prefix: str = DEFAULT_FLAG_PREFIX,
    warnings: list[str] | None = None,
) -> list[FlagCandidate]:
    """Search all inspectable packet-derived layers and reconstructed TCP streams for flags.

    Never claims encrypted TLS application payloads were inspected as plaintext.
    """
    pattern = build_flag_regex(max_length=max_flag_length, prefix=flag_prefix)
    results: dict[str, _FlagAccumulator] = {}

    # 1 & 2. HTTP request headers and request bodies (including TShark-reassembled bodies)
    for row in runner.stream_fields(
        pcap_path,
        HTTP_REQUEST_FLAG_FIELDS,
        display_filter="http.request",
        warnings_out=warnings,
    ):
        pkt = parse_int(row[0], 0)
        sid = parse_int(row[1], -1)
        stream_id = sid if sid >= 0 else None
        header_chunks = [row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], *split_aggregated(row[10])]
        header_blob = "\n".join(part for part in header_chunks if part)
        _scan_text_for_flags(header_blob, pattern, results, source="HTTP Request Header", packet_num=pkt, stream_id=stream_id)
        if row[11]:
            body_bytes = decode_hex_bytes(row[11])
            _scan_bytes_for_flags(body_bytes, pattern, results, source="HTTP Request Body", packet_num=pkt, stream_id=stream_id)

    # 3 & 4. HTTP response headers and response bodies (including TShark-reassembled bodies)
    for row in runner.stream_fields(
        pcap_path,
        HTTP_RESPONSE_FLAG_FIELDS,
        display_filter="http.response",
        warnings_out=warnings,
    ):
        pkt = parse_int(row[0], 0)
        sid = parse_int(row[1], -1)
        stream_id = sid if sid >= 0 else None
        header_chunks = [row[2], row[3], row[4], row[5], *split_aggregated(row[6])]
        header_blob = "\n".join(part for part in header_chunks if part)
        _scan_text_for_flags(header_blob, pattern, results, source="HTTP Response Header", packet_num=pkt, stream_id=stream_id)
        if row[7]:
            body_bytes = decode_hex_bytes(row[7])
            _scan_bytes_for_flags(body_bytes, pattern, results, source="HTTP Response Body", packet_num=pkt, stream_id=stream_id)

    # 5. DNS query names & DNS TXT / CNAME strings
    for row in runner.stream_fields(
        pcap_path,
        DNS_FLAG_FIELDS,
        display_filter="dns",
        warnings_out=warnings,
    ):
        pkt = parse_int(row[0], 0)
        for field_label, val in (("DNS Query Name", row[1]), ("DNS CNAME", row[2]), ("DNS TXT", row[3])):
            for item in split_aggregated(val):
                _scan_text_for_flags(item, pattern, results, source=field_label, packet_num=pkt)

    # 6. Unencrypted TLS handshake metadata (SNI & X.509 certificate strings only)
    for row in runner.stream_fields(
        pcap_path,
        TLS_METADATA_FLAG_FIELDS,
        display_filter="tls.handshake",
        warnings_out=warnings,
    ):
        pkt = parse_int(row[0], 0)
        meta_blob = "\n".join(
            item
            for col in row[1:]
            for item in split_aggregated(col)
        )
        _scan_text_for_flags(meta_blob, pattern, results, source="TLS Handshake Metadata", packet_num=pkt)

    # 7. Individual non-TLS TCP packet payloads
    for row in runner.stream_fields(
        pcap_path,
        TCP_PAYLOAD_FIELDS,
        display_filter="tcp.len > 0 && !tls",
        warnings_out=warnings,
    ):
        pkt = parse_int(row[0], 0)
        sid = parse_int(row[1], -1)
        stream_id = sid if sid >= 0 else None
        payload = decode_hex_bytes(row[2])
        source_label = f"TCP Stream {stream_id}" if stream_id is not None else "TCP Payload"
        _scan_bytes_for_flags(payload, pattern, results, source=source_label, packet_num=pkt, stream_id=stream_id)

    # 8. UDP payloads
    for row in runner.stream_fields(
        pcap_path,
        UDP_PAYLOAD_FIELDS,
        display_filter="udp.length > 8",
        warnings_out=warnings,
    ):
        pkt = parse_int(row[0], 0)
        payload = decode_hex_bytes(row[1])
        _scan_bytes_for_flags(payload, pattern, results, source="UDP Payload", packet_num=pkt)

    # 11. Other printable packet-derived text (FTP, SMTP, Telnet, ICMP, frame comments, raw data)
    for row in runner.stream_fields(
        pcap_path,
        OTHER_TEXT_FIELDS,
        display_filter="frame.comment || ftp || smtp || telnet || icmp.data || data.data",
        warnings_out=warnings,
    ):
        pkt = parse_int(row[0], 0)
        for idx, label in (
            (1, "Frame Comment"),
            (2, "FTP Request"),
            (3, "FTP Response"),
            (4, "SMTP Command"),
            (5, "Telnet Data"),
        ):
            for item in split_aggregated(row[idx]):
                _scan_text_for_flags(item, pattern, results, source=label, packet_num=pkt)
        for idx, label in ((6, "ICMP Payload"), (7, "Raw Packet Data")):
            if row[idx]:
                raw = decode_hex_bytes(row[idx])
                _scan_bytes_for_flags(raw, pattern, results, source=label, packet_num=pkt)

    # 10. Exported HTTP objects (scan persisted files or temporary export)
    def _scan_object_files(obj_dir: Path) -> None:
        if not obj_dir.exists():
            return
        for obj_file in sorted(obj_dir.iterdir()):
            if not obj_file.is_file():
                continue
            try:
                raw_obj = obj_file.read_bytes()
            except OSError:
                continue
            _scan_bytes_for_flags(
                raw_obj,
                pattern,
                results,
                source=f"Exported HTTP Object ({obj_file.name})",
            )

    if exported_objects_dir is not None and exported_objects_dir.exists():
        _scan_object_files(exported_objects_dir)
    else:
        with tempfile.TemporaryDirectory(prefix="pktdet_flag_obj_") as tmp_obj_dir:
            tmp_path = Path(tmp_obj_dir)
            runner.export_objects(pcap_path, "http", tmp_path, warnings_out=warnings)
            _scan_object_files(tmp_path)

    # 9 & 12. Reconstructed TCP streams via TShark follow,tcp,raw (for fragmented flags)
    tls_streams = stream_has_tls or set()
    candidate_streams: list[int] = []
    if stream_packets:
        for sid, pkts in sorted(stream_packets.items()):
            if sid in tls_streams:
                continue
            if len(pkts) >= 2:
                candidate_streams.append(sid)

    if candidate_streams:
        reassembled = runner.follow_tcp_raw_batch(pcap_path, candidate_streams, warnings_out=warnings)
        for sid, chunks in reassembled.items():
            if not chunks:
                continue
            pkts = stream_packets.get(sid, []) if stream_packets else []
            source_label = f"Reconstructed TCP Stream {sid}"
            # Inspect both chronological stream bytes and separated direction bytes
            combined_bytes = b"".join(chunk for _, chunk in chunks)
            dir0_bytes = b"".join(chunk for direction, chunk in chunks if direction == 0)
            dir1_bytes = b"".join(chunk for direction, chunk in chunks if direction == 1)
            for stream_blob in (combined_bytes, dir0_bytes, dir1_bytes):
                if not stream_blob:
                    continue
                _scan_bytes_for_flags(
                    stream_blob,
                    pattern,
                    results,
                    source=source_label,
                    stream_id=sid,
                    reconstructed=True,
                    stream_packets=pkts,
                )

    candidates = [acc.to_candidate() for acc in results.values()]
    candidates.sort(key=lambda c: (c.reconstructed, c.stream_id if c.stream_id is not None else 10**9, c.value))
    return candidates
