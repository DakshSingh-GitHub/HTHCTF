"""HTTP URL, header, and query parameter extractor."""

from __future__ import annotations

from pathlib import Path

from core.models import HttpRecord
from core.tshark import TSharkRunner
from utils.helpers import (
    extract_query_parameters,
    first_non_empty,
    format_epoch_timestamp,
    parse_int,
    reconstruct_http_url,
)

HTTP_REQUEST_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.request.full_uri",
    "http.referer",
    "http.user_agent",
]

HTTP_RESPONSE_FIELDS = [
    "http.request_in",
    "http.response.code",
]


def extract_http_records(
    runner: TSharkRunner,
    pcap_path: str | Path,
    warnings: list[str] | None = None,
) -> tuple[list[HttpRecord], int]:
    """Extract and deduplicate HTTP request intelligence from a capture.

    Returns ``(deduplicated_records, total_http_requests)``.
    """
    response_codes_by_req_frame: dict[int, list[str]] = {}
    for row in runner.stream_fields(
        pcap_path,
        HTTP_RESPONSE_FIELDS,
        display_filter="http.response",
        warnings_out=warnings,
    ):
        req_frame = parse_int(row[0], 0)
        code = row[1].strip()
        if req_frame > 0 and code:
            codes = response_codes_by_req_frame.setdefault(req_frame, [])
            if code not in codes:
                codes.append(code)

    dedup: dict[tuple[str, str, str, str, int, str, str], HttpRecord] = {}
    total_requests = 0

    for row in runner.stream_fields(
        pcap_path,
        HTTP_REQUEST_FIELDS,
        display_filter="http.request",
        warnings_out=warnings,
    ):
        frame_num = parse_int(row[0], 0)
        timestamp = format_epoch_timestamp(row[1])
        src_ip = first_non_empty(row[2], row[3])
        dst_ip = first_non_empty(row[4], row[5])
        src_port = parse_int(row[6], 0)
        dst_port = parse_int(row[7], 0)
        method = row[8].strip().upper() or "GET"
        host = row[9].strip()
        uri = row[10].strip() or "/"
        full_uri_field = row[11].strip()
        referer = row[12].strip()
        user_agent = row[13].strip()

        full_url = reconstruct_http_url(host, uri, full_uri_field)
        query_params = extract_query_parameters(full_url or uri)
        total_requests += 1

        key = (method, full_url, src_ip, dst_ip, dst_port, referer, user_agent)
        req_codes = response_codes_by_req_frame.get(frame_num, [])

        if key not in dedup:
            dedup[key] = HttpRecord(
                method=method,
                host=host,
                uri=uri,
                full_url=full_url,
                query_params=query_params,
                referer=referer,
                user_agent=user_agent,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol="HTTP",
                status_codes=list(req_codes),
                packet_numbers=[frame_num] if frame_num > 0 else [],
                timestamps=[timestamp] if timestamp else [],
                count=1,
            )
        else:
            rec = dedup[key]
            rec.count += 1
            if frame_num > 0 and frame_num not in rec.packet_numbers:
                rec.packet_numbers.append(frame_num)
            if timestamp and timestamp not in rec.timestamps:
                rec.timestamps.append(timestamp)
            for code in req_codes:
                if code not in rec.status_codes:
                    rec.status_codes.append(code)

    records = sorted(
        dedup.values(),
        key=lambda r: (r.packet_numbers[0] if r.packet_numbers else 0, r.full_url),
    )
    return records, total_requests
