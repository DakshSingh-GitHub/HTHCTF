"""HTTP object extraction using TShark with safe filename sanitization."""

from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path
from urllib.parse import unquote

from core.models import ExtractedObject
from core.tshark import TSharkRunner
from utils.helpers import make_unique_path, parse_int, sanitize_filename

_TSHARK_DUP_SUFFIX_RE = re.compile(r"\(\d+\)(?=\.[^.]+$|$)")


def _normalize_object_lookup_name(name: str) -> str:
    decoded = unquote(name).split("?", 1)[0].strip().lower()
    return _TSHARK_DUP_SUFFIX_RE.sub("", decoded)

HTTP_OBJECT_META_FIELDS = [
    "frame.number",
    "http.host",
    "http.request.uri",
    "http.request_in",
    "http.content_type",
]


def _collect_http_host_map(
    runner: TSharkRunner,
    pcap_path: str | Path,
    warnings: list[str] | None = None,
) -> tuple[dict[str, tuple[str, int, str]], dict[int, tuple[str, str]]]:
    """Build filename -> (host, packet_number, content_type) hints from HTTP packets."""
    req_by_frame: dict[int, tuple[str, str]] = {}
    by_basename: dict[str, tuple[str, int, str]] = {}

    for row in runner.stream_fields(
        pcap_path,
        HTTP_OBJECT_META_FIELDS,
        display_filter="http.request || http.response",
        warnings_out=warnings,
    ):
        frame_num = parse_int(row[0], 0)
        host = row[1].strip()
        uri = row[2].strip()
        req_in = parse_int(row[3], 0)
        content_type = row[4].strip()

        if uri:
            req_by_frame[frame_num] = (host, uri)
            base = sanitize_filename(uri.split("?", 1)[0].rsplit("/", 1)[-1] or "", fallback="")
            if base and base not in by_basename:
                by_basename[base.lower()] = (host, frame_num, content_type)
        elif req_in > 0 and req_in in req_by_frame:
            req_host, req_uri = req_by_frame[req_in]
            base = sanitize_filename(req_uri.split("?", 1)[0].rsplit("/", 1)[-1] or "", fallback="")
            if base:
                by_basename[base.lower()] = (req_host, frame_num, content_type)

    return by_basename, req_by_frame


def extract_http_objects(
    runner: TSharkRunner,
    pcap_path: str | Path,
    output_dir: Path | None = None,
    warnings: list[str] | None = None,
) -> list[ExtractedObject]:
    """Extract HTTP objects from the capture into `output_dir` (or temporary scan metadata).

    Extracted files are never executed and filenames are sanitized against traversal.
    """
    by_basename, _ = _collect_http_host_map(runner, pcap_path, warnings=warnings)
    extracted: list[ExtractedObject] = []

    with tempfile.TemporaryDirectory(prefix="pktdet_export_") as tmp_dir_str:
        staging_dir = Path(tmp_dir_str)
        raw_files = runner.export_objects(pcap_path, "http", staging_dir, warnings_out=warnings)
        if not raw_files:
            return []

        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)

        for src_file in raw_files:
            size_bytes = src_file.stat().st_size
            safe_name = sanitize_filename(src_file.name, fallback="http_object.bin")
            lookup_key = _normalize_object_lookup_name(safe_name)
            host, pkt_num, content_type = by_basename.get(lookup_key, ("", 0, ""))
            if not host:
                raw_lower = safe_name.lower()
                host, pkt_num, content_type = by_basename.get(raw_lower, ("", 0, ""))

            if output_dir is not None:
                dest_path = make_unique_path(output_dir, safe_name)
                shutil.copy2(src_file, dest_path)
                out_location = str(dest_path)
            else:
                out_location = "(not saved; pass --output DIR to persist extracted objects)"

            extracted.append(
                ExtractedObject(
                    filename=safe_name,
                    size_bytes=size_bytes,
                    host=host or "unknown",
                    output_path=out_location,
                    packet_number=pkt_num if pkt_num > 0 else None,
                    content_type=content_type,
                )
            )

    return extracted
