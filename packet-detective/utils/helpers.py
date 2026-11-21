"""Shared utility functions for safe decoding, sanitization, and formatting."""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qs, urlparse


def is_truthy_field(value: str | None) -> bool:
    """Return True when a TShark boolean/FT_NONE field is active."""
    if not value:
        return False
    normalized = value.strip().lower()
    return normalized in {"1", "true", "yes"}


def split_aggregated(value: str | None, delimiter: str = "|") -> list[str]:
    """Split an aggregated TShark field value into non-empty stripped items."""
    if not value:
        return []
    return [part.strip() for part in value.split(delimiter) if part.strip()]


def first_non_empty(*values: str | None) -> str:
    """Return the first non-empty stripped string from values."""
    for value in values:
        if value and value.strip():
            return value.strip()
    return ""


def parse_int(value: str | None, default: int = 0) -> int:
    """Safely parse an integer from a string."""
    if not value:
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


def format_epoch_timestamp(epoch_str: str | None) -> str:
    """Convert a TShark epoch timestamp string into an ISO-8601 UTC string."""
    if not epoch_str or not epoch_str.strip():
        return ""
    try:
        ts = float(epoch_str.strip())
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except (ValueError, OSError, OverflowError):
        return epoch_str.strip()


def decode_hex_bytes(hex_str: str | None) -> bytes:
    """Decode TShark FT_BYTES hex strings (with or without colons/whitespace)."""
    if not hex_str:
        return b""
    cleaned = hex_str.replace(":", "").replace(" ", "").replace("\n", "").replace("\r", "").strip()
    if not cleaned:
        return b""
    if len(cleaned) % 2 != 0:
        cleaned = cleaned[:-1]
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return b""


def decode_payload_text(raw: bytes) -> str:
    """Decode raw bytes to inspectable text while preserving ASCII/UTF-8 characters."""
    if not raw:
        return ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace")


def extract_printable_runs(raw: bytes, min_length: int = 4) -> list[str]:
    """Extract contiguous printable ASCII runs from raw binary payloads."""
    if not raw:
        return []
    runs: list[str] = []
    current = bytearray()
    for byte in raw:
        if 32 <= byte <= 126 or byte in (9, 10, 13):
            current.append(byte)
        else:
            if len(current) >= min_length:
                runs.append(current.decode("ascii", errors="replace"))
            current.clear()
    if len(current) >= min_length:
        runs.append(current.decode("ascii", errors="replace"))
    return runs


def reconstruct_http_url(host: str, uri: str, full_uri: str = "") -> str:
    """Reconstruct a full HTTP URL from Host header and request URI."""
    clean_full = full_uri.strip()
    if clean_full and clean_full.lower().startswith(("http://", "https://")):
        return clean_full
    clean_host = host.strip()
    clean_uri = uri.strip() or "/"
    if clean_uri.lower().startswith(("http://", "https://")):
        return clean_uri
    if clean_host:
        if not clean_uri.startswith("/"):
            clean_uri = "/" + clean_uri
        return f"http://{clean_host}{clean_uri}"
    return clean_uri


def extract_query_parameters(uri_or_url: str) -> dict[str, list[str]]:
    """Parse query string parameters from a URI or URL."""
    if not uri_or_url:
        return {}
    parsed = urlparse(uri_or_url)
    if not parsed.query:
        return {}
    return parse_qs(parsed.query, keep_blank_values=True)


def sanitize_filename(filename: str, fallback: str = "object.bin") -> str:
    """Sanitize a filename from untrusted packet data to prevent traversal."""
    base = os.path.basename(filename.replace("\\", "/")).strip()
    base = re.sub(r"[\x00-\x1f\x7f<>:\"|?*]", "_", base)
    if not base or base in {".", ".."}:
        return fallback
    return base[:180]


def make_unique_path(directory: Path, filename: str) -> Path:
    """Return a non-colliding file path inside directory."""
    safe_name = sanitize_filename(filename)
    candidate = directory / safe_name
    if not candidate.exists():
        return candidate
    stem = candidate.stem
    suffix = candidate.suffix
    counter = 1
    while True:
        next_candidate = directory / f"{stem}_{counter}{suffix}"
        if not next_candidate.exists():
            return next_candidate
        counter += 1


def format_packet_ranges(packet_numbers: Iterable[int]) -> str:
    """Format sorted packet numbers into compact ranges such as '410-416' or '12, 18-20'."""
    nums = sorted({n for n in packet_numbers if n > 0})
    if not nums:
        return "unknown"
    ranges: list[str] = []
    start = prev = nums[0]
    for num in nums[1:]:
        if num == prev + 1:
            prev = num
        else:
            ranges.append(str(start) if start == prev else f"{start}-{prev}")
            start = prev = num
    ranges.append(str(start) if start == prev else f"{start}-{prev}")
    return ", ".join(ranges)


def format_bytes(size: int) -> str:
    """Format byte size in a human-readable way."""
    if size < 1024:
        return f"{size} B"
    units = ["KB", "MB", "GB", "TB"]
    value = float(size)
    for unit in units:
        value /= 1024.0
        if value < 1024.0:
            return f"{value:.1f} {unit}"
    return f"{value:.1f} PB"
