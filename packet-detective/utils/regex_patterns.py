"""Configurable regular expression patterns for Packet Detective."""

from __future__ import annotations

import re
from typing import Pattern

DEFAULT_FLAG_PREFIX = "HTH3"
DEFAULT_MAX_FLAG_LENGTH = 512


def build_flag_regex(
    max_length: int = DEFAULT_MAX_FLAG_LENGTH,
    prefix: str = DEFAULT_FLAG_PREFIX,
) -> Pattern[str]:
    """Build the configurable case-insensitive flag-matching regex.

    Default pattern: ``(?i)HTH3\\{[^{}\\r\\n]{1,512}\\}``
    """
    if max_length < 1:
        raise ValueError("max_length must be at least 1")
    if not prefix or not prefix.strip():
        raise ValueError("prefix must be a non-empty string")
    escaped_prefix = re.escape(prefix.strip())
    return re.compile(rf"(?i){escaped_prefix}\{{[^{{}}\r\n]{{1,{max_length}}}\}}")


DEFAULT_FLAG_REGEX: Pattern[str] = build_flag_regex()
PRINTABLE_RUN_REGEX: Pattern[str] = re.compile(r"[\x20-\x7e]{4,}")
BASE64_CANDIDATE_REGEX: Pattern[str] = re.compile(r"\b(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b")
