"""JSON report writer for Packet Detective."""

from __future__ import annotations

import json
from pathlib import Path

from core.models import AnalysisReport


def write_json_report(report: AnalysisReport, destination: Path) -> Path:
    """Serialize the complete AnalysisReport to JSON."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        json.dump(report.to_dict(), handle, indent=2, ensure_ascii=False)
    return destination
