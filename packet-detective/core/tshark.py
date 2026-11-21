"""Safe, streaming TShark subprocess wrapper and installation diagnostics."""

from __future__ import annotations

import csv
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

logger = logging.getLogger(__name__)

MACOS_WIRESHARK_TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"


class TSharkError(RuntimeError):
    """Base error for TShark invocation failures."""


class TSharkNotFoundError(TSharkError):
    """Raised when TShark executable cannot be found."""


class CaptureFileError(TSharkError):
    """Raised when the capture file is missing or unreadable."""


def get_tshark_install_instructions() -> str:
    """Return helpful cross-platform installation instructions for TShark."""
    return (
        "TShark is required for Packet Detective but was not found on PATH.\n\n"
        "Installation instructions:\n"
        "  macOS (Homebrew):   brew install --cask wireshark\n"
        "                      (or install Wireshark.app and add "
        "/Applications/Wireshark.app/Contents/MacOS to PATH)\n"
        "  Ubuntu / Debian:    sudo apt-get update && sudo apt-get install -y tshark\n"
        "  Fedora / RHEL:      sudo dnf install -y wireshark-cli\n"
        "  Arch Linux:         sudo pacman -S wireshark-cli\n"
        "  Windows (winget):   winget install WiresharkFoundation.Wireshark\n"
    )


def find_tshark_binary(explicit_path: str | None = None) -> str:
    """Locate the TShark binary or raise TSharkNotFoundError with guidance."""
    if explicit_path:
        candidate = shutil.which(explicit_path) or (explicit_path if os.path.isfile(explicit_path) else None)
        if candidate:
            return candidate
        raise TSharkNotFoundError(
            f"Configured TShark binary not found: {explicit_path}\n\n{get_tshark_install_instructions()}"
        )

    found = shutil.which("tshark")
    if found:
        return found

    if os.path.isfile(MACOS_WIRESHARK_TSHARK) and os.access(MACOS_WIRESHARK_TSHARK, os.X_OK):
        return MACOS_WIRESHARK_TSHARK

    raise TSharkNotFoundError(get_tshark_install_instructions())


@dataclass
class TSharkStreamResult:
    """Captures stderr warnings and exit status from a completed stream."""

    returncode: int = 0
    warnings: list[str] | None = None


class TSharkRunner:
    """Safe subprocess wrapper around TShark with streaming support."""

    def __init__(self, tshark_path: str | None = None, timeout: int = 300) -> None:
        self.tshark_path = find_tshark_binary(tshark_path)
        self.timeout = timeout

    def version(self) -> str:
        """Return the first line of `tshark --version`."""
        result = subprocess.run(
            [self.tshark_path, "--version"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode != 0:
            raise TSharkError(result.stderr.strip() or "Failed to query TShark version.")
        return (result.stdout.splitlines() or ["unknown"])[0].strip()

    @staticmethod
    def validate_capture_path(pcap_path: str | Path) -> Path:
        """Ensure capture path exists and is a readable file."""
        path = Path(pcap_path)
        if not path.exists():
            raise CaptureFileError(f"Capture file does not exist: {path}")
        if not path.is_file():
            raise CaptureFileError(f"Capture path is not a file: {path}")
        return path

    def stream_fields(
        self,
        pcap_path: str | Path,
        fields: Sequence[str],
        display_filter: str | None = None,
        aggregator: str = "|",
        warnings_out: list[str] | None = None,
        disable_name_resolution: bool = True,
    ) -> Iterator[list[str]]:
        """Stream parsed field rows from TShark line-by-line using Popen.

        Handles malformed/truncated captures gracefully: packets emitted before
        a TShark read error are yielded and stderr diagnostics are recorded.
        """
        path = self.validate_capture_path(pcap_path)
        command: list[str] = [self.tshark_path, "-r", str(path)]
        if disable_name_resolution:
            command.append("-n")
        if display_filter:
            command.extend(["-Y", display_filter])
        command.extend(
            [
                "-T",
                "fields",
                "-E",
                "separator=\t",
                "-E",
                "quote=d",
                "-E",
                "occurrence=a",
                "-E",
                f"aggregator={aggregator}",
            ]
        )
        for field in fields:
            command.extend(["-e", field])

        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        assert proc.stdout is not None
        assert proc.stderr is not None

        field_count = len(fields)
        try:
            reader = csv.reader(proc.stdout, delimiter="\t", quotechar='"')
            for row in reader:
                if not row:
                    continue
                if len(row) < field_count:
                    row.extend([""] * (field_count - len(row)))
                elif len(row) > field_count:
                    row = row[:field_count]
                yield row
        finally:
            proc.stdout.close()
            stderr_text = proc.stderr.read().strip()
            proc.stderr.close()
            try:
                returncode = proc.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                raise TSharkError(f"TShark timed out after {self.timeout}s while reading {path.name}")

            if returncode != 0 and stderr_text:
                logger.warning("TShark exited with %d: %s", returncode, stderr_text)
                if warnings_out is not None:
                    for line in stderr_text.splitlines():
                        cleaned = line.strip()
                        if cleaned and cleaned not in warnings_out:
                            warnings_out.append(cleaned)

    def run_command(
        self,
        args: Sequence[str],
        warnings_out: list[str] | None = None,
        timeout: int | None = None,
    ) -> str:
        """Run a bounded TShark command safely without shell=True and return stdout."""
        command = [self.tshark_path, *args]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout or self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TSharkError(f"TShark command timed out: {' '.join(command[:5])}") from exc

        if result.returncode != 0 and result.stderr.strip():
            logger.warning("TShark command returned %d: %s", result.returncode, result.stderr.strip())
            if warnings_out is not None:
                for line in result.stderr.splitlines():
                    cleaned = line.strip()
                    if cleaned and cleaned not in warnings_out:
                        warnings_out.append(cleaned)
        return result.stdout

    def follow_tcp_raw(
        self,
        pcap_path: str | Path,
        stream_id: int,
        warnings_out: list[str] | None = None,
    ) -> list[tuple[int, bytes]]:
        """Return ordered chunks [(direction_0_or_1, raw_bytes), ...] for a TCP stream."""
        return self.follow_tcp_raw_batch(pcap_path, [stream_id], warnings_out=warnings_out).get(stream_id, [])

    def follow_tcp_raw_batch(
        self,
        pcap_path: str | Path,
        stream_ids: Sequence[int],
        warnings_out: list[str] | None = None,
        batch_size: int = 40,
    ) -> dict[int, list[tuple[int, bytes]]]:
        """Reconstruct multiple TCP streams efficiently using batched `-z follow,tcp,raw` calls."""
        path = self.validate_capture_path(pcap_path)
        streams: dict[int, list[tuple[int, bytes]]] = {}
        ids = list(stream_ids)
        if not ids:
            return streams

        for idx in range(0, len(ids), batch_size):
            batch = ids[idx : idx + batch_size]
            args: list[str] = ["-r", str(path), "-n", "-q"]
            for sid in batch:
                args.extend(["-z", f"follow,tcp,raw,{sid}"])
            stdout = self.run_command(args, warnings_out=warnings_out)
            self._parse_follow_tcp_raw_output(stdout, streams)
        return streams

    @staticmethod
    def _parse_follow_tcp_raw_output(
        stdout: str,
        out_streams: dict[int, list[tuple[int, bytes]]],
    ) -> None:
        current_stream: int | None = None
        in_body = False
        for line in stdout.splitlines():
            if line.startswith("Filter: tcp.stream eq "):
                try:
                    current_stream = int(line.split("Filter: tcp.stream eq ", 1)[1].strip())
                    out_streams.setdefault(current_stream, [])
                except ValueError:
                    current_stream = None
                in_body = False
                continue
            if line.startswith("Node 1:"):
                in_body = True
                continue
            if line.startswith("===="):
                in_body = False
                continue
            if not in_body or current_stream is None or not line.strip():
                continue
            direction = 1 if line.startswith("\t") else 0
            hex_part = line.strip()
            try:
                raw = bytes.fromhex(hex_part)
            except ValueError:
                continue
            if raw:
                out_streams[current_stream].append((direction, raw))

    def export_objects(
        self,
        pcap_path: str | Path,
        protocol: str,
        dest_dir: Path,
        warnings_out: list[str] | None = None,
    ) -> list[Path]:
        """Use TShark `--export-objects` to export objects for a given protocol (e.g., http)."""
        path = self.validate_capture_path(pcap_path)
        dest_dir.mkdir(parents=True, exist_ok=True)
        self.run_command(
            ["-r", str(path), "-n", "-q", "--export-objects", f"{protocol},{dest_dir}"],
            warnings_out=warnings_out,
        )
        return sorted(p for p in dest_dir.iterdir() if p.is_file())
