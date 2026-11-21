"""Main forensic analysis orchestrator for Packet Detective."""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path

from core.models import AnalysisReport, CaptureSummary
from core.tshark import TSharkRunner
from modules.dns_analyzer import extract_dns_records
from modules.file_extractor import extract_http_objects
from modules.flag_hunter import hunt_flags
from modules.ip_analyzer import analyze_network_traffic
from modules.tls_analyzer import extract_tls_records
from modules.traffic_detector import detect_suspicious_traffic
from modules.url_extractor import extract_http_records
from utils.regex_patterns import DEFAULT_FLAG_PREFIX, DEFAULT_MAX_FLAG_LENGTH

logger = logging.getLogger(__name__)


class PacketDetectiveAnalyzer:
    """Coordinates modular TShark-backed forensic extractors on a PCAP/PCAPNG file."""

    def __init__(
        self,
        tshark_path: str | None = None,
        max_flag_length: int = DEFAULT_MAX_FLAG_LENGTH,
        flag_prefix: str = DEFAULT_FLAG_PREFIX,
        timeout: int = 300,
    ) -> None:
        self.runner = TSharkRunner(tshark_path=tshark_path, timeout=timeout)
        self.max_flag_length = max_flag_length
        self.flag_prefix = flag_prefix

    def analyze(
        self,
        pcap_path: str | Path,
        output_dir: str | Path | None = None,
    ) -> AnalysisReport:
        """Analyze a PCAP or PCAPNG file and return a complete AnalysisReport."""
        capture = self.runner.validate_capture_path(pcap_path)
        file_size = capture.stat().st_size
        warnings: list[str] = []

        if file_size == 0:
            warnings.append("Capture file is empty (0 bytes); no packets to analyze.")
            summary = CaptureSummary(
                file_path=str(capture),
                file_size_bytes=0,
                total_packets=0,
                warnings=warnings,
            )
            return AnalysisReport(summary=summary, analysis_errors=list(warnings))

        logger.info("Starting network telemetry pass on %s", capture)
        telemetry = analyze_network_traffic(self.runner, capture, warnings=warnings)

        if telemetry.total_packets == 0:
            if not warnings:
                warnings.append("Capture contains 0 packets.")
            summary = CaptureSummary(
                file_path=str(capture),
                file_size_bytes=file_size,
                total_packets=0,
                warnings=warnings,
            )
            return AnalysisReport(summary=summary, network=telemetry.network, analysis_errors=list(warnings))

        logger.info("Extracting HTTP, DNS, and TLS intelligence")
        http_records, total_http_requests = extract_http_records(self.runner, capture, warnings=warnings)
        dns_records, total_dns_queries = extract_dns_records(self.runner, capture, warnings=warnings)
        tls_records, total_tls_sni = extract_tls_records(self.runner, capture, warnings=warnings)

        logger.info("Running heuristic suspicious traffic detector")
        suspicious_findings = detect_suspicious_traffic(telemetry, dns_records)

        if output_dir is not None:
            objects_dir = Path(output_dir) / "extracted_objects"
            extracted_objects = extract_http_objects(
                self.runner,
                capture,
                output_dir=objects_dir,
                warnings=warnings,
            )
            logger.info("Running flag hunter")
            flag_candidates = hunt_flags(
                self.runner,
                capture,
                stream_packets=telemetry.tcp_accumulator.stream_packets,
                stream_has_tls=telemetry.tcp_accumulator.stream_has_tls,
                exported_objects_dir=objects_dir,
                max_flag_length=self.max_flag_length,
                flag_prefix=self.flag_prefix,
                warnings=warnings,
            )
        else:
            with tempfile.TemporaryDirectory(prefix="pktdet_objs_") as tmp_obj_dir:
                tmp_objects_path = Path(tmp_obj_dir)
                extracted_objects = extract_http_objects(
                    self.runner,
                    capture,
                    output_dir=None,
                    warnings=warnings,
                )
                # Export once into tmp_objects_path for flag scanning when --output is omitted
                if extracted_objects:
                    self.runner.export_objects(capture, "http", tmp_objects_path, warnings_out=warnings)
                logger.info("Running flag hunter")
                flag_candidates = hunt_flags(
                    self.runner,
                    capture,
                    stream_packets=telemetry.tcp_accumulator.stream_packets,
                    stream_has_tls=telemetry.tcp_accumulator.stream_has_tls,
                    exported_objects_dir=tmp_objects_path,
                    max_flag_length=self.max_flag_length,
                    flag_prefix=self.flag_prefix,
                    warnings=warnings,
                )

        summary = CaptureSummary(
            file_path=str(capture),
            file_size_bytes=file_size,
            total_packets=telemetry.total_packets,
            protocols=list(telemetry.network.protocol_distribution.keys()),
            protocol_counts=telemetry.network.protocol_distribution,
            http_requests_count=total_http_requests,
            dns_queries_count=total_dns_queries,
            tls_hostnames_count=len(tls_records) if tls_records else total_tls_sni,
            unique_ip_count=len(telemetry.network.unique_ips),
            warnings=warnings,
        )

        return AnalysisReport(
            summary=summary,
            http_records=http_records,
            dns_records=dns_records,
            tls_records=tls_records,
            network=telemetry.network,
            suspicious_findings=suspicious_findings,
            extracted_objects=extracted_objects,
            flag_candidates=flag_candidates,
            analysis_errors=list(warnings),
        )
