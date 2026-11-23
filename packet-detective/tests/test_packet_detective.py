"""Unit and integration tests for Packet Detective."""

from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

import packet_detective
from core.analyzer import PacketDetectiveAnalyzer
from core.tshark import TSharkNotFoundError, find_tshark_binary
from reporting.exporters import export_all_reports
from tests.fixtures import (
    PCAP_GLOBAL_HEADER,
    build_dns_a_response_payload,
    build_dns_query_payload,
    build_tcp_frame,
    build_tcp_stream_exchange,
    build_tls_client_hello_payload,
    build_udp_frame,
    write_pcap,
)


class PacketDetectiveTestSuite(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_http_dns_tls_extraction_and_deduplication(self) -> None:
        frames: list[bytes] = []

        # DNS query + response
        frames.append(
            build_udp_frame(
                "10.0.0.5",
                "10.0.0.1",
                55100,
                53,
                build_dns_query_payload(0x1234, "portal.ctf.local"),
                ip_id=1,
            )
        )
        frames.append(
            build_udp_frame(
                "10.0.0.1",
                "10.0.0.5",
                53,
                55100,
                build_dns_a_response_payload(0x1234, "portal.ctf.local", "192.168.50.10"),
                ip_id=2,
            )
        )

        # Duplicate HTTP requests to test deduplication + HTTP object response
        http_req = (
            b"GET /download/clue.txt?token=abc123&mode=raw HTTP/1.1\r\n"
            b"Host: portal.ctf.local\r\n"
            b"Referer: http://portal.ctf.local/index.html\r\n"
            b"User-Agent: PacketDetectiveTest/1.0\r\n\r\n"
        )
        http_resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: 24\r\n\r\n"
            b"HTH3{http_object_secret}"
        )
        frames.extend(
            build_tcp_stream_exchange(
                "10.0.0.5",
                "192.168.50.10",
                41001,
                80,
                [http_req],
                [http_resp],
                start_ip_id=10,
            )
        )
        frames.extend(
            build_tcp_stream_exchange(
                "10.0.0.5",
                "192.168.50.10",
                41002,
                80,
                [http_req],
                [http_resp],
                start_ip_id=30,
            )
        )

        # TLS ClientHello with SNI
        frames.extend(
            build_tcp_stream_exchange(
                "10.0.0.5",
                "93.184.216.34",
                42000,
                443,
                [build_tls_client_hello_payload("secure.example.org")],
                [],
                start_ip_id=50,
            )
        )

        pcap = write_pcap(self.tmp_path / "intel.pcap", frames)
        out_dir = self.tmp_path / "out"
        analyzer = PacketDetectiveAnalyzer()
        report = analyzer.analyze(pcap, output_dir=out_dir)
        exported = export_all_reports(report, out_dir)

        # HTTP assertions
        self.assertEqual(report.summary.http_requests_count, 2)
        self.assertEqual(len(report.http_records), 1)  # deduplicated
        http_rec = report.http_records[0]
        self.assertEqual(http_rec.method, "GET")
        self.assertEqual(http_rec.host, "portal.ctf.local")
        self.assertEqual(http_rec.full_url, "http://portal.ctf.local/download/clue.txt?token=abc123&mode=raw")
        self.assertEqual(http_rec.query_params, {"token": ["abc123"], "mode": ["raw"]})
        self.assertEqual(http_rec.referer, "http://portal.ctf.local/index.html")
        self.assertEqual(http_rec.user_agent, "PacketDetectiveTest/1.0")
        self.assertEqual(http_rec.count, 2)
        self.assertEqual(len(http_rec.packet_numbers), 2)

        # DNS assertions
        self.assertEqual(report.summary.dns_queries_count, 1)
        self.assertEqual(len(report.dns_records), 1)
        dns_rec = report.dns_records[0]
        self.assertEqual(dns_rec.query_name, "portal.ctf.local")
        self.assertIn("192.168.50.10", dns_rec.resolved_ips)

        # TLS SNI assertions
        self.assertEqual(len(report.tls_records), 1)
        self.assertEqual(report.tls_records[0].sni, "secure.example.org")
        self.assertIn("encrypted", report.tls_records[0].note.lower())

        # File extraction + duplicate handling assertions
        self.assertEqual(len(report.extracted_objects), 2)
        extracted_paths = {Path(obj.output_path).name for obj in report.extracted_objects}
        self.assertEqual(len(extracted_paths), 2)
        for obj in report.extracted_objects:
            self.assertTrue(Path(obj.output_path).exists())
            self.assertEqual(obj.host, "portal.ctf.local")

        # Export assertions
        self.assertTrue(exported["report_txt"].exists())
        self.assertTrue(exported["report_json"].exists())
        self.assertTrue(exported["urls_csv"].exists())
        self.assertTrue(exported["domains_csv"].exists())
        self.assertTrue(exported["flags_txt"].exists())

        parsed_json = json.loads(exported["report_json"].read_text(encoding="utf-8"))
        self.assertEqual(parsed_json["summary"]["http_requests_count"], 2)
        with exported["urls_csv"].open(encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["full_url"], "http://portal.ctf.local/download/clue.txt?token=abc123&mode=raw")

    def test_flag_hunting_multiple_case_insensitive_dedup_and_fragmented(self) -> None:
        frames: list[bytes] = []

        # Stream 0: Multiple flags + case-insensitive prefix + duplicate flag in UDP
        multi_payload = (
            b"prefix HTH3{first_multi_flag} middle "
            b"hth3{lowercase_prefix_99} tail "
            b"Hth3{MiXeD_Case-Flag!}"
        )
        frames.extend(
            build_tcp_stream_exchange(
                "10.1.1.10",
                "10.1.1.20",
                50001,
                9000,
                [multi_payload],
                [],
                start_ip_id=100,
            )
        )

        # Duplicate exact match of HTH3{first_multi_flag} in UDP payload
        frames.append(
            build_udp_frame(
                "10.1.1.10",
                "10.1.1.20",
                50002,
                9001,
                b"dup copy: HTH3{first_multi_flag}",
                ip_id=150,
            )
        )

        # Stream 1: Flag split across 3 TCP segments!
        frames.extend(
            build_tcp_stream_exchange(
                "10.1.1.11",
                "10.1.1.21",
                50003,
                9002,
                [b"banner...\nHTH3{split_", b"across_three_", b"tcp_segments}\nbye"],
                [b"OK\n"],
                start_ip_id=200,
            )
        )

        pcap = write_pcap(self.tmp_path / "flags.pcap", frames)
        analyzer = PacketDetectiveAnalyzer()
        report = analyzer.analyze(pcap)

        by_value = {c.value: c for c in report.flag_candidates}
        self.assertIn("HTH3{first_multi_flag}", by_value)
        self.assertIn("hth3{lowercase_prefix_99}", by_value)
        self.assertIn("Hth3{MiXeD_Case-Flag!}", by_value)
        self.assertIn("HTH3{split_across_three_tcp_segments}", by_value)

        # Duplicate exact match should be deduplicated into one candidate with occurrences >= 2
        self.assertEqual(len(by_value), 4)
        self.assertGreaterEqual(by_value["HTH3{first_multi_flag}"].occurrences, 2)
        self.assertFalse(by_value["HTH3{first_multi_flag}"].reconstructed)

        # Fragmented flag must be marked as reconstructed
        frag = by_value["HTH3{split_across_three_tcp_segments}"]
        self.assertTrue(frag.reconstructed)
        self.assertIn("Reconstructed TCP Stream", frag.source)
        self.assertEqual(frag.confidence, "Candidate")

    def test_out_of_order_tcp_reassembly_and_encoded_protocol_flags(self) -> None:
        frames: list[bytes] = []

        # Build an out-of-order TCP stream: segment 2 arrives BEFORE segment 1!
        seg1 = b"HTH3{out_of_"
        seg2 = b"order_reassembly}"
        c_seq = 1000
        s_seq = 5000
        frames.append(build_tcp_frame("10.3.3.1", "10.3.3.2", 52000, 9500, seq=c_seq, ack=0, flags=0x02, ip_id=1))
        frames.append(build_tcp_frame("10.3.3.2", "10.3.3.1", 9500, 52000, seq=s_seq, ack=c_seq + 1, flags=0x12, ip_id=2))
        frames.append(build_tcp_frame("10.3.3.1", "10.3.3.2", 52000, 9500, seq=c_seq + 1, ack=s_seq + 1, flags=0x10, ip_id=3))
        # Out-of-order: send seg2 (seq = c_seq + 1 + len(seg1)) before seg1 (seq = c_seq + 1)
        frames.append(
            build_tcp_frame(
                "10.3.3.1",
                "10.3.3.2",
                52000,
                9500,
                seq=c_seq + 1 + len(seg1),
                ack=s_seq + 1,
                flags=0x18,
                payload=seg2,
                ip_id=4,
            )
        )
        frames.append(
            build_tcp_frame(
                "10.3.3.1",
                "10.3.3.2",
                52000,
                9500,
                seq=c_seq + 1,
                ack=s_seq + 1,
                flags=0x18,
                payload=seg1,
                ip_id=5,
            )
        )

        # HTTP request with URL-encoded flag in URI and Base64-encoded flag in body
        import base64

        b64_flag = base64.b64encode(b"HTH3{base64_http_body}").decode("ascii")
        http_req = (
            f"POST /submit?flag=HTH3%7Burl_encoded_param%7D HTTP/1.1\r\n"
            f"Host: ctf.internal\r\n"
            f"Content-Length: {len(b64_flag)}\r\n\r\n"
            f"{b64_flag}"
        ).encode("ascii")
        frames.extend(
            build_tcp_stream_exchange(
                "10.3.3.1",
                "10.3.3.3",
                52001,
                80,
                [http_req],
                [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"],
                start_ip_id=20,
            )
        )

        pcap = write_pcap(self.tmp_path / "ooo_encoded.pcap", frames)
        report = PacketDetectiveAnalyzer().analyze(pcap)
        by_value = {c.value: c for c in report.flag_candidates}

        self.assertIn("HTH3{out_of_order_reassembly}", by_value)
        self.assertTrue(by_value["HTH3{out_of_order_reassembly}"].reconstructed)
        self.assertIn("HTH3{url_encoded_param}", by_value)
        self.assertIn("HTH3{base64_http_body}", by_value)

    def test_max_flag_length_configuration(self) -> None:
        long_flag = "HTH3{" + ("a" * 80) + "}"
        short_flag = "HTH3{short_ok}"
        frames = [
            build_udp_frame("10.0.0.1", "10.0.0.2", 40000, 40001, f"{short_flag} {long_flag}".encode(), ip_id=1)
        ]
        pcap = write_pcap(self.tmp_path / "maxlen.pcap", frames)

        analyzer_capped = PacketDetectiveAnalyzer(max_flag_length=20)
        report_capped = analyzer_capped.analyze(pcap)
        values = {c.value for c in report_capped.flag_candidates}
        self.assertEqual(values, {short_flag})

    def test_suspicious_traffic_heuristics(self) -> None:
        frames: list[bytes] = []
        # Port scan: 12 distinct destination ports SYN from 10.9.9.9
        for idx, port in enumerate(range(1000, 1012), start=1):
            frames.append(
                build_tcp_frame("10.9.9.9", "10.9.9.10", 51000 + idx, port, seq=idx, flags=0x02, ip_id=idx)
            )
        # Suspiciously long DNS label (> 40 chars)
        long_label = "a" * 48
        frames.append(
            build_udp_frame(
                "10.9.9.9",
                "8.8.8.8",
                52000,
                53,
                build_dns_query_payload(0x9999, f"{long_label}.exfil.example.com"),
                ip_id=99,
            )
        )
        pcap = write_pcap(self.tmp_path / "suspicious.pcap", frames)
        report = PacketDetectiveAnalyzer().analyze(pcap)

        categories = {f.category for f in report.suspicious_findings}
        self.assertIn("Port Scan Heuristic", categories)
        self.assertIn("Suspicious DNS", categories)

    def test_malformed_truncated_pcap_handled_gracefully(self) -> None:
        valid_frame = build_udp_frame("10.0.0.1", "10.0.0.2", 1234, 5678, b"HTH3{before_corruption}", ip_id=1)
        pcap = write_pcap(self.tmp_path / "truncated.pcap", [valid_frame])
        # Append a truncated packet record header claiming 500 bytes but only providing 12
        corrupted = pcap.read_bytes() + b"\x00\x00\x00\x00\x00\x00\x00\x00\xf4\x01\x00\x00\xf4\x01\x00\x00" + (b"\xff" * 12)
        pcap.write_bytes(corrupted)

        report = PacketDetectiveAnalyzer().analyze(pcap)
        self.assertGreaterEqual(report.summary.total_packets, 1)
        self.assertTrue(any(c.value == "HTH3{before_corruption}" for c in report.flag_candidates))
        self.assertTrue(len(report.summary.warnings) >= 1)

    def test_empty_captures(self) -> None:
        zero_byte = self.tmp_path / "zero.pcap"
        zero_byte.write_bytes(b"")
        report_zero = PacketDetectiveAnalyzer().analyze(zero_byte)
        self.assertEqual(report_zero.summary.total_packets, 0)
        self.assertEqual(report_zero.flag_candidates, [])

        header_only = self.tmp_path / "empty_valid.pcap"
        header_only.write_bytes(PCAP_GLOBAL_HEADER)
        report_empty = PacketDetectiveAnalyzer().analyze(header_only)
        self.assertEqual(report_empty.summary.total_packets, 0)
        self.assertEqual(report_empty.flag_candidates, [])

    def test_large_capture_streaming(self) -> None:
        # 2,500 UDP packets + embedded flag near the end
        frames = [
            build_udp_frame("10.2.0.1", "10.2.0.2", 30000 + (i % 100), 8125, b"metric:ok", ip_id=i + 1)
            for i in range(2500)
        ]
        frames.append(build_udp_frame("10.2.0.1", "10.2.0.2", 31000, 8125, b"HTH3{large_stream_end}", ip_id=2600))
        pcap = write_pcap(self.tmp_path / "large.pcap", frames)

        report = PacketDetectiveAnalyzer().analyze(pcap)
        self.assertEqual(report.summary.total_packets, 2501)
        self.assertTrue(any(c.value == "HTH3{large_stream_end}" for c in report.flag_candidates))

    def test_custom_flag_prefix_override(self) -> None:
        frame = build_udp_frame("10.0.0.1", "10.0.0.2", 1234, 5678, b"CUSTOM{flag_with_different_prefix}", ip_id=1)
        pcap = write_pcap(self.tmp_path / "custom.pcap", [frame])
        analyzer = PacketDetectiveAnalyzer(flag_prefix="CUSTOM")
        report = analyzer.analyze(pcap)
        self.assertTrue(any(c.value == "CUSTOM{flag_with_different_prefix}" for c in report.flag_candidates))

    def test_missing_tshark_raises_with_install_instructions(self) -> None:
        with mock.patch("core.tshark.shutil.which", return_value=None), mock.patch(
            "core.tshark.os.path.isfile", return_value=False
        ):
            with self.assertRaises(TSharkNotFoundError) as ctx:
                find_tshark_binary()
            msg = str(ctx.exception)
            self.assertIn("brew install", msg)
            self.assertIn("apt-get install", msg)

        # CLI exit code check when TShark is missing
        pcap = write_pcap(self.tmp_path / "dummy.pcap", [])
        with mock.patch("core.tshark.shutil.which", return_value=None), mock.patch(
            "core.tshark.os.path.isfile", return_value=False
        ):
            rc = packet_detective.main(["analyze", str(pcap), "--no-color"])
            self.assertEqual(rc, 3)


if __name__ == "__main__":
    unittest.main()
