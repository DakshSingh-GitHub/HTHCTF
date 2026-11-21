# Packet Detective

**Packet Detective** is a modular Python 3.11+ command-line network forensics and CTF analysis toolkit powered by **TShark**. It inspects offline `.pcap` and `.pcapng` captures to extract URL/domain intelligence, analyze IP/TCP/UDP conversations, flag heuristic anomalies, extract HTTP objects safely, and hunt for `HTH3{...}` flag candidates across packet layers and reconstructed TCP streams.

## Requirements

- **Python 3.11+**
- **TShark** (Wireshark CLI) installed and available on `PATH` (or at `/Applications/Wireshark.app/Contents/MacOS/tshark` on macOS)

### Installing TShark

- **macOS (Homebrew):** `brew install --cask wireshark`
- **Ubuntu / Debian:** `sudo apt-get update && sudo apt-get install -y tshark`
- **Fedora / RHEL:** `sudo dnf install -y wireshark-cli`
- **Windows (winget):** `winget install WiresharkFoundation.Wireshark`

## Usage

Analyze a capture file in the terminal:

```bash
python3 packet_detective.py analyze capture.pcapng
```

Analyze and export full reports (`report.txt`, `report.json`, `urls.csv`, `domains.csv`, `flags.txt`, and `extracted_objects/`):

```bash
python3 packet_detective.py analyze capture.pcapng --output results/
```

Customize flag matching options:

```bash
python3 packet_detective.py analyze capture.pcapng --max-flag-length 1024 --flags-only
```

## Architecture

```
packet-detective/
├── packet_detective.py      # CLI entry point
├── requirements.txt
├── README.md
├── core/
│   ├── analyzer.py          # Main forensic orchestration pipeline
│   ├── models.py            # Typed dataclasses for report sections
│   └── tshark.py            # Safe streaming TShark subprocess wrapper
├── modules/
│   ├── url_extractor.py     # HTTP URL, header, and query param extraction
│   ├── dns_analyzer.py      # DNS query and resolution analysis
│   ├── tls_analyzer.py      # TLS SNI & handshake metadata extraction
│   ├── ip_analyzer.py       # Streaming IP/port/protocol telemetry
│   ├── tcp_analyzer.py      # TCP/UDP conversations & retrans/RST/SYN analysis
│   ├── flag_hunter.py       # HTH3{...} flag discovery & TCP stream reassembly
│   ├── traffic_detector.py  # Heuristic suspicious traffic detector
│   └── file_extractor.py    # Safe HTTP object extraction
├── reporting/
│   ├── console.py           # Colored/plain terminal formatting
│   ├── json_report.py       # JSON report writer
│   └── exporters.py         # TXT, CSV, and standalone flags.txt exporters
├── utils/
│   ├── regex_patterns.py    # Configurable HTH3 flag regex builder
│   └── helpers.py           # Decoding, sanitization, and formatting helpers
└── tests/
    ├── fixtures.py          # Synthetic binary PCAP generators
    └── test_packet_detective.py
```

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```

## Security & Forensics Notes

- Capture files are treated as untrusted input. TShark is invoked via `subprocess` argument lists without `shell=True`.
- Extracted HTTP objects are filename-sanitized, deduplicated, and never executed.
- Encrypted TLS/HTTPS application payloads are **not** claimed to be inspected as plaintext; only unencrypted handshake metadata (such as SNI hostnames) is extracted unless TLS decryption is separately configured.
