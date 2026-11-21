"""Pure-Python synthetic binary PCAP builders for deterministic TShark tests."""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

PCAP_GLOBAL_HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def _checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _eth_header(src_mac: bytes = b"\x00\x11\x22\x33\x44\x55", dst_mac: bytes = b"\x66\x77\x88\x99\xaa\xbb") -> bytes:
    return dst_mac + src_mac + b"\x08\x00"


def _ipv4_packet(src_ip: str, dst_ip: str, proto: int, payload: bytes, ip_id: int = 1) -> bytes:
    src = ipaddress.IPv4Address(src_ip).packed
    dst = ipaddress.IPv4Address(dst_ip).packed
    total_len = 20 + len(payload)
    header_wo_csum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        ip_id & 0xFFFF,
        0x4000,
        64,
        proto,
        0,
        src,
        dst,
    )
    csum = _checksum(header_wo_csum)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        ip_id & 0xFFFF,
        0x4000,
        64,
        proto,
        csum,
        src,
        dst,
    )
    return _eth_header() + header + payload


def build_tcp_frame(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int = 1,
    ack: int = 0,
    flags: int = 0x18,  # PSH+ACK
    payload: bytes = b"",
    ip_id: int = 1,
) -> bytes:
    src_b = ipaddress.IPv4Address(src_ip).packed
    dst_b = ipaddress.IPv4Address(dst_ip).packed
    tcp_len = 20 + len(payload)
    tcp_wo_csum = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        5 << 4,
        flags,
        65535,
        0,
        0,
    )
    pseudo = struct.pack("!4s4sBBH", src_b, dst_b, 0, 6, tcp_len)
    csum = _checksum(pseudo + tcp_wo_csum + payload)
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        5 << 4,
        flags,
        65535,
        csum,
        0,
    )
    return _ipv4_packet(src_ip, dst_ip, 6, tcp_hdr + payload, ip_id=ip_id)


def build_udp_frame(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
    ip_id: int = 1,
) -> bytes:
    src_b = ipaddress.IPv4Address(src_ip).packed
    dst_b = ipaddress.IPv4Address(dst_ip).packed
    udp_len = 8 + len(payload)
    udp_wo_csum = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    pseudo = struct.pack("!4s4sBBH", src_b, dst_b, 0, 17, udp_len)
    csum = _checksum(pseudo + udp_wo_csum + payload) or 0xFFFF
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, csum)
    return _ipv4_packet(src_ip, dst_ip, 17, udp_hdr + payload, ip_id=ip_id)


def _encode_dns_name(domain: str) -> bytes:
    parts = [p.encode("ascii") for p in domain.strip(".").split(".") if p]
    return b"".join(bytes([len(p)]) + p for p in parts) + b"\x00"


def build_dns_query_payload(txid: int, domain: str, qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = _encode_dns_name(domain) + struct.pack("!HH", qtype, 1)
    return header + question


def build_dns_a_response_payload(txid: int, domain: str, resolved_ip: str, ttl: int = 300) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    qname = _encode_dns_name(domain)
    question = qname + struct.pack("!HH", 1, 1)
    rdata = ipaddress.IPv4Address(resolved_ip).packed
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + rdata
    return header + question + answer


def build_tls_client_hello_payload(sni: str) -> bytes:
    sni_bytes = sni.encode("ascii")
    sni_entry = struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    extensions = struct.pack("!H", len(sni_ext)) + sni_ext

    body = (
        b"\x03\x03"  # Client version TLS 1.2
        + (b"\x11" * 32)  # Random
        + b"\x00"  # Session ID length
        + struct.pack("!HH", 2, 0x1301)  # Cipher suite TLS_AES_128_GCM_SHA256
        + struct.pack("!BB", 1, 0)  # Compression methods: null
        + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record


def build_tcp_stream_exchange(
    client_ip: str,
    server_ip: str,
    client_port: int,
    server_port: int,
    client_segments: list[bytes],
    server_segments: list[bytes] | None = None,
    start_ip_id: int = 100,
) -> list[bytes]:
    """Generate a valid TCP 3-way handshake + segmented data + FIN exchange."""
    frames: list[bytes] = []
    c_seq = 1000
    s_seq = 5000
    ip_id = start_ip_id

    # SYN
    frames.append(build_tcp_frame(client_ip, server_ip, client_port, server_port, seq=c_seq, ack=0, flags=0x02, ip_id=ip_id))
    ip_id += 1
    c_seq += 1

    # SYN-ACK
    frames.append(build_tcp_frame(server_ip, client_ip, server_port, client_port, seq=s_seq, ack=c_seq, flags=0x12, ip_id=ip_id))
    ip_id += 1
    s_seq += 1

    # ACK
    frames.append(build_tcp_frame(client_ip, server_ip, client_port, server_port, seq=c_seq, ack=s_seq, flags=0x10, ip_id=ip_id))
    ip_id += 1

    for seg in client_segments:
        frames.append(
            build_tcp_frame(
                client_ip,
                server_ip,
                client_port,
                server_port,
                seq=c_seq,
                ack=s_seq,
                flags=0x18,
                payload=seg,
                ip_id=ip_id,
            )
        )
        ip_id += 1
        c_seq += len(seg)

    for seg in (server_segments or []):
        frames.append(
            build_tcp_frame(
                server_ip,
                client_ip,
                server_port,
                client_port,
                seq=s_seq,
                ack=c_seq,
                flags=0x18,
                payload=seg,
                ip_id=ip_id,
            )
        )
        ip_id += 1
        s_seq += len(seg)

    # FIN-ACK
    frames.append(build_tcp_frame(client_ip, server_ip, client_port, server_port, seq=c_seq, ack=s_seq, flags=0x11, ip_id=ip_id))
    return frames


def write_pcap(path: Path, frames: list[bytes], start_ts: int = 1700000000) -> Path:
    """Write Ethernet frames into a standard little-endian .pcap file."""
    chunks = [PCAP_GLOBAL_HEADER]
    for idx, frame in enumerate(frames):
        ts_sec = start_ts + idx // 10
        ts_usec = (idx % 10) * 100000
        pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame))
        chunks.append(pkt_hdr + frame)
    path.write_bytes(b"".join(chunks))
    return path
