 
import subprocess
import sys
import csv
import io


def extract(pcap, display_filter, fields):
    command = [
        "tshark",
        "-r", pcap,
        "-Y", display_filter,
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "quote=d",
    ]

    for field in fields:
        command.extend(["-e", field])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("TShark error:", result.stderr)
        return []

    return list(csv.reader(
        io.StringIO(result.stdout),
        delimiter="\t",
        quotechar='"'
    ))


def main(pcap):
    print("\n========== NETWORK FORENSICS ==========\n")

    # 1. HTTP URLs
    print("[+] HTTP REQUESTS")

    rows = extract(
        pcap,
        "http.request",
        [
            "ip.src",
            "ip.dst",
            "http.host",
            "http.request.uri"
        ]
    )

    for src, dst, host, uri in rows:
        if host:
            print(f"http://{host}{uri}")
            print(f"    {src} -> {dst}")

    # 2. DNS domains
    print("\n[+] DNS QUERIES")

    rows = extract(
        pcap,
        "dns.flags.response == 0",
        [
            "ip.src",
            "dns.qry.name"
        ]
    )

    for src, domain in rows:
        print(f"{domain}  (queried by {src})")

    # 3. HTTPS SNI hostnames
    print("\n[+] HTTPS HOSTNAMES (TLS SNI)")

    rows = extract(
        pcap,
        "tls.handshake.extensions_server_name",
        [
            "ip.src",
            "ip.dst",
            "tls.handshake.extensions_server_name"
        ]
    )

    for src, dst, hostname in rows:
        print(f"https://{hostname}")
        print(f"    {src} -> {dst}")

    print("\n========== ANALYSIS COMPLETE ==========")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python packet_detector.py capture.pcapng")
        sys.exit(1)

    main(sys.argv[1])
