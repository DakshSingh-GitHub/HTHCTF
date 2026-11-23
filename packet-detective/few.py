# data = open("spin.pcapng", "rb").read()
# import re
# for m in re.finditer(b"(POST /relay|GET /drop/L1-SPINNER\\.bin)", data):
#     start = max(0, m.start() - 40)
#     print("="*50)
#     print(data[start:start+700])

import base64
import re

with open("spin.pcapng", "rb") as f:
    pcap_data = f.read()

# Match every POST /relay HTTP request and capture the Base64 block after BODY:
pattern = re.compile(rb"POST /relay.*?BODY:\r?\n([A-Za-z0-9+/=\r\n]+)", re.DOTALL)
matches = pattern.findall(pcap_data)

print(f"Found {len(matches)} relay payload(s):\n")

for i, raw_b64 in enumerate(matches, start=1):
    # Strip newlines/whitespace before decoding
    cleaned_b64 = b"".join(raw_b64.split())
    decoded_text = base64.b64decode(cleaned_b64).decode("utf-8", errors="replace")

    print(f"{'=' * 20} RELAY #{i} {'=' * 20}")
    print(decoded_text.strip())

    # Highlight any HTH3{...} flag candidates
    flags = re.findall(r"HTH3\{[^}]+\}", decoded_text)
    if flags:
        print(f"\n[!] Flag candidate: {flags[0]}")
    print()
