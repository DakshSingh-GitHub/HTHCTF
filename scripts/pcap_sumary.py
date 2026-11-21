
#!/usr/bin/env python3
from scapy.all import rdpcap, IP, TCP, UDP, DNS
import sys
from collections import Counter

packets = rdpcap(sys.argv[1])

protocols = Counter()
ips = Counter()
ports = Counter()

for pkt in packets:
    if IP in pkt:
        ips[pkt[IP].src] += 1
        ips[pkt[IP].dst] += 1

    if TCP in pkt:
        protocols["TCP"] += 1
        ports[pkt[TCP].dport] += 1
    elif UDP in pkt:
        protocols["UDP"] += 1
        ports[pkt[UDP].dport] += 1

    if DNS in pkt:
        protocols["DNS"] += 1

print("Total packets:", len(packets))
print("\nProtocols:", protocols)
print("\nTop IPs:", ips.most_common(15))
print("\nDestination ports:", ports.most_common(15))
