from scapy.all import IP, UDP, TCP, Ether, wrpcap
import random

src_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
dst_ips = ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"]
protocols = ["TCP", "UDP"]
packet_count = 100
packets = []

for _ in range(packet_count):
    src = random.choice(src_ips)
    dst = random.choice(dst_ips)
    proto = random.choice(protocols)
    sport = random.randint(1024, 65535)
    dport = random.choice([80, 443, 53, 22, 5000, 8080])
    if proto == "TCP":
        pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport)
    else:
        pkt = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)
    packets.append(pkt)

wrpcap("sample_complex_flows.pcap", packets)
print("✅ Generated sample_complex_flows.pcap with 100 packets.")
