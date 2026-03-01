from scapy.all import rdpcap, IP

# 1. Load the file you just created
packets = rdpcap("live_capture.pcap")
print(f"Analyzing {len(packets)} packets...")

# 2. Track how much data each IP sent
stats = {}

for packet in packets:
    if ARP in packet:
        src = packet[ARP]
    if IP in packet:
        src = packet[IP].src
        # Get the size of the packet
        stats[src] = stats.get(src, 0) + len(packet)

# 3. Print the results
print("\n--- Data Usage by IP ---")
for ip, size in sorted(stats.items(), key=lambda item: item[1], reverse=True):
    print(f"{ip}: {size} bytes")