from scapy.all import *

packets = rdpcap("live_capture.pcap")
print(f"Analyzing {len(packets)} packets...")

IP_Stats = {}
domains_visited = {}

for packet in packets:
    if IP in packet:
        src = packet[IP].src
        # Get the size of the packet
        IP_Stats[src] = IP_Stats.get(src, 0) + len(packet)
        if DNS in packet and packet[DNS].qr == 0:  
                if DNSQR in packet:
                    domain = packet[DNSQR].qname.decode(errors="ignore")
                    domains_visited[domain] = domains_visited.get(domain, 0) + 1


# Data usage separated by IP
print("\n--- Data Usage by IP ---")
for ip, size in sorted(IP_Stats.items(), key=lambda item: item[1], reverse=True):
    print(f"{ip}: {size} bytes")

# Domains visited
print("\n--- Domains Visited ---")
if domains_visited:
    for domain, count in sorted(domains_visited.items(), key=lambda item: item[1], reverse=True):
        print(f"{count} requests -> {domain}")
else:
    print("No DNS queries found in this capture.")
# ARP requests