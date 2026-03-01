from scapy.all import *
import os
import argparse

def analyze_pcap(file_path):

    if not os.path.exists(file_path):
        print(f"[!] Error: The file {file_path} does not exist.")
        return

    print(f"[*] Reading {file_path}...")
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        print(f"[!] Failed to read pcap: {e}")
        return
        
    print(f"Analyzing {len(packets)} packets...")

    IP_Stats = {}
    domains_visited = {}

    for packet in packets:
        if IP in packet:
            src = packet[IP].src
            # Calculate data usage
            IP_Stats[src] = IP_Stats.get(src, 0) + len(packet)

            # List up domains visited
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
        
def main():
    parser = argparse.ArgumentParser(description="Analyze a PCAP file for traffic stats.")
    parser.add_argument(
        "-i", "--input", 
        help="The path to the .pcap file to analyze."
        )
    
    args = parser.parse_args()
    analyze_pcap(args.input)

if __name__ == "__main__":
    main()