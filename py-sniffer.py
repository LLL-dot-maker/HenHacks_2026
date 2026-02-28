#!/usr/bin/env python3
# pcap_writer.py

import argparse
from scapy.all import *

PCAP_FILE = "live_capture.pcap"

def process_packet_and_save(packet):
    """
    This function will be called for each packet sniffed.
    """
    # ARP-based traffic
    if ARP in packet:
        print(f"[ARP] {packet[ARP].psrc} is at {packet[ARP].hwsrc}")
        return

    # IP-based traffic
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # ----- DNS  -----
        if DNS in packet:
            if packet[DNS].qr == 0:  # 0 = query, 1 = response
                if DNSQR in packet:
                    domain = packet[DNSQR].qname.decode(errors="ignore")
                    print(f"[DNS Query] {src_ip} -> {domain}")

        # ----- TCP -----
        if TCP in packet:
            print(f"[TCP] {src_ip}:{packet[TCP].sport} -> "
                  f"{dst_ip}:{packet[TCP].dport} "
                  f"[Flags: {packet[TCP].flags}]")

        # ----- UDP -----
        elif UDP in packet:
            print(f"[UDP] {src_ip}:{packet[UDP].sport} -> "
                  f"{dst_ip}:{packet[UDP].dport}")

        # ----- ICMP -----
        elif ICMP in packet:
            print(f"[ICMP] {src_ip} -> {dst_ip}")
    wrpcap(PCAP_FILE,packet,append = True)

def main():
    # 1. Create the argument parser
    parser = argparse.ArgumentParser(
        description="A simple Python network sniffer using Scapy.",
        epilog="Example: python py-sniffer.py -i eth0 -f 'tcp and port 80' -c 10"
    )
    # 2. Add arguments
    parser.add_argument(
        "-i", "--interface",
        type=str,
        help="Network interface to sniff on (e.g., 'Wi-Fi', 'Ethernet')."
    )
    parser.add_argument(
        "-f", "--filter",
        type=str,
        default=None,
        help="BPF filter string (e.g., 'tcp and port 80')."
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 for unlimited)."
    )
    # 3. Parse the arguments
    args = parser.parse_args()
    
    # 4. Validate and use arguments
    iface = args.interface
    bpf_filter = args.filter
    count = args.count

    if iface:
        print(f"[*] Sniffing on interface: {iface}")
    else:
        print("[*] Sniffing on default interface (conf.iface)")

    if bpf_filter:
        print(f"[*] Applying BPF filter: {bpf_filter}")
    
    if count > 0:
        print(f"[*] Capturing {count} packets...")
    else:
        print("[*] Capturing packets... Press Ctrl+C to stop and save)")
    
    # 5. Build the sniff() call
    sniff_args = {
        'store': 0,
        'prn': process_packet_and_save,
        'count': count
    }
    
    if iface:
        sniff_args['iface'] = iface
    if bpf_filter:
        sniff_args['filter'] = bpf_filter
    
    # 6. Run the sniffer
    try:
        sniff(**sniff_args)
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")  
        print("[!] Hint: Do you need to run as root/admin?")
        print("[!] Hint: Is the interface name correct? (use 'ifconfig' or 'ipconfig')")


# Make sure we only run main() when the script is executed directly
if __name__ == "__main__":
    main()