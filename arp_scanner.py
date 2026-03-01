from scapy.all import *

# Change this to your network's subnet
# Find it with 'ifconfig' (e.g., 192.168.0.0/24)
TARGET_SUBNET = "128.0.0.0/24" 
# You must get this right! 
# If your IP is 10.0.0.5, your subnet is "10.0.0.0/24"

print(f"Scanning LAN for subnet {TARGET_SUBNET}...")

# We need to build a packet at Layer 2
# 1. Ethernet "broadcast" frame (dst=ff:ff:ff:ff:ff:ff)
eth_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

# 2. ARP request packet
# pdst = "packet destination" (the IP range we want to scan)
arp_req = ARP(pdst=TARGET_SUBNET)

# 3. Stack them
broadcast_packet = eth_frame / arp_req

# 4. Send and receive (srp)
# srp() is for Layer 2. It returns two lists:
# ans = answered packets
# unans = unanswered packets
# We set a 2-second timeout and verbose=0 to hide Scapy's noise.
ans, unans = srp(broadcast_packet, timeout=2, verbose=0)

print("\nScan Complete. Hosts found:")
print("IP Address\t\tMAC Address")
print("-----------------------------------------")

# The 'ans' list is a list of (sent, received) tuples.
# We iterate through it and pull out the data we need.
hosts = []
for sent_packet, received_packet in ans:
    ip = received_packet[ARP].psrc       # Sender's IP
    mac = received_packet[Ether].src    # Sender's MAC
    hosts.append({'ip': ip, 'mac': mac})

# Sort by IP for a clean list
hosts.sort(key=lambda x: [int(y) for y in x['ip'].split('.')])

for host in hosts:
    print(f"{host['ip'].ljust(16)}\t{host['mac']}")

print(f"\nFound {len(hosts)} hosts.")