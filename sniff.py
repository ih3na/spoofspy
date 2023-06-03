from scapy.all import *
import queue
import netifaces

# Class Queue initialization
class CapturedDataQueue:
    def __init__(self):
        self.queue = queue.Queue()

    def put(self, item):
        self.queue.put(item)

    def get(self):
        return self.queue.get()

    def empty(self):
        return self.queue.empty()

captured_data = CapturedDataQueue()  # Queue to store captured data

expected_interface = "enp3s0f3u1u1"  # Default interface

# Bogon ranges list
bogon_ranges = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "127.0.53.53",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",	
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",

    "::/128",	# Node-scope unicast unspecified address
    "::1/128",	# Node-scope unicast loopback address
    "::ffff:0:0/96",	# IPv4-mapped addresses
    "::/96",	# IPv4-compatible addresses
    "100::/64",	# Remotely triggered black hole addresses
    "2001:10::/28",	# Overlay routable cryptographic hash identifiers (ORCHID)
    "2001:db8::/32",	# Documentation prefix
    "fc00::/7",	#Unique local addresses (ULA)
    "fe80::/10",	#Link-local unicast
    "fec0::/10",	#Site-local unicast (deprecated)
    "ff00::/8",
    "2002::/24",	# 6to4 bogon (0.0.0.0/8)
    "2002:a00::/24",	# 6to4 bogon (10.0.0.0/8)
    "2002:7f00::/24",	# 6to4 bogon (127.0.0.0/8)
    "2002:a9fe::/32",	# 6to4 bogon (169.254.0.0/16)
    "2002:ac10::/28",	# 6to4 bogon (172.16.0.0/12)
    "2002:c000::/40",	# 6to4 bogon (192.0.0.0/24)
    "2002:c000:200::/40v",	# 6to4 bogon (192.0.2.0/24)
    "2002:c0a8::/32	6to4",	# bogon (192.168.0.0/16)
    "2002:c612::/31	6to4",	# bogon (198.18.0.0/15)
    "2002:c633:6400::/40",	# 6to4 bogon (198.51.100.0/24)
    "2002:cb00:7100::/40",	# 6to4 bogon (203.0.113.0/24)
    "2002:e000::/20	6to4",	# bogon (224.0.0.0/4)
    "2002:f000::/20	6to4",	# bogon (240.0.0.0/4)
    "2002:ffff:ffff::/48",	# 6to4 bogon (255.255.255.255/32)
    "2001::/40	Teredo bogon",	# (0.0.0.0/8)
    "2001:0:a00::/40",	# Teredo bogon (10.0.0.0/8)
    "2001:0:7f00::/40",	# Teredo bogon (127.0.0.0/8)
    "2001:0:a9fe::/48",	# Teredo bogon (169.254.0.0/16)
    "2001:0:ac10::/44",	# Teredo bogon (172.16.0.0/12)
    "2001:0:c000::/56",	# Teredo bogon (192.0.0.0/24)
    "2001:0:c000:200::/56",	# Teredo bogon (192.0.2.0/24)
    "2001:0:c0a8::/48",	# Teredo bogon (192.168.0.0/16)
    "2001:0:c612::/47",	# Teredo bogon (198.18.0.0/15)
    "2001:0:c633:6400::/56",	# Teredo bogon (198.51.100.0/24)
    "2001:0:cb00:7100::/56",	# Teredo bogon (203.0.113.0/24)
    "2001:0:e000::/36",	# Teredo bogon (224.0.0.0/4)
    "2001:0:f000::/36",	# Teredo bogon (240.0.0.0/4)
    "2001:0:ffff:ffff::/64",	# Teredo bogon (255.255.255.255/32)
]

# Assign protocol names by their numbers
def proto_name_by_num(proto_num):
    
    protocols = {
    0: "IP",
    1: "ICMP",
    2: "IGMP",
    3: "GGP",
    4: "IP-ENCAP",
    5: "ST",
    6: "TCP",
    8: "EGP",
    9: "IGP",
    12: "PUP",
    17: "UDP",
    20: "HMP",
    22: "XNS-IDP",
    27: "RDP",
    29: "ISO-TP4",
    33: "DCCP",
    132: "SCTP",
    136: "UDP-Lite",
    58: "ICMPv6",
    50: "ESP",
    51: "AH",
    47: "GRE",
    4: "IPIP",
    60: "TCPv6",
    99: "MTP",
    }
    
    for num in protocols.keys():
        if num == proto_num:
            return protocols.get(num)
        
    return "Protocol not found"


# Process captured packets
def process_packet(packet):
    
    # Captured packs malicious checkups
    if packet.haslayer(IP):
        # Extract IP information from the packet
        source_ip = packet[IP].src
        expected_ip = netifaces.ifaddresses(expected_interface)[netifaces.AF_INET][0]['addr']
        destination_ip = packet[IP].dst
        protocol = packet[IP].proto
        protocol_name = proto_name_by_num(protocol) 
        
        #Perform RPF check
        if source_ip != expected_ip:
            captured_data.put("Potential IP spoofing detected: RPF check failed!")

        # Perform Bogon filtering
        for bogon_range in bogon_ranges:
            if source_ip in bogon_range:
                captured_data.put("Potential IP spoofing detected: Bogon filter matched!")

    # Store the packet data for display on the web page
    captured_data.put(f"Source IP: {source_ip}")
    captured_data.put(f"Destination IP: {destination_ip}")
    captured_data.put(f"Protocol: {protocol_name}")
    
    data = []
    while not (captured_data.empty()):
        data.append(captured_data.get())
    for unit in data:
        print(str(unit)+"\n")
    print("*********************")

if __name__ == "__main__":
    sniff(filter="ip", prn=process_packet, iface=expected_interface) # Start sniffing packets on the network interface
