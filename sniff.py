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
    "127.0.0.0/8",


    "::/128",
    "fe80::/10",

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
