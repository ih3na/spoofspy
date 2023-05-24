from scapy.all import *
import netifaces

expected_interface = "enp3s0f3u1u1"

# Define a list of known bogon IP ranges
bogon_ranges = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    # Add more bogon ranges as needed
]

# Define a callback function to process each captured packet
def process_packet(packet):
    if packet.haslayer(IP):
        # Extract IP information from the packet
        source_ip = packet[IP].src
        expected_ip = netifaces.ifaddresses(expected_interface)[netifaces.AF_INET][0]['addr']
        destination_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        if source_ip != expected_ip:
            print("Potential IP spoofing detected: RPF check failed!")
            return

        # Perform Bogon filtering
        for bogon_range in bogon_ranges:
            if IP(source_ip) in IP(bogon_range):
                print("Potential IP spoofing detected: Bogon filter matched!")
                return

        # Process the extracted IP information
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")
        print(f"Protocol: {protocol}")

# Start sniffing packets on the network interface
if __name__ == "__main__":
    sniff(filter="ip", prn=process_packet, iface=expected_interface)

