from fastapi import FastAPI, Request
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

app = FastAPI()

expected_interface = "enp3s0f3u1u1"  # Default interface
captured_data = CapturedDataQueue()  # Queue to store captured data

# List of known bogon IPv4 and IPv6 ranges
bogon_ranges = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",


    "::/128",
    "fe80::/10",

]

# Process captured packets
def process_packet(packet):
    
    if packet.haslayer(IP):
        # Perform RPF check
        if packet[IP].src != packet[IP].src_route:
            captured_data.put("Potential IP spoofing detected: RPF check failed!")

        # Perform Bogon filtering
        source_ip = packet[IP].src
        for bogon_range in bogon_ranges:
            if IP(source_ip) in IP(bogon_range):
                captured_data.put("Potential IP spoofing detected: Bogon filter matched!")

    # Store the packet data for display on the web page
    captured_data.put(f"Source IP: {source_ip}")
    captured_data.put(f"Destination IP: {destination_ip}")
    captured_data.put(f"Protocol: {protocol}")

# @app.get("/")
# async def root():
#     return {"message": "Hello from home"}

# @app.get("/stats")
# def index(request: Request):
#     data = []
#     while not captured_data.empty():
#         data.append(captured_data.get())
#     return {"request": request, "interface": expected_interface, "data": data}

# @app.post("/")
# async def update_interface(request: Request):
#     form = await request.form()
#     global expected_interface
#     expected_interface = form["interface"]
#     return {"message": "Interface updated successfully"}

if __name__ == "__main__":
    sniff(filter="ip", prn=process_packet, iface=expected_interface) # Start sniffing packets on the network interface
