import pyshark
from sklearn.ensemble import IsolationForest



def capture_packets(interface, capture_duration):
    capture = pyshark.LiveCapture(interface=interface)
    capture.sniff(timeout=capture_duration)
    for packet in capture.sniff_continuously(packet_count=10):
        print(packet)

capture_packets('eth0', 60)  



def capture_packets_detailes(packet):
    for packet in capture_packets:
        print(f"Packet Number: {packet.number}")
    if 'IP' in packet:
        print(f"Source IP: {packet.ip.src}")
        print(f"Destination IP: {packet.ip.dst}")
    if 'TCP' in packet:
        print(f"Source Port: {packet.tcp.srcport}")
        print(f"Destination Port: {packet.tcp.dstport}")
    if 'SIZE' in packet:
        print(f"size: {packet.size}")









    

