import pyshark
import json

def analyze_arp_packet(packet):
    arp_layer = packet.arp
    operation = arp_layer.op
    source_mac = arp_layer.src_hw_mac
    source_ip = arp_layer.src_proto_ipv4
    target_mac = arp_layer.dst_hw_mac
    target_ip = arp_layer.proto_ipv4

    arp_info = {
        'Operation': operation,
        'Source MAC': source_mac,
        'Source IP': source_ip,
        'Target MAC': target_mac,
        'Target IP': target_ip
    }
    packet_info = {
        'ARP' : arp_info
    }

    print(json.dumps(packet_info, indent=16))


def capture_arp_packets(interface):
    capture = pyshark.LiveCapture(interface=interface, display_filter='arp')
    for packet in capture.sniff_continuously():
        analyze_arp_packet(packet)

if __name__ == '__main__':
    interface = 'Wi-Fi'
    capture_arp_packets(interface)

