import pyshark
import json

def analyze_ah_packet(packet):
    ah_header = packet.sh

    next_header = ah_header.next_header
    payload_lenght = ah_header.payload_length
    spi = ah_header.spi
    sequence_number = ah_header.sequence_number
    authentication_data = ah_header.authentication_data

    ah_info = {
        'Next Header': next_header,
        'Payload Lenght': payload_lenght,
        'SPI': spi,
        'Sequence Number': sequence_number,
        'Authentication_ Data': authentication_data
    }

    return ah_info

def analyze_tranport_layer_ah(packet):
    transport_layer = packet.transport_layer
    protocol = transport_layer.protocol
    source_port = transport_layer.srcport
    destination_port = transport_layer.dstport

    transport_info = {
        'Protocol': protocol,
        'Source Port': source_port,
        'Destination Port': destination_port,
    }
    return transport_info

def capture_ah_packets(interface):
    capture = pyshark.LiveCapture(interface=interface, display_filter='eth.type == 0x800 and ip.proto == 50')
    for packet in capture.sniff_continuously():
        if 'AH' in packet:
            ah_info = analyze_ah_packet(packet)
            transport_info = analyze_tranport_layer_ah(packet)

            packet_info = {
                'AH' : ah_info,
                'Transport Layer': transport_info
            }


            print(json.dumps(packet_info, indent=4))

if __name__ == '__main__':
    interface = 'eth0'
    capture_ah_packets(interface)