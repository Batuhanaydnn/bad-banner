import pyshark
import json


def analyze_esp_packet(packet):
    esp_layer = packet.esp
    spi = esp_layer.spi
    sequence_number = esp_layer.seq
    payload_lenght = esp_layer.length
    crypt_algo = esp_layer.crypt_algo
    auth_alog = esp_layer.auth_algo
    iv = esp_layer.iv
    encrypted_data = esp_layer.payload

    esp_info = {
        'SPI': spi,
        'Sequence Number': sequence_number,
        'Payload Length': payload_lenght,
        'Encryption Algorithm': crypt_algo,
        'Authentication Algorithm': auth_alog,
        'IV': iv,
        'Encrypted Data': encrypted_data
    }

    packet_info = {
        'ESP': esp_info
    }
    print(json.dumps(packet_info, indent=1))


def capture_esp_packets(interface):
    capture = pyshark.LiveCapture(interface=interface, display_filter='esp')
    for packet in capture.sniff_continuously():
        analyze_esp_packet(packet)


if __name__ == '__main__':
    interface = 'Wi-Fi'
    capture_esp_packets(interface)
