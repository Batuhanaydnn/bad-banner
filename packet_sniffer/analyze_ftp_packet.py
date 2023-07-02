import pyshark
import json


def analyze_ftp_packet(packet):
    ftp_layer = packet.ftp
    command = ftp_layer.command
    response = ftp_layer.response
    username = ftp_layer.user
    password = ftp_layer.passwd
    file_name = ftp_layer.arg

    ftp_info = {
        'Command': command,
        'Response': response,
        'Username': username,
        'Password': password,
        'File Name': file_name
    }
    packet_info = {
        'FTP': ftp_info
    }

    print(json.dumps(packet_info, indent=4))


def capture_ftp_packets(interface):
    capture = pyshark.LiveCapture(interface=interface, display_filter='ftp')
    for packet in capture.sniff_continuously():
        analyze_ftp_packet(packet)


if __name__ == '__main__':
    interface = 'Wi-Fi'
    capture_ftp_packets(interface)
