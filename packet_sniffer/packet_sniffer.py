import pyshark

class PacketAnalyzer:
    def __init__(self):
        self.results = {}

    def analyze_packet(self, packet):
        eth_type = packet.eth.type

        if eth_type == '0x8000': # IPv4
            self.analyze_ipv4_packet(packet)
        
        elif eth_type == '0x8006': # ARP
            self.analyze_arp_packet(packet)
        
        elif eth_type == '0x86dd': # IPv6
            self.analyze_ipv6_packet(packet)
        
        elif eth_type == '0x88cc': # LLDP
            self.analyze_lldp_packet(packet)
        
        elif eth_type == '0x06': # TCP
            self.analyze_tcp_packet(packet)
        
        elif eth_type == '0x11': # UDP
            self.analyze_udp_packet(packet)
        
        elif eth_type == '0x01': # ICMP
            self.analyze_icmp_packet(packet)
        
        elif eth_type == '0x02': # IGMP
            self.analyze_igmp_packet(packet)
        
        elif eth_type == '0x84': # SCTP
            self.analyze_sctp_packet(packet)
        
        elif eth_type == '0x00': # reserved
            self.analyze_reserved_packet(packet)
        
        elif eth_type == '0x21': # FTP
            self.analyze_ftp_packet(packet)
        
        elif eth_type == '0x22': # SSH
            self.analyze_ssh_packet(packet)
        
        elif eth_type == '0x25': # ESP
            self.analyze_esp_packet(packet)
        
        elif eth_type == '0x51': # AH
            self.analyze_ah_packet(packet)
        
        elif eth_type == '0x80': # HTTP
            self.analyze_http_packet(packet)
        
        elif eth_type == '0x443': # HTTPS
            self.analyze_https_packet(packet)
        