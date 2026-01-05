from scapy.all import IP, UDP, TCP, ICMP, ARP, send, sniff


def packet_callback(packet):
    if packet.haslayer(IP):  
        ip_packet = packet[IP]
        print(f"Source: {ip_packet.src} -> Destination: {ip_packet.dst}")
        print(f"Version: {ip_packet.version}")
        print(f"Total Length: {ip_packet.len}")
        print(f"Flags: {ip_packet.flags}")
        print(f"Fragment Offset: {ip_packet.frag}")
        print(f"Protocol: {ip_packet.proto}")

        
        if packet.haslayer(TCP):
            print(f"TCP packet: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"UDP packet: {packet[UDP].sport} -> {packet[UDP].dport}")
        elif packet.haslayer(ICMP):
            print(f"ICMP packet: Type={packet[ICMP].type}, Code={packet[ICMP].code}")
        print('-' * 40)
    
    elif packet.haslayer(ARP):  
        arp_packet = packet[ARP]
        print(f"ARP Request: {arp_packet.psrc} -> {arp_packet.pdst}")
        print(f"Hardware Type: {arp_packet.hwtype}, Protocol Type: {arp_packet.ptype}")
        print('-' * 40)

pkt = IP(dst="192.168.1.1", flags="MF") / ICMP() / ("X" * 2000)  
send(pkt)


print("Starting packet sniffing...")
sniff(count=5, prn=packet_callback, store=0)  
print("Packet capture finished.")
