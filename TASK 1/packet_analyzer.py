import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def analyze_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Determine protocol type cleanly
        protocol = "OTHER"
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        elif packet[IP].proto == 2:
            protocol = "IGMP"

        print("\n" + "=" * 55)
        print(f"[+] Captured Packet | Protocol: {protocol}")
        print(f"    Source IP     : {src_ip}")
        print(f"    Destination IP: {dst_ip}")

        # Extract Port Information
        if protocol == "TCP":
            print(f"    Source Port   : {packet[TCP].sport}")
            print(f"    Dest Port     : {packet[TCP].dport}")
        elif protocol == "UDP":
            print(f"    Source Port   : {packet[UDP].sport}")
            print(f"    Dest Port     : {packet[UDP].dport}")

        # Extract Raw Payload snippet
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"    Payload (Raw) : {repr(payload[:40])}")
        
        print("=" * 55)

def main():
    print("-------------------------------------------------------")
    print("      CodSoft Task 1 - Network Packet Analyzer         ")
    print("-------------------------------------------------------")
    print("[*] Starting live packet capture... (Press Ctrl+C to stop)\n")
    
    try:
        sniff(prn=analyze_packet, store=False)
    except KeyboardInterrupt:
        print("\n[*] Packet capture stopped by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()