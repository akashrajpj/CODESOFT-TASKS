#!/usr/bin/env python3
"""
Task 4 - Network Intrusion Detection System (NIDS)
Defensive/educational network monitoring tool.

Modes:
  --demo              Run with built-in simulated traffic
  --pcap FILE         Analyze an existing PCAP file
  --live IFACE        Monitor a live interface (requires Scapy/Npcap/root/admin)

Detections:
  - ICMP burst / ping flood pattern
  - TCP port scan pattern
  - Repeated SSH connection attempts
"""

import argparse
from collections import defaultdict, deque
from datetime import datetime
import time

from scapy.all import IP, TCP, UDP, ICMP, Raw, rdpcap, sniff


class NIDS:
    def __init__(self, window=10, icmp_threshold=20, portscan_threshold=10,
                 ssh_threshold=8):
        self.window = window
        self.icmp_threshold = icmp_threshold
        self.portscan_threshold = portscan_threshold
        self.ssh_threshold = ssh_threshold

        self.icmp_events = defaultdict(deque)
        self.port_events = defaultdict(deque)
        self.ssh_events = defaultdict(deque)

        self.alert_cache = set()

    def _cleanup(self, events, key, now):
        q = events[key]
        while q and now - q[0][0] > self.window:
            q.popleft()

    def _alert_once(self, key, message):
        if key not in self.alert_cache:
            self.alert_cache.add(key)
            print(f"[ALERT] {message}")

    def process(self, packet):
        if not packet.haslayer(IP):
            return

        ip = packet[IP]
        src = ip.src
        dst = ip.dst
        now = time.time()

        # ICMP burst detection
        if packet.haslayer(ICMP):
            self.icmp_events[src].append((now, dst))
            self._cleanup(self.icmp_events, src, now)
            count = len(self.icmp_events[src])

            if count >= self.icmp_threshold:
                self._alert_once(
                    ("icmp", src),
                    f"Possible ICMP flood: {src} sent {count} ICMP packets "
                    f"within {self.window} seconds."
                )

        # TCP-based detections
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = str(tcp.flags)

            # Port scan: SYN packets to many different destination ports
            if "S" in flags and "A" not in flags:
                self.port_events[src].append((now, int(tcp.dport)))
                self._cleanup(self.port_events, src, now)

                ports = {port for _, port in self.port_events[src]}
                if len(ports) >= self.portscan_threshold:
                    self._alert_once(
                        ("portscan", src),
                        f"Possible TCP port scan: {src} contacted "
                        f"{len(ports)} different ports on {dst} "
                        f"within {self.window} seconds."
                    )

            # SSH repeated connection attempts
            if int(tcp.dport) == 22 and "S" in flags and "A" not in flags:
                self.ssh_events[src].append((now, dst))
                self._cleanup(self.ssh_events, src, now)

                count = len(self.ssh_events[src])
                if count >= self.ssh_threshold:
                    self._alert_once(
                        ("ssh", src),
                        f"Possible SSH brute-force activity: {src} made "
                        f"{count} SSH connection attempts within "
                        f"{self.window} seconds."
                    )

    def packet_summary(self, packet):
        if not packet.haslayer(IP):
            return

        ip = packet[IP]
        protocol = "OTHER"

        if packet.haslayer(TCP):
            protocol = f"TCP:{packet[TCP].sport}->{packet[TCP].dport}"
        elif packet.haslayer(UDP):
            protocol = f"UDP:{packet[UDP].sport}->{packet[UDP].dport}"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        print(f"[TRAFFIC] {ip.src:15} -> {ip.dst:15}  {protocol}")


def analyze_packets(packets, nids, show_traffic=True):
    for packet in packets:
        if show_traffic:
            nids.packet_summary(packet)
        nids.process(packet)


def make_demo_packets():
    """Create harmless synthetic packets in memory for demonstration."""
    packets = []

    # Normal traffic
    packets.append(IP(src="192.168.1.10", dst="192.168.1.1") /
                   ICMP())

    # Simulated ICMP burst
    for _ in range(22):
        packets.append(IP(src="10.0.0.50", dst="10.0.0.1") / ICMP())

    # Simulated TCP port scan
    for port in range(20, 35):
        packets.append(
            IP(src="10.0.0.60", dst="10.0.0.1") /
            TCP(sport=40000 + port, dport=port, flags="S")
        )

    # Simulated SSH repeated attempts
    for i in range(10):
        packets.append(
            IP(src="10.0.0.70", dst="10.0.0.1") /
            TCP(sport=45000 + i, dport=22, flags="S")
        )

    return packets


def main():
    parser = argparse.ArgumentParser(
        description="Task 4 - Defensive Network Intrusion Detection System"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true",
                      help="Run a safe built-in demonstration")
    mode.add_argument("--pcap", metavar="FILE",
                      help="Analyze an existing PCAP file")
    mode.add_argument("--live", metavar="IFACE",
                      help="Monitor a live network interface")

    parser.add_argument("--window", type=int, default=10,
                        help="Detection time window in seconds")
    parser.add_argument("--icmp-threshold", type=int, default=20)
    parser.add_argument("--portscan-threshold", type=int, default=10)
    parser.add_argument("--ssh-threshold", type=int, default=8)
    parser.add_argument("--quiet", action="store_true",
                        help="Hide normal traffic lines")

    args = parser.parse_args()

    nids = NIDS(
        window=args.window,
        icmp_threshold=args.icmp_threshold,
        portscan_threshold=args.portscan_threshold,
        ssh_threshold=args.ssh_threshold
    )

    print("=" * 65)
    print("TASK 4 - NETWORK INTRUSION DETECTION SYSTEM")
    print("Started:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 65)

    if args.demo:
        print("[INFO] Running safe built-in demonstration...\n")
        analyze_packets(make_demo_packets(), nids, not args.quiet)

    elif args.pcap:
        print(f"[INFO] Reading PCAP: {args.pcap}\n")
        packets = rdpcap(args.pcap)
        analyze_packets(packets, nids, not args.quiet)

    elif args.live:
        print(f"[INFO] Monitoring interface: {args.live}")
        print("[INFO] Press Ctrl+C to stop.\n")
        sniff(
            iface=args.live,
            prn=lambda p: (
                nids.packet_summary(p) if not args.quiet else None,
                nids.process(p)
            ),
            store=False
        )

    print("\n[INFO] Detection completed.")


if __name__ == "__main__":
    main()
