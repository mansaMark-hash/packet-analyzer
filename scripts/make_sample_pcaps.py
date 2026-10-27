#!/usr/bin/env python3
"""Write sample .pcap files to disk so you can test the detectors safely.

Nothing is sent on the network: packets are only written to files.
    python scripts/make_sample_pcaps.py
    python -m packet_analyzer -r port_scan.pcap
    python -m packet_analyzer -r arp_spoof.pcap
"""
from scapy.all import ARP, IP, TCP, Ether, wrpcap

scan = [Ether() / IP(src="192.168.0.50", dst="192.168.0.105") / TCP(dport=p, flags="S")
        for p in range(1, 26)]
wrpcap("port_scan.pcap", scan)

spoof = [
    Ether() / ARP(op=2, psrc="192.168.0.1", hwsrc="aa:aa:aa:aa:aa:aa", pdst="192.168.0.105"),
    Ether() / ARP(op=2, psrc="192.168.0.1", hwsrc="bb:bb:bb:bb:bb:bb", pdst="192.168.0.105"),
]
wrpcap("arp_spoof.pcap", spoof)
print("Wrote port_scan.pcap and arp_spoof.pcap")
