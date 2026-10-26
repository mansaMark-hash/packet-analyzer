"""Core analysis logic: protocol stats, top talkers, DNS lookups, scan detection."""
from collections import Counter, defaultdict

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP


class Analyzer:
    def __init__(self, scan_threshold=15):
        self.total = 0
        self.total_bytes = 0
        self.protocols = Counter()          # TCP / UDP / ICMP / ARP / DNS
        self.talkers = Counter()            # packets per source IP
        self.dns_queries = Counter()        # domain names looked up
        self.syn_ports = defaultdict(set)   # src IP -> distinct ports hit with SYN
        self.alerts = []
        self.scan_threshold = scan_threshold
        self._alerted = set()

    def process(self, pkt):
        self.total += 1
        self.total_bytes += len(pkt)

        if pkt.haslayer(ARP):
            self.protocols["ARP"] += 1

        if not pkt.haslayer(IP):
            return

        src = pkt[IP].src
        self.talkers[src] += 1

        if pkt.haslayer(TCP):
            self.protocols["TCP"] += 1
            flags = int(pkt[TCP].flags)
            syn, ack = flags & 0x02, flags & 0x10
            if syn and not ack:  # a "knock" with no handshake yet
                self.syn_ports[src].add(pkt[TCP].dport)
                self._check_scan(src)
        elif pkt.haslayer(UDP):
            self.protocols["UDP"] += 1
        elif pkt.haslayer(ICMP):
            self.protocols["ICMP"] += 1

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
            self.protocols["DNS"] += 1
            name = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            self.dns_queries[name] += 1

    def _check_scan(self, src):
        """Many different ports hit by SYN from one IP = possible port scan."""
        if len(self.syn_ports[src]) >= self.scan_threshold and src not in self._alerted:
            self._alerted.add(src)
            msg = f"[ALERT] Possible port scan from {src} ({len(self.syn_ports[src])} ports)"
            self.alerts.append(msg)
            print(msg)

    def report(self):
        print("\n" + "=" * 50)
        print(f"Packets: {self.total}   Bytes: {self.total_bytes}")
        print("\nProtocols:")
        for proto, n in self.protocols.most_common():
            print(f"  {proto:<6} {n}")
        print("\nTop talkers:")
        for ip, n in self.talkers.most_common(5):
            print(f"  {ip:<18} {n} packets")
        print("\nTop DNS lookups:")
        for name, n in self.dns_queries.most_common(5):
            print(f"  {name:<35} {n}")
        print("\nAlerts:", "none" if not self.alerts else "")
        for a in self.alerts:
            print(" ", a)
