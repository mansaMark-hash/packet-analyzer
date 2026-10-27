from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP

from packet_analyzer import Analyzer


def syn(src, dport):
    return IP(src=src, dst="10.0.0.2") / TCP(dport=dport, flags="S")


def test_protocol_counts():
    a = Analyzer()
    a.process(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80, flags="S"))
    a.process(IP(src="10.0.0.1", dst="10.0.0.2") / UDP(dport=53))
    a.process(IP(src="10.0.0.1", dst="10.0.0.2") / ICMP())
    assert a.protocols["TCP"] == 1
    assert a.protocols["UDP"] == 1
    assert a.protocols["ICMP"] == 1
    assert a.total == 3


def test_dns_query_recorded():
    a = Analyzer()
    a.process(IP(src="10.0.0.1", dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")))
    assert a.dns_queries["example.com"] == 1


def test_port_scan_detected():
    a = Analyzer(scan_threshold=15)
    for port in range(1, 20):
        a.process(syn("10.0.0.99", port))
    assert len(a.alerts) == 1
    assert "10.0.0.99" in a.alerts[0]


def test_normal_traffic_no_alert():
    a = Analyzer(scan_threshold=15)
    for _ in range(50):
        a.process(syn("10.0.0.5", 443))  # same port repeatedly is not a scan
    assert a.alerts == []


def arp_reply(ip, mac):
    return ARP(op=2, psrc=ip, hwsrc=mac, pdst="192.168.0.105")


def test_arp_spoof_detected():
    a = Analyzer()
    a.process(arp_reply("192.168.0.1", "aa:aa:aa:aa:aa:aa"))  # real router
    a.process(arp_reply("192.168.0.1", "bb:bb:bb:bb:bb:bb"))  # attacker claims it
    assert len(a.alerts) == 1
    assert "192.168.0.1" in a.alerts[0]
    assert "bb:bb:bb:bb:bb:bb" in a.alerts[0]


def test_same_mac_repeated_no_alert():
    a = Analyzer()
    for _ in range(5):
        a.process(arp_reply("192.168.0.1", "aa:aa:aa:aa:aa:aa"))
    assert a.alerts == []


def test_arp_requests_ignored():
    a = Analyzer()
    a.process(ARP(op=1, psrc="192.168.0.1", hwsrc="aa:aa:aa:aa:aa:aa"))
    a.process(ARP(op=1, psrc="192.168.0.1", hwsrc="bb:bb:bb:bb:bb:bb"))
    assert a.alerts == []
