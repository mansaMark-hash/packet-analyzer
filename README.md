# Packet Analyzer

A passive packet sniffer and traffic analyzer built with Python and [Scapy](https://scapy.net/). It watches network traffic, summarizes it, and flags possible TCP port scans.

> **Legal / ethical use:** Only capture traffic on networks you own or have explicit written permission to monitor. This tool is passive (it never sends packets), but unauthorized sniffing is illegal in most places. Built for learning and defensive use in a home lab.

## Features

- Protocol breakdown (TCP, UDP, ICMP, ARP, DNS)
- Top talkers (most active source IPs)
- DNS lookup tracking
- Port-scan detection (one IP sending SYN packets to many distinct ports)
- ARP spoofing detection (one IP suddenly claimed by a different MAC address)
- Live capture or offline `.pcap` analysis
- Save captures to `.pcap` for Wireshark

## Install

```bash
git clone https://github.com/<your-username>/packet-analyzer.git
cd packet-analyzer
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Tested on Kali Linux.

## Usage

```bash
# Live capture (needs root), stop after 200 packets
sudo .venv/bin/python -m packet_analyzer -i eth0 -c 200

# Web traffic only, and save the capture
sudo .venv/bin/python -m packet_analyzer -i eth0 -f "tcp port 80" -w web.pcap

# Analyze an existing capture (no root needed)
python -m packet_analyzer -r web.pcap
```

Find your interface name with `ip a`.

| Flag | Meaning |
|------|---------|
| `-i` | Interface to sniff (e.g. `eth0`) |
| `-r` | Read an existing `.pcap` instead of sniffing |
| `-w` | Save captured packets to a `.pcap` |
| `-c` | Stop after N packets |
| `-f` | BPF filter, e.g. `"tcp port 80"` |
| `-t` | Distinct SYN ports before a scan alert (default 15) |

## Example output

```
[ALERT] Possible port scan from 192.168.56.101 (15 ports)

==================================================
Packets: 412   Bytes: 38120

Protocols:
  TCP    390
  DNS    12
  ARP    10

Top talkers:
  192.168.56.101     380 packets
```

## How the scan detection works

A normal TCP connection starts with a SYN, and the server replies SYN+ACK. The analyzer tracks SYN-only packets and counts the distinct destination ports each source IP touches. Reaching the threshold (default 15) triggers an alert. Tools like Nmap's `-sS` scan look exactly like this on the wire.

## How the ARP spoofing detection works

ARP maps IP addresses to MAC addresses on a local network. The analyzer remembers the first MAC that answered for each IP. If a later ARP reply claims the same IP with a **different** MAC, it raises an alert. This is the signature of a man-in-the-middle attack. Note: legitimate cases (a router with two interfaces, a device replaced, failover) can also trigger it, so treat alerts as a prompt to investigate.

## Try the detectors safely (no network traffic)

```bash
python scripts/make_sample_pcaps.py   # writes port_scan.pcap and arp_spoof.pcap
python -m packet_analyzer -r port_scan.pcap
python -m packet_analyzer -r arp_spoof.pcap
```

**Test the scan detector in your own lab:** run the analyzer on one VM, then run `nmap -sS <that-VM-IP>` from another VM you own.

## Project layout

```
packet_analyzer/
  analyzer.py   # analysis logic
  cli.py        # command-line interface
scripts/        # sample .pcap generator
tests/          # pytest tests (no network needed)
```

## Run the tests

```bash
pip install -r requirements-dev.txt
pytest
```

## Roadmap

- [ ] HTTP Host / User-Agent extraction
- [x] ARP spoofing detection
- [ ] JSON / CSV report export
- [ ] Live terminal dashboard

## License

MIT
