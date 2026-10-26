"""Command-line interface."""
import argparse

from scapy.all import rdpcap, sniff, wrpcap

from .analyzer import Analyzer


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="packet-analyzer",
        description="Passive packet analyzer. Use only on networks you own or have permission to monitor.",
    )
    p.add_argument("-i", "--iface", help="interface to sniff (e.g. eth0)")
    p.add_argument("-r", "--read", help="analyze an existing .pcap file")
    p.add_argument("-w", "--write", help="save captured packets to a .pcap file")
    p.add_argument("-c", "--count", type=int, default=0, help="stop after N packets")
    p.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp port 80'")
    p.add_argument("-t", "--threshold", type=int, default=15,
                   help="distinct SYN ports before a scan alert (default 15)")
    args = p.parse_args(argv)

    analyzer = Analyzer(scan_threshold=args.threshold)

    try:
        if args.read:
            for pkt in rdpcap(args.read):
                analyzer.process(pkt)
        else:
            print("Sniffing... press Ctrl+C to stop.")
            packets = sniff(iface=args.iface, filter=args.filter, count=args.count,
                            prn=analyzer.process, store=bool(args.write))
            if args.write:
                wrpcap(args.write, packets)
                print(f"Saved capture to {args.write}")
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("Live capture needs root: run with sudo.")
        return 1

    analyzer.report()
    return 0
