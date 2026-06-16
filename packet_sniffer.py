"""
Network Packet Sniffer
Captures and parses raw network packets using Python's built-in socket library.
Run with: sudo python3 packet_sniffer.py [options]
"""

import socket
import struct
import argparse
import datetime
import sys
import os
import json
from collections import defaultdict

# ─── Parsers ──────────────────────────────────────────────────────────────────

def parse_ethernet(data):
    if len(data) < 14:
        return None
    dst = ":".join(f"{b:02x}" for b in data[0:6])
    src = ":".join(f"{b:02x}" for b in data[6:12])
    proto = struct.unpack("!H", data[12:14])[0]
    return {"dst_mac": dst, "src_mac": src, "proto": proto, "payload": data[14:]}

def parse_ipv4(data):
    if len(data) < 20:
        return None
    ihl = (data[0] & 0x0F) * 4
    ttl, proto = data[8], data[9]
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    return {
        "version": 4, "ihl": ihl, "ttl": ttl,
        "proto": proto, "src_ip": src, "dst_ip": dst,
        "payload": data[ihl:]
    }

def parse_ipv6(data):
    if len(data) < 40:
        return None
    next_hdr = data[6]
    src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    return {"version": 6, "next_hdr": next_hdr, "src_ip": src, "dst_ip": dst, "payload": data[40:]}

def parse_tcp(data):
    if len(data) < 20:
        return None
    src_port, dst_port, seq, ack = struct.unpack("!HHLL", data[0:12])
    offset = ((data[12] >> 4) * 4)
    flags = data[13]
    flag_str = "".join([
        "FIN " if flags & 0x01 else "",
        "SYN " if flags & 0x02 else "",
        "RST " if flags & 0x04 else "",
        "PSH " if flags & 0x08 else "",
        "ACK " if flags & 0x10 else "",
        "URG " if flags & 0x20 else "",
    ]).strip()
    return {
        "src_port": src_port, "dst_port": dst_port,
        "seq": seq, "ack": ack, "flags": flag_str,
        "payload": data[offset:]
    }

def parse_udp(data):
    if len(data) < 8:
        return None
    src_port, dst_port, length = struct.unpack("!HHH", data[0:6])
    return {"src_port": src_port, "dst_port": dst_port, "length": length, "payload": data[8:]}

def parse_icmp(data):
    if len(data) < 4:
        return None
    icmp_type, code = data[0], data[1]
    type_map = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request", 11: "Time Exceeded"}
    return {"type": icmp_type, "code": code, "description": type_map.get(icmp_type, f"Type {icmp_type}")}

def parse_dns(data):
    if len(data) < 12:
        return None
    txn_id, flags, qdcount = struct.unpack("!HHH", data[0:6])
    is_response = bool(flags & 0x8000)
    return {"txn_id": hex(txn_id), "is_response": is_response, "questions": qdcount}

def try_decode_payload(data, max_len=64):
    try:
        text = data[:max_len].decode("utf-8", errors="replace")
        return text if text.isprintable() else None
    except Exception:
        return None

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}

# ─── Stats ────────────────────────────────────────────────────────────────────

class Stats:
    def __init__(self):
        self.total = 0
        self.by_proto = defaultdict(int)
        self.by_src = defaultdict(int)
        self.bytes_total = 0

    def update(self, proto_name, src_ip, pkt_len):
        self.total += 1
        self.by_proto[proto_name] += 1
        self.by_src[src_ip] += 1
        self.bytes_total += pkt_len

    def summary(self):
        print("\n" + "═" * 60)
        print(f"  CAPTURE SUMMARY")
        print("═" * 60)
        print(f"  Total packets : {self.total}")
        print(f"  Total bytes   : {self.bytes_total:,}")
        print(f"\n  By Protocol:")
        for p, c in sorted(self.by_proto.items(), key=lambda x: -x[1]):
            print(f"    {p:<10} {c}")
        print(f"\n  Top Sources:")
        top = sorted(self.by_src.items(), key=lambda x: -x[1])[:5]
        for ip, c in top:
            print(f"    {ip:<40} {c} pkts")
        print("═" * 60)

# ─── Display ──────────────────────────────────────────────────────────────────

def format_packet(pkt_num, timestamp, eth, ip, transport, proto_name, raw_len, args):
    ts = timestamp.strftime("%H:%M:%S.%f")[:-3]
    src_ip = ip.get("src_ip", "?")
    dst_ip = ip.get("dst_ip", "?")

    if transport and "src_port" in transport:
        conn = f"{src_ip}:{transport['src_port']} → {dst_ip}:{transport['dst_port']}"
    else:
        conn = f"{src_ip} → {dst_ip}"

    header = f"[{pkt_num:>5}] {ts}  {proto_name:<6}  {conn}  ({raw_len} B)"

    lines = [header]

    if args.verbose:
        if eth:
            lines.append(f"         MAC  {eth['src_mac']} → {eth['dst_mac']}")
        if ip.get("version") == 4:
            lines.append(f"         IPv4 TTL={ip['ttl']}  proto={ip['proto']}")
        if transport:
            if proto_name == "TCP":
                lines.append(f"         TCP  seq={transport['seq']}  ack={transport['ack']}  flags=[{transport['flags']}]")
            elif proto_name == "UDP":
                lines.append(f"         UDP  len={transport['length']}")
            elif proto_name == "ICMP":
                lines.append(f"         ICMP {transport['description']}  code={transport['code']}")
            if proto_name == "UDP" and transport["dst_port"] == 53:
                dns = parse_dns(transport.get("payload", b""))
                if dns:
                    rtype = "Response" if dns["is_response"] else "Query"
                    lines.append(f"         DNS  {rtype}  txn={dns['txn_id']}  questions={dns['questions']}")
            payload = transport.get("payload", b"")
            if payload and args.show_payload:
                decoded = try_decode_payload(payload)
                if decoded:
                    lines.append(f"         DATA {repr(decoded[:80])}")

    return "\n".join(lines)

# ─── Sniffer ──────────────────────────────────────────────────────────────────

def sniff(args):
    if os.geteuid() != 0:
        print("[!] Root privileges required. Re-run with: sudo python3 packet_sniffer.py")
        sys.exit(1)

    stats = Stats()
    log_file = None
    if args.output:
        log_file = open(args.output, "w")
        print(f"[*] Logging to: {args.output}")

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    except AttributeError:
        print("[!] AF_PACKET not available on this OS. Linux required.")
        sys.exit(1)

    if args.iface:
        sock.bind((args.iface, 0))

    count = 0
    filter_proto = args.proto.upper() if args.proto else None
    filter_ip = args.ip

    print(f"[*] Sniffing packets{' on ' + args.iface if args.iface else ''} ...")
    print(f"[*] Capture limit : {args.count if args.count else 'unlimited'}")
    if filter_proto:
        print(f"[*] Protocol filter: {filter_proto}")
    if filter_ip:
        print(f"[*] IP filter      : {filter_ip}")
    print("─" * 60)

    try:
        while True:
            raw, _ = sock.recvfrom(65535)
            pkt_len = len(raw)

            eth = parse_ethernet(raw)
            if not eth:
                continue

            ip = None
            if eth["proto"] == 0x0800:       # IPv4
                ip = parse_ipv4(eth["payload"])
            elif eth["proto"] == 0x86DD:     # IPv6
                ip = parse_ipv6(eth["payload"])
            else:
                continue  # skip ARP, etc.

            if not ip:
                continue

            # IP filter
            if filter_ip and filter_ip not in (ip.get("src_ip"), ip.get("dst_ip")):
                continue

            proto_num = ip.get("proto") or ip.get("next_hdr", 0)
            proto_name = PROTO_NAMES.get(proto_num, f"PROTO{proto_num}")

            # Protocol filter
            if filter_proto and proto_name != filter_proto:
                continue

            transport = None
            payload = ip.get("payload", b"")
            if proto_num == 6:
                transport = parse_tcp(payload)
            elif proto_num == 17:
                transport = parse_udp(payload)
            elif proto_num in (1, 58):
                transport = parse_icmp(payload)
                proto_name = "ICMP"

            # Port filter
            if args.port and transport and "src_port" in transport:
                if args.port not in (transport["src_port"], transport["dst_port"]):
                    continue

            count += 1
            ts = datetime.datetime.now()
            stats.update(proto_name, ip.get("src_ip", "?"), pkt_len)

            line = format_packet(count, ts, eth, ip, transport, proto_name, pkt_len, args)
            print(line)

            if log_file:
                log_file.write(line + "\n")
                log_file.flush()

            if args.count and count >= args.count:
                break

    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")
    finally:
        sock.close()
        if log_file:
            log_file.close()
        stats.summary()

# ─── Entry ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Network Packet Sniffer — uses raw sockets (Linux, requires root)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--iface",   help="Network interface (e.g. eth0, wlan0). Default: all")
    parser.add_argument("-c", "--count",   type=int, help="Stop after N packets")
    parser.add_argument("-p", "--proto",   help="Filter by protocol: TCP, UDP, ICMP")
    parser.add_argument("--port",          type=int, help="Filter by port number")
    parser.add_argument("--ip",            help="Filter by source or destination IP")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show packet details")
    parser.add_argument("--show-payload",  action="store_true", help="Show decoded text payload (with -v)")
    parser.add_argument("-o", "--output",  help="Save capture log to a file")

    args = parser.parse_args()
    sniff(args)

if __name__ == "__main__":
    main()
