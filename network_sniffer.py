"""
╔══════════════════════════════════════════════════════════════╗
║         TASK 1: Basic Network Sniffer — CodeAlpha            ║
║         Built with Python using scapy & socket               ║
╚══════════════════════════════════════════════════════════════╝

Features:
  - Captures live network packets (TCP, UDP, ICMP, ARP, DNS)
  - Displays source/destination IPs, protocols, ports & payloads
  - Saves captured packets to a log file
  - Supports packet count limit & interface selection
  - Color-coded terminal output
  - Summary statistics at the end

Usage:
  sudo python3 network_sniffer.py                         # default (eth0, 50 packets)
  sudo python3 network_sniffer.py -i wlan0 -c 100         # custom interface & count
  sudo python3 network_sniffer.py -i eth0 -c 20 -o log.txt
"""

import socket
import struct
import textwrap
import argparse
import datetime
import os
import sys

# ─── Try importing scapy; fall back to raw sockets ────────────────────────────
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw
    USE_SCAPY = True
except ImportError:
    USE_SCAPY = False

# ─── ANSI Colors ───────────────────────────────────────────────────────────────
class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"

# ─── Global stats tracker ──────────────────────────────────────────────────────
stats = {
    "total": 0, "TCP": 0, "UDP": 0,
    "ICMP": 0, "ARP": 0, "DNS": 0, "OTHER": 0
}
log_lines = []

# ─── Helpers ───────────────────────────────────────────────────────────────────
def timestamp():
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

def format_payload(data, max_bytes=64):
    """Show hex + ASCII side-by-side for payload bytes."""
    data = data[:max_bytes]
    hex_part = " ".join(f"{b:02X}" for b in data)
    asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"  HEX : {hex_part}\n  ASCII: {asc_part}"

def log(msg, color="", output_file=None):
    clean = msg  # without color codes for file
    print(f"{color}{msg}{Color.RESET}")
    log_lines.append(clean)

def separator(char="─", length=65, color=Color.WHITE):
    log(char * length, color)

# ─── Scapy-based sniffer ───────────────────────────────────────────────────────
def scapy_callback(packet, output_file=None):
    stats["total"] += 1
    ts = timestamp()
    separator()

    if packet.haslayer(ARP):
        stats["ARP"] += 1
        arp = packet[ARP]
        op = "REQUEST" if arp.op == 1 else "REPLY"
        log(f"[{ts}] 📡  ARP {op}", Color.YELLOW)
        log(f"  Sender: {arp.psrc} ({arp.hwsrc})")
        log(f"  Target: {arp.pdst} ({arp.hwdst})")
        return

    if not packet.haslayer(IP):
        stats["OTHER"] += 1
        log(f"[{ts}] ❓  Non-IP packet", Color.WHITE)
        return

    ip = packet[IP]
    proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(ip.proto, f"Proto-{ip.proto}")

    # ── TCP ──
    if packet.haslayer(TCP):
        stats["TCP"] += 1
        tcp = packet[TCP]
        flags = tcp.sprintf("%flags%")
        color = Color.BLUE
        log(f"[{ts}] 🔵  TCP  {ip.src}:{tcp.sport}  →  {ip.dst}:{tcp.dport}  [Flags: {flags}]", color)
        log(f"  TTL={ip.ttl}  Seq={tcp.seq}  Ack={tcp.ack}  Win={tcp.window}")
        if packet.haslayer(DNS):
            stats["DNS"] += 1
            dns = packet[DNS]
            if dns.qd:
                log(f"  🌐  DNS Query : {dns.qd.qname.decode(errors='replace')}", Color.CYAN)
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            log("  📦  Payload:")
            log(format_payload(payload))

    # ── UDP ──
    elif packet.haslayer(UDP):
        stats["UDP"] += 1
        udp = packet[UDP]
        color = Color.GREEN
        log(f"[{ts}] 🟢  UDP  {ip.src}:{udp.sport}  →  {ip.dst}:{udp.dport}", color)
        log(f"  TTL={ip.ttl}  Length={udp.len}")
        if packet.haslayer(DNS):
            stats["DNS"] += 1
            dns = packet[DNS]
            if dns.qd:
                log(f"  🌐  DNS Query : {dns.qd.qname.decode(errors='replace')}", Color.CYAN)
            if dns.an:
                log(f"  🌐  DNS Answer: {dns.an.rdata}", Color.CYAN)
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            log("  📦  Payload:")
            log(format_payload(payload))

    # ── ICMP ──
    elif packet.haslayer(ICMP):
        stats["ICMP"] += 1
        icmp = packet[ICMP]
        types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable"}
        itype = types.get(icmp.type, f"Type-{icmp.type}")
        log(f"[{ts}] 🟠  ICMP {ip.src}  →  {ip.dst}  [{itype}]", Color.MAGENTA)
        log(f"  TTL={ip.ttl}  Code={icmp.code}")

    else:
        stats["OTHER"] += 1
        log(f"[{ts}] ❓  {proto_name}  {ip.src}  →  {ip.dst}", Color.WHITE)
        log(f"  TTL={ip.ttl}  Len={ip.len}")

# ─── Raw socket sniffer (fallback if scapy not available) ─────────────────────
def raw_socket_sniffer(count=50, output_file=None):
    """
    Pure socket-based sniffer (Linux only, requires root).
    Parses Ethernet → IP → TCP/UDP/ICMP manually.
    """
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print(f"{Color.RED}[!] Root privileges required. Run with sudo.{Color.RESET}")
        sys.exit(1)
    except AttributeError:
        print(f"{Color.RED}[!] AF_PACKET not supported on this OS. Install scapy instead.{Color.RESET}")
        sys.exit(1)

    captured = 0
    while captured < count:
        raw_data, _ = conn.recvfrom(65535)
        captured += 1
        stats["total"] += 1
        ts = timestamp()
        separator()

        # Ethernet header (14 bytes)
        eth_dest, eth_src, eth_proto = struct.unpack("! 6s 6s H", raw_data[:14])
        eth_proto = socket.ntohs(eth_proto)
        data = raw_data[14:]

        if eth_proto == 8:  # IPv4
            if len(data) < 20:
                continue
            (version_ihl, tos, total_length, ident, flags_frag,
             ttl, proto, checksum, src, dst) = struct.unpack("! B B H H H B B H 4s 4s", data[:20])
            ihl = (version_ihl & 0xF) * 4
            src_ip = socket.inet_ntoa(src)
            dst_ip = socket.inet_ntoa(dst)
            segment = data[ihl:]

            if proto == 6:  # TCP
                stats["TCP"] += 1
                if len(segment) < 20:
                    continue
                (sport, dport, seq, ack, off_res,
                 flags, win, chk, urg) = struct.unpack("! H H L L B B H H H", segment[:20])
                data_off = (off_res >> 4) * 4
                payload = segment[data_off:]
                flag_str = ""
                if flags & 0x02: flag_str += "SYN "
                if flags & 0x10: flag_str += "ACK "
                if flags & 0x04: flag_str += "RST "
                if flags & 0x01: flag_str += "FIN "
                log(f"[{ts}] 🔵  TCP  {src_ip}:{sport}  →  {dst_ip}:{dport}  [{flag_str.strip()}]", Color.BLUE)
                log(f"  TTL={ttl}  Seq={seq}  Ack={ack}  Win={win}")
                if payload:
                    log("  📦  Payload:")
                    log(format_payload(payload))

            elif proto == 17:  # UDP
                stats["UDP"] += 1
                if len(segment) < 8:
                    continue
                sport, dport, length, chk = struct.unpack("! H H H H", segment[:8])
                payload = segment[8:]
                log(f"[{ts}] 🟢  UDP  {src_ip}:{sport}  →  {dst_ip}:{dport}", Color.GREEN)
                log(f"  TTL={ttl}  Length={length}")
                if payload:
                    log("  📦  Payload:")
                    log(format_payload(payload))

            elif proto == 1:  # ICMP
                stats["ICMP"] += 1
                if len(segment) < 4:
                    continue
                icmp_type, code, chk = struct.unpack("! B B H", segment[:4])
                types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable"}
                itype = types.get(icmp_type, f"Type-{icmp_type}")
                log(f"[{ts}] 🟠  ICMP {src_ip}  →  {dst_ip}  [{itype}]", Color.MAGENTA)
                log(f"  TTL={ttl}  Code={code}")
            else:
                stats["OTHER"] += 1
                log(f"[{ts}] ❓  Proto={proto}  {src_ip}  →  {dst_ip}", Color.WHITE)
        else:
            stats["OTHER"] += 1

# ─── Print Summary ─────────────────────────────────────────────────────────────
def print_summary():
    separator("═")
    log(f"\n{Color.BOLD}📊  CAPTURE SUMMARY{Color.RESET}")
    log(f"  Total Packets : {stats['total']}")
    log(f"  TCP           : {stats['TCP']}", Color.BLUE)
    log(f"  UDP           : {stats['UDP']}", Color.GREEN)
    log(f"  ICMP          : {stats['ICMP']}", Color.MAGENTA)
    log(f"  ARP           : {stats['ARP']}", Color.YELLOW)
    log(f"  DNS (subset)  : {stats['DNS']}", Color.CYAN)
    log(f"  Other         : {stats['OTHER']}", Color.WHITE)
    separator("═")

# ─── Save log ──────────────────────────────────────────────────────────────────
def save_log(path):
    with open(path, "w") as f:
        f.write("\n".join(log_lines))
    print(f"{Color.GREEN}[✔] Log saved to: {path}{Color.RESET}")

# ─── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="CodeAlpha Task 1 — Basic Network Sniffer",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-i", "--interface", default="eth0",
                        help="Network interface to sniff on (default: eth0)")
    parser.add_argument("-c", "--count", type=int, default=50,
                        help="Number of packets to capture (default: 50)")
    parser.add_argument("-o", "--output", default=None,
                        help="Save captured data to a log file")
    args = parser.parse_args()

    banner = f"""
{Color.CYAN}{Color.BOLD}
╔══════════════════════════════════════════════════╗
║        🌐  CodeAlpha — Network Sniffer           ║
║        Task 1 | Cybersecurity Internship         ║
╚══════════════════════════════════════════════════╝
  Interface : {args.interface}
  Packets   : {args.count}
  Backend   : {"Scapy" if USE_SCAPY else "Raw Socket"}
  Output    : {args.output or "Console only"}
{Color.RESET}"""
    print(banner)

    try:
        if USE_SCAPY:
            sniff(
                iface=args.interface,
                count=args.count,
                prn=lambda pkt: scapy_callback(pkt, args.output),
                store=False
            )
        else:
            raw_socket_sniffer(count=args.count, output_file=args.output)
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}[!] Stopped by user.{Color.RESET}")
    except PermissionError:
        print(f"{Color.RED}[!] Permission denied. Run with: sudo python3 network_sniffer.py{Color.RESET}")
        sys.exit(1)

    print_summary()

    if args.output:
        save_log(args.output)


if __name__ == "__main__":
    main()
