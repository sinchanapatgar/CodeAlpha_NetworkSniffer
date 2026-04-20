🌐 Task 1: Basic Network Sniffer — CodeAlpha Cybersecurity Internship
Overview
A Python-based network packet sniffer that captures and analyzes live network traffic.
It supports two backends:
Scapy (recommended) — richer protocol parsing, DNS, ARP, TCP flags
Raw Socket — built-in Python fallback (Linux only)
📦 Installation
# Clone your GitHub repo first
git clone https://github.com/YOUR_USERNAME/CodeAlpha_NetworkSniffer
cd CodeAlpha_NetworkSniffer

# Install dependency
pip install scapy
▶️ Usage
# Basic (default: eth0 interface, 50 packets)
sudo python3 network_sniffer.py

# Custom interface and count
sudo python3 network_sniffer.py -i wlan0 -c 100

# Save output to a log file
sudo python3 network_sniffer.py -i eth0 -c 50 -o capture.log
⚠️ Root/sudo is required for raw packet capturing on Linux/macOS.
📡 What It Captures
Protocol
Info Shown
TCP
Src/Dst IP & Port, Flags (SYN/ACK/FIN/RST), Seq/Ack, Payload
UDP
Src/Dst IP & Port, Length, Payload
ICMP
Src/Dst IP, Type (Echo Request/Reply, Dest Unreachable)
ARP
Sender/Target IP & MAC, Request vs Reply
DNS
Queries and Answers (domain names)
🖥️ Sample Output
╔══════════════════════════════════════════════════╗
║        🌐  CodeAlpha — Network Sniffer           ║
║        Task 1 | Cybersecurity Internship         ║
╚══════════════════════════════════════════════════╝

─────────────────────────────────────────────────────────────────
[12:45:03.421] 🔵  TCP  192.168.1.5:54321  →  142.250.80.46:443  [SYN]
  TTL=64  Seq=0  Ack=0  Win=65535
─────────────────────────────────────────────────────────────────
[12:45:03.510] 🟢  UDP  192.168.1.5:53  →  8.8.8.8:53
  TTL=64  Length=45
  🌐  DNS Query : www.google.com.
─────────────────────────────────────────────────────────────────

📊  CAPTURE SUMMARY
  Total Packets : 50
  TCP           : 28
  UDP           : 12
  ICMP          : 3
  ARP           : 2
  DNS (subset)  : 8
  Other         : 7
🔧 How It Works
Scapy's sniff() captures packets on a given interface
Each packet is dissected layer by layer (Ethernet → IP → TCP/UDP/ICMP)
Fields like IPs, ports, flags, TTL, and payloads are extracted and printed
Stats are accumulated and printed as a summary at the end
Optionally saved to a log file
📚 Libraries Used
scapy — packet crafting and sniffing
socket, struct — raw socket fallback
argparse — CLI argument handling
datetime — timestamping packets
⚠️ Legal Notice
This tool is for educational purposes only. Only use it on networks you own or have explicit permission to monitor. Unauthorized packet sniffing is illegal.
