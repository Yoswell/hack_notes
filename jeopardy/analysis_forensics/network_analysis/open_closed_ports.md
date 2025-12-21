### Port Scanning and Open/Closed Ports

In network analysis, identifying open and closed ports is crucial for understanding service availability and potential vulnerabilities. An open port listens for incoming connections, while a closed port rejects them. This is often analyzed in CTF challenges via PCAP files from port scans like Nmap.

Port scanning techniques include SYN scans, TCP connects, and UDP scans. Responses reveal port states based on TCP flags.

#### TCP Three-Way Handshake Basics
  * **SYN Packet**: Client sends `SYN=1` to initiate connection.
  * **SYN-ACK Packet**: Server responds with `SYN=1, ACK=1` if port is open.
  * **ACK Packet**: Client sends `ACK=1` to complete handshake.
  * **RST Packet**: Server sends `RST=1` (or `RST-ACK`) if port is closed, resetting the connection.

#### Port States

  * **Open**: Server responds with SYN-ACK, allowing connection.
  * **Closed**: Server responds with RST-ACK, rejecting connection.
  * **Filtered**: No response or ICMP unreachable (firewall blocking).

#### Scanning Techniques

  * **SYN Scan (Half-Open)**: Send SYN, wait for SYN-ACK (open) or RST (closed). Stealthy, doesn't complete handshake.
  * **TCP Connect Scan**: Full handshake; reliable but logged.
  * **UDP Scan**: Send UDP packets; open ports may respond, closed send ICMP port unreachable.
  * **Tools**: Nmap (`nmap -sS target`), Masscan, or manual with Scapy.

#### Wireshark Filters for Analysis

```bash
# Open ports: SYN-ACK responses
tcp.flags.syn == 1 and tcp.flags.ack == 1

# Closed ports: RST responses to SYN
tcp.flags.syn == 1 and tcp.flags.reset == 1

# Full handshake: SYN, SYN-ACK, ACK
tcp.flags.syn == 1 or (tcp.flags.syn == 1 and tcp.flags.ack == 1) or tcp.flags.ack == 1
```

#### Example Analysis

  * **Open Port (e.g., 80)**: Client SYN → Server SYN-ACK → Client ACK.
  * **Closed Port (e.g., 9999)**: Client SYN → Server RST-ACK.

#### Tips for CTF

  * Look for scan patterns in PCAPs to identify attacker IPs.
  * Correlate with service banners for open ports.
  * Use `tshark` to count responses: `tshark -r scan.pcap -Y "tcp.flags.reset == 1" | wc -l`

-----

**Made with love by VIsh0k**