import argparse
from collections import Counter, defaultdict
from datetime import datetime
import ipaddress
import math
import threading
import time
from scapy.all import DNS, DNSQR, ICMP, IP, PcapWriter, TCP, UDP, sniff

# --- IoT Policy & Detection Thresholds ---
IOT_SUBNET = ipaddress.ip_network("192.168.50.0/24")
AUTHORIZED_IOT_DESTINATIONS = {"192.168.50.1", "192.168.50.5", "127.0.0.1"}

DNS_QUERY_MAX_LEN = 52
DNS_ENTROPY_THRESHOLD = 3.8
DNS_MIN_SUBDOMAIN_LEN = 12
SCAN_THRESHOLD = 15
TIME_WINDOW = 5

# --- IPS Strike Tracking ---
STRIKE_THRESHOLD = 3
STRIKE_WINDOW = 60
SAFELIST_IPS = {"127.0.0.1", "192.168.1.1", "192.168.50.1", "192.168.50.5"}

connection_tracker = defaultdict(list)
ip_strikes = defaultdict(list)
blocked_ips = set()
metrics_lock = threading.Lock()
traffic_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0, "total_bytes": 0}
pcap_writer = None


def print_metrics_loop():
  """Prints a live traffic summary to the terminal every 5 seconds."""
  while True:
    time.sleep(5)
    with metrics_lock:
      s = traffic_stats.copy()
      for k in traffic_stats:
        traffic_stats[k] = 0
    print(
        f"[STATS 5s] TCP: {s['TCP']} | UDP: {s['UDP']} | ICMP: {s['ICMP']} |"
        f" Bytes: {s['total_bytes']}"
    )


def trigger_alert(alert_type, src_ip, dst_ip, details):
  """Logs security alerts to the console and appends them to alerts.log."""
  timestamp = datetime.now().strftime("%H:%M:%S")
  log_line = (
      f"[{timestamp}] [ALERT] {alert_type:<25} | {src_ip:<15} ->"
      f" {dst_ip:<15} | {details}"
  )
  print(log_line)

  with open("alerts.log", "a", encoding="utf-8") as f:
    f.write(log_line + "\n")

  if src_ip not in SAFELIST_IPS and src_ip not in blocked_ips:
    now = time.time()
    ip_strikes[src_ip].append(now)
    ip_strikes[src_ip] = [
        t for t in ip_strikes[src_ip] if now - t <= STRIKE_WINDOW
    ]
    if len(ip_strikes[src_ip]) >= STRIKE_THRESHOLD:
      blocked_ips.add(src_ip)
      print(
          f"[{timestamp}] [IPS BLOCKED] {src_ip} exceeded {STRIKE_THRESHOLD}"
          f" strikes (trigger: {alert_type})"
      )


def is_iot_device(ip_str):
  try:
    return ipaddress.ip_address(ip_str) in IOT_SUBNET
  except ValueError:
    return False


def calculate_shannon_entropy(text):
  if not text:
    return 0.0
  length = len(text)
  counts = Counter(text)
  return -sum(
      (count / length) * math.log2(count / length) for count in counts.values()
  )


def inspect_dns_tunneling(dns_query, src_ip, dst_ip):
  if len(dns_query) > DNS_QUERY_MAX_LEN:
    trigger_alert(
        "DNS_TUNNELING_LENGTH",
        src_ip,
        dst_ip,
        f"Length {len(dns_query)} chars: {dns_query[:35]}...",
    )
    return

  labels = dns_query.split(".")
  if len(labels) > 2:
    subdomain_payload = "".join(labels[:-2])
    if len(subdomain_payload) >= DNS_MIN_SUBDOMAIN_LEN:
      entropy = calculate_shannon_entropy(subdomain_payload)
      if entropy >= DNS_ENTROPY_THRESHOLD:
        trigger_alert(
            "DNS_TUNNELING_ENTROPY",
            src_ip,
            dst_ip,
            f"Entropy {entropy:.2f} bits: {subdomain_payload[:30]}",
        )


def analyze_packet(packet):
  if pcap_writer is not None:
    pcap_writer.write(packet)

  if not packet.haslayer(IP):
    return

  ip_layer = packet[IP]
  src_ip = ip_layer.src
  dst_ip = ip_layer.dst
  pkt_len = len(packet)

  with metrics_lock:
    traffic_stats["total_bytes"] += pkt_len
    if packet.haslayer(TCP):
      traffic_stats["TCP"] += 1
    elif packet.haslayer(UDP):
      traffic_stats["UDP"] += 1
    elif packet.haslayer(ICMP):
      traffic_stats["ICMP"] += 1
    else:
      traffic_stats["OTHER"] += 1

  # 1. IoT Outbound Policy
  if is_iot_device(src_ip) and dst_ip not in AUTHORIZED_IOT_DESTINATIONS:
    trigger_alert(
        "IOT_UNAUTHORIZED_OUTBOUND",
        src_ip,
        dst_ip,
        "Unapproved external destination",
    )

  # 2. Packet Size Anomalies
  if pkt_len > 1500:
    trigger_alert("OVERSIZED_PACKET", src_ip, dst_ip, f"Length: {pkt_len}B")

  if packet.haslayer(ICMP) and pkt_len > 128:
    trigger_alert(
        "SUSPICIOUS_ICMP", src_ip, dst_ip, f"ICMP payload: {pkt_len}B"
    )

  # 3. TCP Header, Scan Velocity & IoT Protocols
  if packet.haslayer(TCP):
    tcp_layer = packet[TCP]
    flags = tcp_layer.flags
    dport = tcp_layer.dport
    sport = tcp_layer.sport

    if dport == 1883 or sport == 1883:
      trigger_alert(
          "UNENCRYPTED_MQTT", src_ip, dst_ip, "Cleartext MQTT on port 1883"
      )

    if dport in (23, 2323):
      trigger_alert(
          "INSECURE_IOT_TELNET", src_ip, dst_ip, f"Telnet on port {dport}"
      )

    if flags == 0x29:
      trigger_alert("XMAS_SCAN", src_ip, dst_ip, f"Dst Port: {dport}")
    elif flags == 0:
      trigger_alert("NULL_SCAN", src_ip, dst_ip, f"Dst Port: {dport}")

    if flags == "S":
      now = time.time()
      connection_tracker[src_ip].append((now, dport))
      connection_tracker[src_ip] = [
          (t, p)
          for t, p in connection_tracker[src_ip]
          if now - t <= TIME_WINDOW
      ]
      unique_ports = {p for _, p in connection_tracker[src_ip]}
      if len(unique_ports) >= SCAN_THRESHOLD:
        trigger_alert(
            "PORT_SCAN_DETECTED",
            src_ip,
            dst_ip,
            f"{len(unique_ports)} ports in {TIME_WINDOW}s",
        )
        connection_tracker[src_ip].clear()

  # 4. DNS Tunneling Detection
  if packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSQR):
    dns_query = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
    inspect_dns_tunneling(dns_query, src_ip, dst_ip)


if __name__ == "__main__":
  parser = argparse.ArgumentParser(
      description="Standalone Network Threat Analyzer (Wireshark PCAP Compatible)"
  )
  parser.add_argument(
      "-i", "--iface", type=str, default=None, help="Network interface to sniff"
  )
  parser.add_argument(
      "-p",
      "--pcap",
      type=str,
      default=None,
      help="Read and analyze an offline Wireshark .pcap file",
  )
  parser.add_argument(
      "-e",
      "--export-pcap",
      type=str,
      default=None,
      help="Save captured packets to a .pcap file for Wireshark",
  )
  args = parser.parse_args()

  if args.export_pcap:
    pcap_writer = PcapWriter(args.export_pcap, append=True, sync=True)
    print(f"[*] Exporting captured packets to Wireshark file: {args.export_pcap}")

  try:
    if args.pcap:
      print(f"[*] Analyzing Wireshark PCAP file: {args.pcap}\n")
      sniff(offline=args.pcap, prn=analyze_packet, store=False)
      print("\n[+] PCAP analysis complete.")
    else:
      threading.Thread(target=print_metrics_loop, daemon=True).start()
      print("Standalone Network Threat Analyzer running (Ctrl+C to stop)...")
      print("Logging all detections to console and alerts.log\n")
      sniff(iface=args.iface, prn=analyze_packet, store=False)
  except KeyboardInterrupt:
    print("\nStopped.")
  finally:
    if pcap_writer is not None:
      pcap_writer.close()