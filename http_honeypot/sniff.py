from scapy.all import sniff, TCP, IP, Raw
from collections import defaultdict
import time
import logging

logging.basicConfig(
    filename='honeypot.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

scan_tracker = defaultdict(set)
request_times = defaultdict(list)

def detect_attacks(packet):
    # 🔍 Port scan detection
    if packet.haslayer(TCP) and packet.haslayer(IP):
        if packet[TCP].flags == "S":
            src = packet[IP].src
            dport = packet[TCP].dport
            scan_tracker[src].add(dport)

            if len(scan_tracker[src]) > 10:
                logging.info(f"[IDS] Port scan detected from {src}")

    # 🔍 Suspicious HTTP access
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")
        if "GET /admin" in payload:
            src = packet[IP].src
            logging.info(f"[IDS] Suspicious /admin access from {src}")

    # 🔍 Brute-force behavior
    if packet.haslayer(IP):
        src = packet[IP].src
        now = time.time()

        request_times[src].append(now)
        request_times[src] = [t for t in request_times[src] if now - t < 10]

        if len(request_times[src]) > 20:
            logging.info(f"[IDS] Possible brute force from {src}")

def start_ids():
    print("[*] IDS started (Scapy sniffing)")
    sniff(prn=detect_attacks, store=False)


if __name__ == "__main__":
    start_ids()
