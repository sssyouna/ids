from scapy.all import sniff, TCP, IP, Raw
from collections import defaultdict
import time
import logging

import datetime

def custom_formatter(msg):
    timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    return f'{timestamp} - {msg}'

# Custom logger to control format
logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = logging.FileHandler('/app/logs/honeypot.log')
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

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
                logger.info(custom_formatter(f"[WARNING] Port scan detected from {src}"))

    # 🔍 Suspicious HTTP access
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")
        if "GET /admin" in payload:
            src = packet[IP].src
            logger.info(custom_formatter(f"[WARNING] Suspicious /admin access from {src}"))

    # 🔍 Brute-force behavior
    if packet.haslayer(IP):
        src = packet[IP].src
        now = time.time()

        request_times[src].append(now)
        request_times[src] = [t for t in request_times[src] if now - t < 10]

        if len(request_times[src]) > 20:
            logger.info(custom_formatter(f"[WARNING] Possible brute force from {src}"))

def start_ids():
    print("[*] IDS started (Scapy sniffing)")
    sniff(prn=detect_attacks, store=False)


if __name__ == "__main__":
    start_ids()
