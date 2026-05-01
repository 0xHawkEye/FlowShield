import time
import pandas as pd
import joblib
import threading
import sqlite3
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sniff

# config
MODEL_FILE = "flowshield_brain_complete.pkl"
DB_FILE = "flowshield_logs.db"
WHITELIST = ["192.168.29.1", "127.0.0.1"]
IGNORED_DESTINATIONS = ["239.255.255.250", "255.255.255.255", "13.35.20.122"]

print("[*] Starting FlowShield Engine...")
try:
    model = joblib.load(MODEL_FILE)
    print("[+] Model loaded successfully.")
except Exception as e:
    print(f"[-] Error loading model: {e}")
    exit(1)

active_flows = {}


def init_db():
    # sqlite db for web frontend
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alerts 
                 (id INTEGER PRIMARY KEY, timestamp REAL, src TEXT, dst TEXT, type TEXT, speed REAL)''')
    conn.commit()
    conn.close()


init_db()


def log_to_db(src, dst, reason, speed):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO alerts (timestamp, src, dst, type, speed) VALUES (?, ?, ?, ?, ?)",
                  (time.time(), src, dst, reason, speed))
        conn.commit()
        conn.close()
    except sqlite3.OperationalError:
        pass


def print_alert(src, dst, confidence, stats, pps, reason, is_threat):
    prefix = "[!!] THREAT" if is_threat else "[i] INFO"
    print(f"\n{prefix}: {src} -> {dst}")
    print(f" | Speed: {int(pps)} pps (Avg size: {int(stats['total_bytes'] / stats['packet_count'])}b)")
    print(f" | Flags: SYN={stats['syn_count']} ACK={stats['ack_count']}")
    print(f" | AI Confidence: {confidence * 100:.1f}%")
    print(f" | Verdict: {reason}")
    print("-" * 50)


def analyze_flow(flow_key, stats):
    src_ip, dst_ip, _, proto = flow_key
    curr_time = time.time()

    time_diff = curr_time - stats['last_check']
    if time_diff == 0:
        time_diff = 0.0001

    pkt_diff = stats['packet_count'] - stats['last_packet_count_marker']
    pps = pkt_diff / time_diff
    avg_size = stats['total_bytes'] / (stats['packet_count'] + 0.1)
    duration = (curr_time - stats['start_time']) * 1000000

    features = pd.DataFrame([{
        'proto': proto,
        'packet_count': stats['packet_count'],
        'len': stats['total_bytes'],
        'duration': duration,
        'bytes_rate': stats['total_bytes'] / time_diff,
        'packets_rate': pps,
        'syn_count': stats['syn_count'],
        'ack_count': stats['ack_count'],
        'fin_count': stats['fin_count'],
        'psh_count': stats['psh_count']
    }])

    try:
        pred = model.predict(features)[0]
        conf = model.predict_proba(features)[0][1]

        is_threat = False
        reason = "SAFE"

        if pred == 1 and conf > 0.60:
            is_threat = True
            reason = "AI Pattern Match"

        if pps > 20 and avg_size < 200:
            is_threat = True
            reason = f"Flood Detected ({int(pps)} pps)"
            conf = 1.0

        if stats['syn_count'] > 5 and stats['syn_count'] > (stats['ack_count'] * 3):
            is_threat = True
            reason = "Port Scan (SYN)"
            conf = 1.0

        if src_ip not in WHITELIST and dst_ip not in IGNORED_DESTINATIONS:
            if is_threat:
                log_to_db(src_ip, dst_ip, reason, pps)
                print_alert(src_ip, dst_ip, conf, stats, pps, reason, True)
            elif pps > 0:
                log_to_db(src_ip, dst_ip, "Normal Traffic", pps)

                # print_alert(src_ip, dst_ip, conf, stats, pps, "Normal Traffic", False)

    except Exception as e:
        pass


def packet_handler(pkt):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        length = len(pkt)
        proto = pkt[IP].proto

        flags = ""
        if TCP in pkt:
            flags = str(pkt[TCP].flags)

        flow_key = (src, dst, 0, proto)
        curr_time = time.time()

        if flow_key not in active_flows:
            active_flows[flow_key] = {
                'start_time': curr_time, 'packet_count': 0, 'total_bytes': 0,
                'syn_count': 0, 'ack_count': 0, 'fin_count': 0, 'psh_count': 0,
                'last_check': curr_time, 'last_packet_count_marker': 0
            }

        flow = active_flows[flow_key]
        flow['packet_count'] += 1
        flow['total_bytes'] += length

        if 'S' in flags: flow['syn_count'] += 1
        if 'A' in flags: flow['ack_count'] += 1
        if 'F' in flags: flow['fin_count'] += 1
        if 'P' in flags: flow['psh_count'] += 1

        if (curr_time - flow['last_check'] > 0.5):
            analyze_flow(flow_key, flow)
            flow['last_check'] = curr_time
            flow['last_packet_count_marker'] = flow['packet_count']


def session_cleanup():
    while True:
        time.sleep(5)
        curr = time.time()
        for k in list(active_flows.keys()):
            if curr - active_flows[k]['last_check'] > 10:
                del active_flows[k]


if __name__ == "__main__":
    t = threading.Thread(target=session_cleanup, daemon=True)
    t.start()

    print("[*] Sniffer running. Press Ctrl+C to stop.")
    sniff(prn=packet_handler, store=0)