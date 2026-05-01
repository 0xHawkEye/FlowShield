import pandas as pd
import numpy as np
import glob
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

DATASET_FOLDER = "dataset_2018"
OUTPUT_MODEL = "flowshield_brain_complete.pkl"

print(f"[*] STARTING TRAINING")

ATTACK_TYPES = {
    "Brute Force": "Bruteforce",
    "DoS": "DoS",
    "DDoS": "DDoS",
    "Web Attacks": "Web",
    "Botnet": "Botnet",
    "Infiltration": "Infil"
}

master_data = []

for attack_name, keyword in ATTACK_TYPES.items():
    search_pattern = os.path.join(DATASET_FOLDER, f"*{keyword}*.parquet")
    found_files = glob.glob(search_pattern)

    if not found_files:
        continue

    for file in found_files:
        print(f"   - Processing {os.path.basename(file)}...", end=" ")
        try:
            df = pd.read_parquet(file)
            df.columns = df.columns.str.strip()

            rename_map = {
                'Protocol': 'proto',
                'Tot Fwd Pkts': 'packet_count', 'Total Fwd Packets': 'packet_count',
                'TotLen Fwd Pkts': 'len', 'Total Length of Fwd Packets': 'len', 'Fwd Packets Length Total': 'len',
                'Flow Duration': 'duration',
                'Flow Bytes/s': 'bytes_rate',
                'Flow Packets/s': 'packets_rate',
                'SYN Flag Count': 'syn_count',
                'ACK Flag Count': 'ack_count',
                'FIN Flag Count': 'fin_count',
                'PSH Flag Count': 'psh_count',
                'Label': 'label'
            }
            df = df.rename(columns=rename_map)

            required_cols = ['proto', 'packet_count', 'len', 'duration', 'bytes_rate', 'packets_rate',
                             'syn_count', 'ack_count', 'fin_count', 'psh_count', 'label']

            if not set(required_cols).issubset(df.columns):
                print("Skipped (Missing Flags)")
                continue

            df = df.replace([np.inf, -np.inf], np.nan).dropna()

            attacks = df[df['label'] != "Benign"]
            benign = df[df['label'] == "Benign"]
            if len(benign) > 0: benign = benign.sample(frac=0.1, random_state=42)

            balanced_df = pd.concat([attacks, benign])
            master_data.append(balanced_df[required_cols])
            print(f"Loaded")

        except Exception as e:
            print(f"Error: {e}")

if not master_data:
    print("\nError: No data loaded.")
    exit()

full_data = pd.concat(master_data, ignore_index=True)
full_data['label'] = full_data['label'].apply(lambda x: 0 if str(x) == "Benign" else 1)

print(f"[*] Training on {len(full_data)} flows with 10 Features...")
X = full_data.drop(columns=['label'])
y = full_data['label']

model = RandomForestClassifier(n_estimators=100, max_depth=25, n_jobs=-1)
model.fit(X, y)

print(f"\nMODEL TRAINED! Saved to '{OUTPUT_MODEL}'")
joblib.dump(model, OUTPUT_MODEL, compress=3)