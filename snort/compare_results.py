import os

def read_snort_alerts(snort_output_path):
    alerts = set()
    if not os.path.exists(snort_output_path):
        print("⚠️ Snort alert file not found. Skipping comparison.")
        return alerts
    with open(snort_output_path, "r") as f:
        for line in f:
            if "->" in line:
                parts = line.split()
                if len(parts) >= 5:
                    src = parts[2]
                    dst = parts[4].strip(":")
                    alerts.add((src, dst))
    return alerts
