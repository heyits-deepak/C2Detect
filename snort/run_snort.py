import subprocess
import os

def run_snort_on_pcap(pcap_path, output_path="snort/snort_alerts.txt"):
    os.makedirs("snort", exist_ok=True)
    try:
        result = subprocess.run(
            ["snort", "-r", pcap_path, "-A", "console", "-c", "/etc/snort/snort.conf"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60
        )
        with open(output_path, "w") as f:
            f.write(result.stdout)
        return True
    except Exception as e:
        print(f"❌ Snort failed: {e}")
        return False
