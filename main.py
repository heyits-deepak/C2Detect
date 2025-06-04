from dotenv import load_dotenv
import os
from parser.zeek_parser import parse_connlog
from analysis.detector import detect_beaconing
from visualize.plot_beacons import plot_intervals
from intel.enrich import enrich_ip_virustotal, get_geo_asn
from snort.compare_results import read_snort_alerts

# Load .env variables
load_dotenv()
api_key = os.getenv("VT_API_KEY")

# Load Zeek conn.log
log_path = "logs/conn.log"
df = parse_connlog(log_path)

# Detect potential beaconing behavior
results = detect_beaconing(df)

# Load Snort alerts
snort_alerts = read_snort_alerts("snort/snort_alerts.txt")  # ← Fixed path

# Display results with enrichment and Snort comparison
print("\n🧠 Beaconing Detection Results:\n" + "=" * 60)
for src, dst, count, std, intervals in results:
    flagged_by_snort = (src, dst) in snort_alerts
    print(f"{src} ➝ {dst} | Connections: {count} | Std Dev: {std:.2f} | Detected by Snort: {'✅' if flagged_by_snort else '❌'}")
    
    plot_intervals(intervals, src, dst)

    vt_info = enrich_ip_virustotal(dst, api_key)
    geo_info = get_geo_asn(dst)

    print(f"🌍 Country: {geo_info['country']}, ASN: {geo_info['asn']}, Org: {geo_info['org']}")
    if vt_info:
        print(f"🛡️ VirusTotal → Malicious: {vt_info['malicious']}, Suspicious: {vt_info['suspicious']}, Harmless: {vt_info['harmless']}")
    print("-" * 60)
