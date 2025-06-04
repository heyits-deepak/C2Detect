# dashboard.py
import streamlit as st
import os
import pandas as pd
import io
import matplotlib.pyplot as plt

from dotenv import load_dotenv
from parser.zeek_parser import parse_connlog
from analysis.detector import detect_beaconing
from intel.enrich import enrich_ip_virustotal, get_geo_asn
from snort.compare_results import read_snort_alerts
from snort.run_snort import run_snort_on_pcap

# Load environment variables
load_dotenv()
api_key = os.getenv("VT_API_KEY")

# UI config
st.set_page_config(page_title="🔐 Beaconing Detection (Zeek conn.log)", layout="wide")
st.title("📡 Zeek conn.log to Beacon Detection Dashboard")
st.caption("Upload a Zeek-generated conn.log file to detect C2 beaconing, enrich with threat intel, and compare with Snort alerts.")

# File uploader for Zeek conn.log
uploaded_log = st.file_uploader("📄 Upload conn.log (generated manually using Zeek)", type=["log"])

if uploaded_log is not None:
    os.makedirs("logs", exist_ok=True)
    connlog_path = os.path.join("logs", "conn.log")

    # Save uploaded conn.log
    with open(connlog_path, "wb") as f:
        f.write(uploaded_log.read())

    st.info("📊 Parsing conn.log and analyzing flows...")
    df = parse_connlog(connlog_path)

    if df.empty:
        st.error("❌ Failed to parse conn.log. Make sure it's a valid Zeek log.")
        st.stop()

    results = detect_beaconing(df)
    snort_success = run_snort_on_pcap("pcaps/temp_uploaded.pcap")  # optional if needed
    snort_alerts = read_snort_alerts("snort/snort_alerts.txt") if snort_success else set()

    if not results:
        st.success("✅ No suspicious beaconing behavior detected.")
    else:
        st.warning(f"⚠️ {len(results)} potential beaconing flows identified.")
        export_data = []

        for src, dst, count, std, intervals in results:
            flagged_by_snort = (src, dst) in snort_alerts
            with st.expander(f"🔍 {src} ➝ {dst} | Count: {count} | Std Dev: {std:.2f} | Snort: {'✅' if flagged_by_snort else '❌'}"):
                # 📈 Use matplotlib for clearer plot
                fig, ax = plt.subplots()
                ax.plot(range(len(intervals)), intervals, marker='o')
                ax.set_title("Beaconing Intervals")
                ax.set_xlabel("Connection Index")
                ax.set_ylabel("Interval (seconds)")
                st.pyplot(fig)

                vt_info = enrich_ip_virustotal(dst, api_key)
                geo_info = get_geo_asn(dst)

                col1, col2 = st.columns(2)
                with col1:
                    st.metric("🌍 Country", geo_info.get("country", "Unknown"))
                    st.metric("🏢 Org", geo_info.get("org", "Unknown"))
                    st.metric("🔢 ASN", geo_info.get("asn", "N/A"))
                with col2:
                    if vt_info:
                        st.metric("🛡️ Malicious", vt_info.get("malicious", 0))
                        st.metric("⚠️ Suspicious", vt_info.get("suspicious", 0))
                        st.metric("✅ Harmless", vt_info.get("harmless", 0))
                    else:
                        st.warning("No VirusTotal data available.")

                export_data.append({
                    "Source IP": src,
                    "Destination IP": dst,
                    "Count": count,
                    "Std Dev": round(std, 2),
                    "Snort Detected": "Yes" if flagged_by_snort else "No",
                    "Country": geo_info.get("country", ""),
                    "ASN": geo_info.get("asn", ""),
                    "Org": geo_info.get("org", ""),
                    "VT Malicious": vt_info.get("malicious", "") if vt_info else "",
                    "VT Suspicious": vt_info.get("suspicious", "") if vt_info else "",
                    "VT Harmless": vt_info.get("harmless", "") if vt_info else ""
                })

        # 📥 Export to CSV
        df_export = pd.DataFrame(export_data)
        csv_buffer = io.StringIO()
        df_export.to_csv(csv_buffer, index=False)
        st.download_button(
            label="📥 Export Results as CSV",
            data=csv_buffer.getvalue(),
            file_name="beaconing_results.csv",
            mime="text/csv"
        )
