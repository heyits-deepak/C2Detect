# 📡 Beaconing Detection Dashboard

An interactive threat hunting dashboard for detecting C2 (Command & Control) beaconing patterns using Zeek `conn.log`, and enriching the flows using threat intelligence APIs and Snort alerts.

---

## 🧰 Features

* 📁 Upload Zeek-generated `conn.log` (manually processed PCAPs).
* 📊 Detect suspicious beaconing patterns via interval and standard deviation analysis.
* 🌍 Enrich with GeoIP & ASN info.
* 🛡️ Enrich using VirusTotal for malicious, suspicious, and harmless indicators.
* 🚨 Match IP pairs with Snort alert output.
* 📈 Visualize beaconing intervals.
* 📤 Export findings to CSV.

---

## 🗂️ Project Structure

```
beacon_project/
├── analysis/
│   └── detector.py           # Beaconing detection logic
├── intel/
│   └── enrich.py            # VirusTotal & GeoIP enrichment
├── logs/                    # Output Zeek logs (conn.log here)
├── parser/
│   └── zeek_parser.py       # Parses conn.log
├── pcaps/                   # Store raw PCAP files manually
├── snort/
│   ├── run_snort.py         # Runs Snort on PCAP
│   └── compare_results.py   # Parses snort_alerts.txt
├── visualize/
│   └── plot_beacons.py      # Beacon interval plotting
├── .env                     # API keys (e.g., VT_API_KEY)
├── Dashboard.py             # Main Streamlit app
├── main.py                  # Optional launcher
└── requirements.txt         # Python dependencies
```

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone <repo_url>
cd beacon_project
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Add API Key

Create a `.env` file:

```
VT_API_KEY=your_virustotal_api_key_here
```

### 4. Generate Zeek Logs (Manually)

Run Zeek on PCAP to generate conn.log:

```bash
cd logs
zeek -C -r ../pcaps/yourfile.pcap
```

### 5. Run the Streamlit Dashboard

```bash
streamlit run Dashboard.py
```

---

## 📦 Output

* Interactive UI for flow inspection
* Real-time interval chart for each flow
* VirusTotal and GeoIP annotations
* CSV export of summarized data

---

## 🔐 Requirements

* Python 3.8+
* Zeek (installed and in PATH)
* Snort (optional)
* VirusTotal API Key

---

## 📌 Notes

* This project **does not** automatically convert PCAP to Zeek logs.
* You must upload the `conn.log` file manually generated using Zeek.
* Project is modular. You can disable Snort/VT enrichment by editing `Dashboard.py`.

---

## 📄 License

MIT License
