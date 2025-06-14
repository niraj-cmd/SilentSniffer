# 🔎 SilentSniffer 🐍

**SilentSniffer** is a passive network reconnaissance tool written in Python. It silently captures and logs network activity including ARP, DNS, and HTTP traffic on a local network.

> ⚠️ Use only on networks you own or have permission to test.

---

## 🔧 Features

- 🌐 Passive host discovery (via ARP sniffing)
- 🧠 DNS request sniffing & logging
- 🕵️ HTTP GET/POST sniffing
- 🏷️ MAC-to-vendor lookup
- 🧾 Logging to TXT, CSV, and JSON
- 🎨 Clean terminal UI using `rich`

---

## 🚀 Usage

```bash
sudo python3 silent_sniffer.py -i eth0
```

You’ll be guided to:
- Choose network interface
- See active hosts
- Start sniffing with optional filtering
- Optionally perform ARP/DNS spoofing

---

## 📦 Requirements

- Python 3
- Scapy
- Rich
- Requests

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 📁 Folder Structure

```
SilentSniffer/
├── silent_sniffer.py
├── logs/
│   ├── sniffer_log.txt
│   ├── sniffer_log.csv
│   └── sniffer_log.json
├── README.md
└── requirements.txt
```

---

## ⚠️ Legal Disclaimer

This tool is intended **only for authorized testing and educational use**.  
Any misuse is strictly against the law and not supported by the developer.

---

## 👤 Author

**Niraj Ashtaputre**  
🔗 [GitHub: niraj-cmd](https://github.com/niraj-cmd)

---

## ⭐️ Like the Project?

Give it a ⭐️ on GitHub to support future development!
