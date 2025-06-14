# SilentSniffer 🐍
A passive network reconnaissance tool written in Python. Captures and logs ARP, DNS, and HTTP traffic silently from the local network.

## 🔧 Features
- Passive host discovery (via ARP sniffing)
- DNS request logging
- HTTP GET/POST sniffing
- MAC-to-vendor resolution
- Logs output to file

## 🚀 Usage
```bash
sudo python3 silent_sniffer.py -i eth0
```

## 📦 Requirements
- Python 3
- Scapy

Install dependencies:
```bash
pip install scapy
```

## ⚠️ Legal Disclaimer
Use for authorized security testing and educational purposes only.

## 📁 Folder Structure
- silent_sniffer.py
- logs/
- README.md

## 👤 Author
Made by Niraj Ashtaputre
