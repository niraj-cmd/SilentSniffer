from scapy.all import sniff, ARP, DNS, IP
import logging

logging.basicConfig(filename='logs/captured.log', level=logging.INFO)

def process_packet(packet):
    if packet.haslayer(ARP):
        logging.info(f"ARP Packet: {packet.psrc} is at {packet.hwsrc}")
    elif packet.haslayer(DNS):
        logging.info(f"DNS Request: {packet[IP].src} asked for {packet[DNS].qd.qname.decode()}")

sniff(prn=process_packet, store=0)
