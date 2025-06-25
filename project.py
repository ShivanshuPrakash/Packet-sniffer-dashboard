from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
import csv
from datetime import datetime

# 🔄 Create or overwrite the CSV file with headers
with open("traffic_log.csv", mode="w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "Source IP", "Dest IP", "Protocol", "Src Port", "Dst Port", "Payload"])

# 🧠 Analyze each packet
def analyze_packet(packet):
    src_ip = dst_ip = proto = src_port = dst_port = payload = ""

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if packet.haslayer(TCP):
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif packet.haslayer(UDP):
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        if packet.haslayer(Raw): 
            try:
                payload = packet[Raw].load.decode('utf-8')[:50]
            except:
                payload = "[Raw Data]"

        # 🖥️ Print packet info
        print(f"\n🔍 {proto} Packet: {src_ip} → {dst_ip}")
        print(f"    Ports: {src_port} → {dst_port}")
        if payload:
            print(f"    📄 Data: {payload}")

        # 📝 Save to CSV inside the function
        with open('traffic_log.csv', 'a', newline='') as f:
            writer = csv.writer(f)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            writer.writerow([timestamp, src_ip, dst_ip, proto, src_port, dst_port, payload])

# 🚦 Start sniffing (you can change filter)
sniff(filter="ip", prn=analyze_packet, store=0)
