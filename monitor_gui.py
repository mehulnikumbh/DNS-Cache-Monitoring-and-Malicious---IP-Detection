import requests
import time
import subprocess
import threading
import tkinter as tk
from tkinter import scrolledtext
import scapy.all as scapy
import os

# VirusTotal API Key
VIRUSTOTAL_API_KEY = "775c1aa074a247fab947badf921bad9a978a5eda040de455246c2030ad0b1796"

# Cache and stats
clean_ip_cache = set()
total_queries = 0
malicious_detections = 0

# GUI Setup
root = tk.Tk()
root.title("DNS Monitor Dashboard")
root.geometry("600x500")

# GUI Widgets
total_label = tk.Label(root, text="Total Queries: 0", font=("Arial", 12))
total_label.pack(pady=5)

malicious_label = tk.Label(root, text="Malicious Detections: 0", font=("Arial", 12))
malicious_label.pack(pady=5)

alert_log = scrolledtext.ScrolledText(root, height=18)
alert_log.pack(fill=tk.BOTH, expand=True, padx=10)

def load_log():
    if os.path.exists("alerts.log"):
        with open("alerts.log", "r") as f:
            alert_log.delete("1.0", tk.END)
            alert_log.insert(tk.END, f.read())

load_button = tk.Button(root, text="Reload Alert Log", command=load_log)
load_button.pack(pady=5)

# Update GUI every second
def update_gui():
    total_label.config(text=f"Total Queries: {total_queries}")
    malicious_label.config(text=f"Malicious Detections: {malicious_detections}")
    root.after(1000, update_gui)

# Check IP reputation using VirusTotal
def check_ip_reputation(ip):
    if ip in clean_ip_cache:
        return False

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        if malicious_count > 0:
            return True
        else:
            clean_ip_cache.add(ip)
            return False
    else:
        print(f"[ERROR] VirusTotal check failed for {ip} (Status: {response.status_code})")
        return False

# Block IP using Windows Firewall
def block_ip(ip):
    try:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name=BlockMalicious_{ip}", "dir=out", "action=block", f"remoteip={ip}"],
            check=True, shell=True
        )
        print(f"[FIREWALL] Blocked IP: {ip}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to block IP {ip}: {e}")

# Process each DNS packet
def process_packet(packet):
    global total_queries, malicious_detections

    if packet.haslayer(scapy.DNS) and packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        domain = packet[scapy.DNS].qd.qname.decode('utf-8') if packet[scapy.DNS].qd else None

        total_queries += 1

        if check_ip_reputation(ip_dst):
            malicious_detections += 1
            alert_msg = f"[ALERT] Malicious IP detected! {ip_dst} (Domain: {domain})"
            print(alert_msg)

            # Log to file
            with open("alerts.log", "a") as logfile:
                logfile.write(f"{time.ctime()} - {alert_msg}\n")

            # Block IP
            block_ip(ip_dst)

# Run packet sniffer in background
def start_monitoring():
    interface = "Wi-Fi"  # Change this to match your system's interface
    scapy.sniff(iface=interface, filter="udp port 53", prn=process_packet, store=False)

# Start monitoring in a new thread
monitor_thread = threading.Thread(target=start_monitoring)
monitor_thread.daemon = True
monitor_thread.start()

# Start GUI updates and mainloop
update_gui()
root.mainloop()
