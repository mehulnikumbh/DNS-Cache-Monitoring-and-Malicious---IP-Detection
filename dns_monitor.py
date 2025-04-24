import requests
import json
import time
import subprocess
import scapy.all as scapy

# VirusTotal API Key
VIRUSTOTAL_API_KEY = "775c1aa074a247fab947badf921bad9a978a5eda040de455246c2030ad0b1796"

# Cache for clean IPs
clean_ip_cache = set()

# Statistics
total_queries = 0
malicious_detections = 0

# Function to check IP reputation using VirusTotal API
def check_ip_reputation(ip):
    if ip in clean_ip_cache:
        return False  # Skip check if already known as clean

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
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
        print(f"Error: Unable to fetch data for IP {ip}. Status Code: {response.status_code}")
        return False

# Function to block a malicious IP using Windows Firewall
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

# Function to process DNS packets
def process_packet(packet):
    global total_queries, malicious_detections

    if packet.haslayer(scapy.DNS) and packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        domain = packet[scapy.DNS].qd.qname.decode('utf-8') if packet[scapy.DNS].qd else None

        total_queries += 1
        print(f"DNS Query: {domain} | Source IP: {ip_src} | Destination IP: {ip_dst}")

        # Check if the destination IP is malicious
        if check_ip_reputation(ip_dst):
            malicious_detections += 1
            alert_msg = f"[ALERT] Malicious IP detected! {ip_dst} (Domain: {domain})"
            print(alert_msg)

            # Log to file
            with open("alerts.log", "a") as logfile:
                logfile.write(f"{time.ctime()} - {alert_msg}\n")

            # Block the malicious IP
            block_ip(ip_dst)

        # Print stats every 10 queries
        if total_queries % 10 == 0:
            print(f"\n--- Stats ---\nTotal Queries: {total_queries} | Malicious Detections: {malicious_detections}\n")

# Sniff DNS traffic on selected network interface
def start_dns_monitoring(interface):
    print(f"Starting DNS monitoring on interface: {interface}")
    scapy.sniff(iface=interface, filter="udp port 53", prn=process_packet, store=False)

if __name__ == "__main__":
    network_interface = "Wi-Fi"  # Change this to match your actual interface name
    start_dns_monitoring(network_interface)
