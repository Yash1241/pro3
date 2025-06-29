import subprocess
import time
import re
import csv

L2_CONFIG = "l2firewall.config"
SEEN_MAC_IP = {}

def parse_flows():
    cmd = "sudo ovs-ofctl dump-flows s1"
    result = subprocess.run(cmd.split(), stdout=subprocess.PIPE)
    lines = result.stdout.decode().splitlines()
    return lines

def extract_mac_ip(flows):
    mac_ip_map = {}
    for line in flows:
        # Match only flows with nw_src (IP) and dl_src (MAC)
        match = re.search(r"nw_src=([\d\.]+).*dl_src=([0-9a-fA-F:]+)", line)
        if match:
            ip = match.group(1)
            mac = match.group(2)
            if mac not in mac_ip_map:
                mac_ip_map[mac] = set()
            mac_ip_map[mac].add(ip)
    return mac_ip_map

def detect_spoofing(mac_ip_map):
    spoofing_pairs = []
    for mac, ips in mac_ip_map.items():
        if len(ips) > 1:
            print(f"[!] MAC {mac} is associated with multiple IPs: {ips}")
            # Create spoofing rules (block this MAC)
            for ip in ips:
                spoofing_pairs.append((mac, "any"))  # We block MAC regardless of target
    return spoofing_pairs

def update_l2_config(spoofed_mac_pairs):
    with open(L2_CONFIG, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["mac_0", "mac_1"])
        for mac_0, mac_1 in spoofed_mac_pairs:
            writer.writerow([mac_0, mac_1])
    print("[+] l2firewall.config updated.")

def main():
    while True:
        print("\n[+] Monitoring flows...")
        flows = parse_flows()
        mac_ip_map = extract_mac_ip(flows)
        spoofed = detect_spoofing(mac_ip_map)
        if spoofed:
            update_l2_config(spoofed)
            print("[*] Restart POX to apply updated rules!")
            # Optional: trigger a signal or restart POX from here
        else:
            print("[✓] No spoofing detected.")
        time.sleep(10)  # Wait 10s before next check

if __name__ == "__main__":
    main()
