import scapy.all as scapy
import pandas as pd
import os

DATA_PATH = "data/network_scan_data.csv"

def scan_network(network_range):
    active_devices = []
    print(f"\nScanning network: {network_range}\n")

    arp_request = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    print("IP Address\t\tMAC Address")
    print("----------------------------------------")

    for response in answered_list:
        ip = response[1].psrc
        mac = response[1].hwsrc
        print(f"{ip}\t\t{mac}")
        active_devices.append({"ip": ip, "mac": mac})

    # Ensure the data directory exists
    os.makedirs("data", exist_ok=True)

    # Convert to DataFrame and save to CSV
    df = pd.DataFrame(active_devices)
    df.to_csv(DATA_PATH, index=False)
    print("\nNetwork scan results saved to", DATA_PATH)

    return active_devices
