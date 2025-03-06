import nmap
import pandas as pd
import os

DATA_PATH = "data/port_scan_results.csv"

def scan_ports(ip):
    scanner = nmap.PortScanner()
    print(f"\nScanning open ports for {ip}...\n")

    scanner.scan(ip, arguments='-T4 -F')

    if ip not in scanner.all_hosts():
        print(f"No open ports found for {ip}.")
        return

    port_data = []
    for port in scanner[ip].all_protocols():
        for p in scanner[ip][port]:
            state = scanner[ip][port][p]['state']
            service = scanner[ip][port][p]['name']
            port_data.append([ip, p, state, service])

    df_ports = pd.DataFrame(port_data, columns=["ip", "port", "state", "service"])

    os.makedirs("data", exist_ok=True)

    # Append instead of overwriting
    df_ports.to_csv(DATA_PATH, index=False, mode='a', header=not os.path.exists(DATA_PATH))

    print("\nPort scan results saved to", DATA_PATH)
