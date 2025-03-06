from scripts.network_scanner import scan_network
from scripts.port_scanner import scan_ports
from scripts.anomaly_detection import detect_anomalies
import os
import socket
import ipaddress

def get_local_ip():
    """Get the local IP address of the machine."""
    try:
        # Create a socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Connect to an external server (doesn't actually send data)
        s.connect(("8.8.8.8", 80))
        # Get the local IP address
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Error getting local IP: {e}")
        return None

def get_network_range(ip):
    """Derive the network range from the local IP address."""
    try:
        # Create an IPv4Network object from the IP address
        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        return str(network)
    except Exception as e:
        print(f"Error deriving network range: {e}")
        return None

def main():
    # Get the local IP address
    local_ip = get_local_ip()
    if not local_ip:
        print("Could not determine local IP address.")
        return

    # Derive the network range
    network_range = get_network_range(local_ip)
    if not network_range:
        print("Could not determine network range.")
        return

    print(f"\nScanning Network: {network_range}")

    active_devices = scan_network(network_range)

    if not active_devices:
        print("No active devices found.")
        return

    print("\nScanning open ports for active devices...\n")
    for device in active_devices:
        ip = device["ip"]
        print(f"\nScanning: {ip}")
        scan_ports(ip)

    print("\nRunning Anomaly Detection on Scanned Data...")
    detect_anomalies()

if __name__ == "__main__":
    main()