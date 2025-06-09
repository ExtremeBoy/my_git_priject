import argparse
import ipaddress
import socket
from scapy.all import ARP, Ether, srp


def get_hostname(ip):
    """Try to resolve host name for the given IP."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror):
        return ""


def scan_network(network, mac_prefix):
    """Scan the given network and return devices whose MAC starts with mac_prefix."""
    try:
        network = ipaddress.ip_network(network, strict=False)
    except ValueError:
        print(f"Invalid network: {network}")
        return []

    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(network)),
        timeout=2,
        verbose=False,
    )

    results = []
    for _sent, received in answered:
        if received.hwsrc.lower().startswith(mac_prefix.lower()):
            hostname = get_hostname(received.psrc)
            results.append((received.psrc, received.hwsrc, hostname))
    return results


def main():
    parser = argparse.ArgumentParser(description="Find devices by MAC prefix using ARP broadcast")
    parser.add_argument("--network", default="192.168.1.0/24", help="Network to scan in CIDR notation")
    parser.add_argument("--mac-prefix", required=True, help="MAC address prefix to search for, e.g. 00:11:22")

    args = parser.parse_args()
    devices = scan_network(args.network, args.mac_prefix)

    if not devices:
        print("No devices found")
    else:
        print("Found devices:")
        for ip, mac, hostname in devices:
            if hostname:
                print(f"{ip} - {mac} - {hostname}")
            else:
                print(f"{ip} - {mac}")


if __name__ == "__main__":
    main()
