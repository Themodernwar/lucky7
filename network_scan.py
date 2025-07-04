import socket
import ipaddress
import psutil
from typing import List, Dict

COMMON_PORTS = [22, 80, 443, 3389, 445, 139, 21, 25, 8080]

def get_local_subnets():
    """Return a list of (interface, IPv4Network) for active adapters."""
    subnets = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address
                netmask = addr.netmask
                if not ip or ip.startswith("127."):
                    continue
                if not netmask:
                    continue
                try:
                    prefix = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
                except Exception:
                    continue
                network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                subnets.append((iface, network))
    return subnets

def scan_ports(ip: str, ports: List[int]) -> List[int]:
    """Scan common ports on a single IP, returning the list of open ports."""
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except Exception:
            pass
    return open_ports

def scan_network() -> List[Dict[str, object]]:
    """Scan all local subnets for devices with open ports."""
    results = []
    subnets = get_local_subnets()
    for iface, network in subnets:
        for host in network.hosts():
            ip_str = str(host)
            ports = scan_ports(ip_str, COMMON_PORTS)
            if ports:
                results.append({"interface": iface, "ip": ip_str, "ports": ports})
    return results

if __name__ == "__main__":
    devices = scan_network()
    for dev in devices:
        print(f"{dev['ip']} ({dev['interface']}) -> open ports: {dev['ports']}")
