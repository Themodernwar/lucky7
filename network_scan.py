import os
import json
from datetime import datetime
import psutil
import socket
from config import CONFIG_DIR
import reputation
import config as cfg_module

# Baseline file for known network connections
BASELINE_FILE = os.path.join(CONFIG_DIR, "network_baseline.json")


def get_remote_banner(ip, port, timeout=2):
    """Return a short banner or header string for the remote service."""
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # Send a simple HTTP HEAD request if it looks like a web port
            if str(port) in {"80", "8080", "443"}:
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                except Exception:
                    pass
            try:
                data = sock.recv(256)
                return data.decode(errors="ignore").strip()
            except Exception:
                return ""
    except Exception:
        return ""


def infer_purpose(banner):
    """Guess the remote service purpose from its banner."""
    if not banner:
        return "Unknown"
    b = banner.lower()
    if "ssh" in b:
        return "SSH Server"
    if "smtp" in b:
        return "Mail Server"
    if "ftp" in b:
        return "FTP Server"
    if "mysql" in b or "postgres" in b:
        return "Database Server"
    if "http" in b or "server:" in b or "html" in b:
        return "Web Server"
    return "Unknown"


def load_baseline():
    """Load the network baseline if it exists."""
    if not os.path.exists(BASELINE_FILE):
        return None
    with open(BASELINE_FILE, "r") as f:
        return set(json.load(f))


def save_baseline(connections):
    """Save the current set of connections as the baseline."""
    with open(BASELINE_FILE, "w") as f:
        json.dump(list(connections), f, indent=4)


def get_current_connections():
    """Return current remote connections and details."""
    connections = set()
    connection_details = {}
    for conn in psutil.net_connections(kind="inet"):
        if conn.raddr:
            conn_str = f"{conn.raddr.ip}:{conn.raddr.port}"
            connections.add(conn_str)
            pid = conn.pid
            try:
                proc = psutil.Process(pid) if pid else None
                pname = proc.name() if proc else "Unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pname = "Unknown"
            connection_details.setdefault(conn_str, []).append(
                {
                    "pid": pid,
                    "process_name": pname,
                    "local_port": conn.laddr.port,
                }
            )
    return connections, connection_details


def scan_network():
    """Scan current network connections and flag new or untrusted ones."""
    current_conns, conn_details = get_current_connections()
    baseline = load_baseline()

    if baseline is None:
        save_baseline(current_conns)
        print("[INFO] No network baseline found. Created new baseline.")
        print("       Run the scan again to detect new connections.")
        return []

    events = []
    global_config = cfg_module.load_config() or cfg_module.DEFAULT_CONFIG

    new_conns = current_conns - baseline
    for conn in new_conns:
        details = conn_details.get(conn, [])
        ip, port = conn.split(":")
        rep_status, rep_details = reputation.get_ip_reputation(ip, global_config)
        banner = get_remote_banner(ip, port)
        purpose = infer_purpose(banner)
        for d in details:
            event = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "process_name": d["process_name"],
                "pid": d["pid"],
                "reason": f"New network connection: {conn}",
                "connections": conn,
                "reputation": rep_status,
                "reputation_details": rep_details,
                "banner": banner,
                "purpose": purpose,
            }
            events.append(event)
            print(
                f"[ALERT] {event['timestamp']}: {event['process_name']} (PID: {event['pid']}) => {event['reason']} | Reputation: {rep_status} | Purpose: {purpose}"
            )

    if events:
        # Update baseline so repeated scans don't flag the same connections again
        save_baseline(current_conns)
    else:
        print("[INFO] No new network connections detected.")

    return events
