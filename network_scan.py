import os
import json
from datetime import datetime
import psutil
from config import CONFIG_DIR
import reputation
import config as cfg_module

# Baseline file for known network connections
BASELINE_FILE = os.path.join(CONFIG_DIR, "network_baseline.json")


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
        ip = conn.split(":")[0]
        rep_status, rep_details = reputation.get_ip_reputation(ip, global_config)
        for d in details:
            event = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "process_name": d["process_name"],
                "pid": d["pid"],
                "reason": f"New network connection: {conn}",
                "connections": conn,
                "reputation": rep_status,
                "reputation_details": rep_details,
            }
            events.append(event)
            print(
                f"[ALERT] {event['timestamp']}: {event['process_name']} (PID: {event['pid']}) => {event['reason']} | Reputation: {rep_status}"
            )

    if events:
        # Update baseline so repeated scans don't flag the same connections again
        save_baseline(current_conns)
    else:
        print("[INFO] No new network connections detected.")

    return events
