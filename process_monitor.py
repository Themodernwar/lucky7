import os
import json
import psutil
from datetime import datetime
from config import CONFIG_DIR
import reputation
import config as cfg_module

# Define the baseline file location.
BASELINE_FILE = os.path.join(CONFIG_DIR, "baseline.json")

def load_baseline():
    """Loads the process baseline from the file."""
    if not os.path.exists(BASELINE_FILE):
        return None
    with open(BASELINE_FILE, "r") as f:
        baseline = json.load(f)
    return set(baseline)

def save_baseline(process_names):
    """Saves the current set of process names as the baseline."""
    with open(BASELINE_FILE, "w") as f:
        json.dump(list(process_names), f, indent=4)

def get_current_processes():
    """
    Retrieves current processes using psutil.
    Returns a set of process names and a dictionary mapping each process name to details.
    """
    processes = set()
    process_details = {}  # Mapping: process name -> list of (pid, create_time)
    for proc in psutil.process_iter(['name', 'pid', 'create_time']):
        try:
            name = proc.info['name']
            pid = proc.info['pid']
            create_time = proc.info['create_time']
            if name:
                processes.add(name)
                process_details.setdefault(name, []).append((pid, create_time))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return processes, process_details

def get_process_connections(pid):
    """
    Returns a list of remote IP addresses (with port) for the process.
    Uses psutil to retrieve network connections.
    """
    remote_ips = []
    try:
        proc = psutil.Process(pid)
        connections = proc.connections(kind='inet')
        for conn in connections:
            if conn.raddr:
                # Format as IP:port
                remote_ips.append(f"{conn.raddr.ip}:{conn.raddr.port}")
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    return remote_ips

def scan_processes(suspicious_keywords, process_whitelist, kworker_cpu_threshold):
    """
    Scans processes and compares them to a baseline. A process is flagged as suspicious if:
      - It is new (not in baseline) or matches any suspicious keyword.
    Processes whose names contain any whitelisted substring are skipped in the main loop.
    
    Then, in a separate loop, any process whose name contains "kworker" is checked for CPU usage,
    and if it exceeds the threshold, it is flagged.
    
    Each flagged event is enriched with network connection info from get_process_connections().
    
    If no baseline exists, one is created.
    """
    current_processes, process_details = get_current_processes()
    baseline = load_baseline()
    
    if baseline is None:
        save_baseline(current_processes)
        print("[INFO] No baseline found. A new baseline has been created with current processes.")
        print("       Please run the scan again to detect new or suspicious processes.")
        return []
    
    events = []
    global_config = cfg_module.load_config() or cfg_module.DEFAULT_CONFIG
    telemetry_keywords = global_config.get("monitoring", {}).get(
        "telemetry_keywords",
        cfg_module.DEFAULT_CONFIG.get("monitoring", {}).get("telemetry_keywords", []),
    )
    # Main loop: flag processes that are new or match suspicious keywords,
    # skipping any process if its name contains a whitelisted substring.
    for proc_name in current_processes:
        lower_proc = proc_name.lower()
        if any(whitelist_item.lower() in lower_proc for whitelist_item in process_whitelist):
            continue

        reasons = []
        if proc_name not in baseline:
            reasons.append("Not found in baseline")
        matched_keywords = [kw for kw in suspicious_keywords if kw.lower() in lower_proc]
        if matched_keywords:
            reasons.append(f"Matches keyword(s): {', '.join(matched_keywords)}")
        
        if reasons:
            details_list = process_details.get(proc_name, [])
            for (pid, create_time) in details_list:
                timestamp = datetime.fromtimestamp(create_time).strftime('%Y-%m-%d %H:%M:%S')
                connections = get_process_connections(pid)
                rep_status, rep_details = reputation.get_event_reputation(",".join(connections) if connections else "", global_config)
                event = {
                    "timestamp": timestamp,
                    "process_name": proc_name,
                    "pid": pid,
                    "reason": "; ".join(reasons),
                    "connections": ", ".join(connections) if connections else "",
                    "reputation": rep_status,# Summary status
                    "reputation_details":rep_details # Detailed lookup info (hidden by default)
                }
                events.append(event)
                print(f"[ALERT] {timestamp}: {proc_name} (PID: {pid}) => {event['reason']}| Reputation: {event['reputation']}")
                if connections:
                    print(f"        Connections: {event['connections']}")
    
    # Separate loop: Check all processes with "kworker" for high CPU usage.
    for proc in psutil.process_iter(['name', 'pid']):
        try:
            name = proc.info['name']
            if name and "kworker" in name.lower():
                cpu_usage = proc.cpu_percent(interval=0.1)
                if cpu_usage >= kworker_cpu_threshold:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    connections = get_process_connections(proc.info['pid'])
                    rep_status, rep_details = reputation.get_event_reputation(",".join(connections) if connections else "", global_config)
                    event = {
                        "timestamp": timestamp,
                        "process_name": name,
                        "pid": proc.info['pid'],
                        "reason": f"kworker high CPU usage: {cpu_usage}%",
                        "connections": ", ".join(connections) if connections else "",
                        "reputation": rep_status,
                        "reputation_details": rep_details
                    }
                    events.append(event)
                    print(f"[ALERT] {timestamp}: {name} (PID: {proc.info['pid']}) => kworker high CPU usage: {cpu_usage}%")
                    if connections:
                        print(f"        Connections: {event['connections']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Telemetry check: look for processes whose names indicate telemetry
    for proc in psutil.process_iter(['name', 'pid']):
        try:
            name = proc.info['name']
            if not name:
                continue
            lower = name.lower()
            if any(tk in lower for tk in telemetry_keywords):
                connections = get_process_connections(proc.info['pid'])
                if not connections:
                    continue
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                enc_states = []
                for conn in connections:
                    try:
                        port = int(conn.split(':')[1])
                        enc_states.append('encrypted' if port in [443, 8443] else 'unencrypted')
                    except (IndexError, ValueError):
                        enc_states.append('unknown')
                state = ','.join(sorted(set(enc_states)))
                reason = f"Telemetry transmission ({state})"
                rep_status, rep_details = reputation.get_event_reputation(",".join(connections), global_config)
                event = {
                    "timestamp": timestamp,
                    "process_name": name,
                    "pid": proc.info['pid'],
                    "reason": reason,
                    "connections": ", ".join(connections),
                    "reputation": rep_status,
                    "reputation_details": rep_details,
                }
                events.append(event)
                print(f"[ALERT] {timestamp}: {name} (PID: {proc.info['pid']}) => {reason} | Reputation: {rep_status}")
                print(f"        Connections: {event['connections']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if not events:
        print("[INFO] No suspicious processes detected.")
    return events

