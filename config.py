import os
import yaml

# Define where the configuration will live
CONFIG_DIR = os.path.expanduser("~/.lucky7")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.yml")

# This is our default configuration for MVP User Story #1.
DEFAULT_CONFIG = {
    "monitoring": {
        "process": True,
        "network": False,
        "files": False,
        "suspicious_process_keywords":["miner","crypto","hack","illegal"],
        #Processes that should normally be ignored.
        "process_whitelist": ["systemd","init","bash","python","gnome-shell","Xorg","kworker"],
        #New: CPU usage threshold ( in percent) above which a kworker process is flagged
        "kworker_cpu_threshold": 20
    },
    "database": {
        "path": os.path.join(CONFIG_DIR, "lucky7.db")
    },
    "logging": {
        "level": "INFO"
    },
    "reputation": {
        "api_key": "", # If provided, VirusTotal will be used.

        # Either "virustotal" (if key provided) or fallback "geofencing".
        "method": "geofencing",
        # For geofencing: trusted if IP is located in this country.
        "geofence_country": "United States"
    }
}

def create_default_config():
    """
    Creates the configuration directory and a default config file if one doesn't exist.
    """
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)
        print(f"[INFO] Created config directory at: {CONFIG_DIR}")

    if os.path.exists(CONFIG_FILE):
        print(f"[WARN] Config file already exists at: {CONFIG_FILE}")
        return

    with open(CONFIG_FILE, "w") as f:
        yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False)
    print(f"[INFO] Default config created at: {CONFIG_FILE}")

def load_config():
    """
    Loads and returns the configuration from the config file.
    If the config file doesn't exist, informs the user to run 'init' first.
    """
    if not os.path.exists(CONFIG_FILE):
        print("[ERROR] No config file found. Please run 'lucky7 init' first.")
        return None

    with open(CONFIG_FILE, "r") as f:
        config = yaml.safe_load(f)
    return config

