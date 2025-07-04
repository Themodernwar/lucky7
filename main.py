import argparse
import time
import config

def init_command():
    """
    Initializes the configuration and the local database.
    """
    config.create_default_config()
    import db
    db.init_db()

def start_command():
    """
    Loads configuration, runs the process monitoring scan,
    and saves any detected events to the database.
    """
    cfg = config.load_config()
    if cfg:
        print("[INFO] Configuration loaded successfully:")
        print(cfg)
        
        default_monitoring = config.DEFAULT_CONFIG.get("monitoring", {})
        suspicious_keywords = cfg.get("monitoring", {}).get(
            "suspicious_process_keywords", 
            default_monitoring.get("suspicious_process_keywords", [])
        )
        process_whitelist = cfg.get("monitoring", {}).get(
            "process_whitelist", 
            default_monitoring.get("process_whitelist", [])
        )
        kworker_cpu_threshold = cfg.get("monitoring", {}).get(
            "kworker_cpu_threshold", 
            default_monitoring.get("kworker_cpu_threshold", 20)
        )
        
        import process_monitor
        events = process_monitor.scan_processes(suspicious_keywords, process_whitelist, kworker_cpu_threshold)
        if events:
            print(f"[INFO] {len(events)} suspicious event(s) detected.")
            import db
            db.insert_events(events)
            print("[INFO] Events saved to the database.")
        else:
            print("[INFO] No suspicious events logged.")
    else:
        print("[ERROR] Could not load configuration. Please run 'lucky7 init' first.")

def monitor_command(args):
    """Continuously runs the monitoring scan at a specified interval."""
    cfg = config.load_config()
    if not cfg:
        print("[ERROR] Could not load configuration. Please run 'lucky7 init' first.")
        return

    interval = args.interval
    default_monitoring = config.DEFAULT_CONFIG.get("monitoring", {})
    suspicious_keywords = cfg.get("monitoring", {}).get(
        "suspicious_process_keywords",
        default_monitoring.get("suspicious_process_keywords", [])
    )
    process_whitelist = cfg.get("monitoring", {}).get(
        "process_whitelist",
        default_monitoring.get("process_whitelist", [])
    )
    kworker_cpu_threshold = cfg.get("monitoring", {}).get(
        "kworker_cpu_threshold",
        default_monitoring.get("kworker_cpu_threshold", 20)
    )

    import process_monitor
    import db

    print(f"[INFO] Starting continuous monitoring (interval: {interval}s)")
    try:
        while True:
            events = process_monitor.scan_processes(
                suspicious_keywords,
                process_whitelist,
                kworker_cpu_threshold,
            )
            if events:
                print(f"[INFO] {len(events)} suspicious event(s) detected.")
                db.insert_events(events)
                print("[INFO] Events saved to the database.")
            else:
                print("[INFO] No suspicious events logged.")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[INFO] Monitoring stopped by user.")

def events_command(args):
    """
    Retrieves and displays stored events from the database with optional filtering.
    """
    import db
    limit = args.limit
    process_filter = args.process_filter
    events = db.fetch_events(limit=limit, process_name_filter=process_filter)
    if events:
        print("[INFO] Displaying stored events:")
        for event in events:
            print(f"ID {event['id']} | {event['timestamp']} | {event['process_name']} (PID: {event['pid']})")
            print(f"    Reason: {event['reason']}")
            if event['connections']:
                print(f"    Connections: {event['connections']}")
            else:
                print("    Connections: None")
            # Show reputation details regardless of connection presence
            print(f"    Reputation: {event['reputation']} ({event['reputation_details']})")
    else:
        print("[INFO] No events found in the database.")

def score_command(args):
    """Scores a website for phishing or scamming potential."""
    url = args.url
    import phishing
    result = phishing.score_website(url)
    print(f"URL: {result['url']}")
    print(f"Inferred Intention: {result['intention']}")
    for k, v in result['features'].items():
        print(f"{k}: {v}")
    print(f"Score: {result['score']}")
    print(f"Verdict: {result['verdict']}")

def check_command(args):
    """Lookup reputation for a given IP, domain, or file."""
    cfg = config.load_config()
    if not cfg:
        print("[ERROR] Could not load configuration. Please run 'lucky7 init' first.")
        return

    import reputation

    if args.ip:
        status, details = reputation.get_ip_reputation(args.ip, cfg)
        print(f"IP {args.ip} => {status} ({details})")
    elif args.domain:
        status, details = reputation.get_domain_reputation(args.domain, cfg)
        print(f"Domain {args.domain} => {status} ({details})")
    elif args.url:
        status, details = reputation.get_url_reputation(args.url, cfg)
        print(f"URL {args.url} => {status} ({details})")
    elif args.file:
        import hashlib
        try:
            with open(args.file, "rb") as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
            status, details = reputation.get_file_reputation(sha256, cfg, args.file)
            print(f"File {args.file} => {status} ({details})")
        except FileNotFoundError:
            print(f"[ERROR] File not found: {args.file}")

def main():
    parser = argparse.ArgumentParser(
        description="Lucky #7 - On-host Monitoring Tool (MVP)"
    )
    subparsers = parser.add_subparsers(dest="command")
    
    subparsers.add_parser("init", help="Initialize configuration and database for Lucky #7")
    subparsers.add_parser("start", help="Start monitoring and log suspicious events once")

    monitor_parser = subparsers.add_parser("monitor", help="Continuously monitor at a specified interval")
    monitor_parser.add_argument("--interval", type=int, default=60,
                                help="Interval in seconds between scans (default: 60)")
    
    # Define the 'events' command with optional filtering parameters.
    events_parser = subparsers.add_parser("events", help="View stored suspicious events")
    events_parser.add_argument("--limit", type=int, default=100, help="Maximum number of events to display (default: 100)")
    events_parser.add_argument("--process-filter", type=str, default=None, help="Filter events by process name (substring match)")

    score_parser = subparsers.add_parser("score", help="Score a website for phishing risk")
    score_parser.add_argument("url", help="URL to evaluate")

    check_parser = subparsers.add_parser("check", help="Check reputation for an IP, domain, URL, or file")
    group = check_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", type=str, help="IP address to lookup")
    group.add_argument("--domain", type=str, help="Domain to lookup")
    group.add_argument("--url", type=str, help="URL to lookup")
    group.add_argument("--file", type=str, help="File path to lookup (SHA256 will be calculated)")
    # Command to score a website for phishing risk
    score_parser = subparsers.add_parser("score", help="Score a website for phishing risk")
    score_parser.add_argument("url", help="URL to evaluate")
    
    args = parser.parse_args()
    
    if args.command == "init":
        init_command()
    elif args.command == "start":
        start_command()
    elif args.command == "monitor":
        monitor_command(args)
    elif args.command == "events":
        events_command(args)
    elif args.command == "score":
        score_command(args)
    elif args.command == "check":
        check_command(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

