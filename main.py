import argparse
from core import config

def init_command():
    """
    Initializes the configuration and the local database.
    """
    config.create_default_config()
    from core import db
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
        
        from core import process_monitor
        events = process_monitor.scan_processes(suspicious_keywords, process_whitelist, kworker_cpu_threshold)
        if events:
            print(f"[INFO] {len(events)} suspicious event(s) detected.")
            from core import db
            db.insert_events(events)
            print("[INFO] Events saved to the database.")
        else:
            print("[INFO] No suspicious events logged.")
    else:
        print("[ERROR] Could not load configuration. Please run 'lucky7 init' first.")

def events_command(args):
    """
    Retrieves and displays stored events from the database with optional filtering.
    """
    from core import db
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
    else:
        print("[INFO] No events found in the database.")

def main():
    parser = argparse.ArgumentParser(
        description="Lucky #7 - On-host Monitoring Tool (MVP)"
    )
    subparsers = parser.add_subparsers(dest="command")
    
    subparsers.add_parser("init", help="Initialize configuration and database for Lucky #7")
    subparsers.add_parser("start", help="Start monitoring and log suspicious events")
    
    # Define the 'events' command with optional filtering parameters.
    events_parser = subparsers.add_parser("events", help="View stored suspicious events")
    events_parser.add_argument("--limit", type=int, default=100, help="Maximum number of events to display (default: 100)")
    events_parser.add_argument("--process-filter", type=str, default=None, help="Filter events by process name (substring match)")
    
    args = parser.parse_args()
    
    if args.command == "init":
        init_command()
    elif args.command == "start":
        start_command()
    elif args.command == "events":
        events_command(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

