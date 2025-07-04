import os
import sqlite3
from config import CONFIG_DIR

# Define the database file path.
DB_PATH = os.path.join(CONFIG_DIR, "lucky7.db")

def init_db():
    """
    Initializes the SQLite database and creates the 'events' table if it doesn't exist.
    Now includes a 'connections' column to store remote IP info.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            process_name TEXT,
            pid INTEGER,
            reason TEXT,
            connections TEXT,
            reputation TEXT,
            reputation_details TEXT,
            banner TEXT,
            purpose TEXT
        )
    """)
    conn.commit()

    # Ensure new columns exist in older databases
    c.execute("PRAGMA table_info(events)")
    cols = [row[1] for row in c.fetchall()]
    if "banner" not in cols:
        c.execute("ALTER TABLE events ADD COLUMN banner TEXT")
    if "purpose" not in cols:
        c.execute("ALTER TABLE events ADD COLUMN purpose TEXT")
    conn.commit()
    conn.close()
    print("[INFO] Database initialized at:", DB_PATH)

def insert_event(event):
    """
    Inserts a single event into the database.
    Expects event to have 'timestamp', 'process_name', 'pid', 'reason', and 'connections'.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO events (timestamp, process_name, pid, reason, connections, reputation, reputation_details, banner, purpose)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event.get("timestamp"),
            event.get("process_name"),
            event.get("pid"),
            event.get("reason"),
            event.get("connections"),
            event.get("reputation"),
            event.get("reputation_details"),
            event.get("banner"),
            event.get("purpose"),
        ),
    )
    conn.commit()
    conn.close()

def insert_events(events):
    """
    Inserts multiple events into the database.
    """
    if not events:
        return
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.executemany(
        """
        INSERT INTO events (timestamp, process_name, pid, reason, connections, reputation, reputation_details, banner, purpose)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                e.get("timestamp"),
                e.get("process_name"),
                e.get("pid"),
                e.get("reason"),
                e.get("connections"),
                e.get("reputation"),
                e.get("reputation_details"),
                e.get("banner"),
                e.get("purpose"),
            )
            for e in events
        ],
    )
    conn.commit()
    conn.close()

def fetch_events(limit=100, process_name_filter=None):
    """
    Fetches events from the database with optional filtering by process name.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if process_name_filter:
        query = """
            SELECT id, timestamp, process_name, pid, reason, connections, reputation, reputation_details, banner, purpose
            FROM events
            WHERE process_name LIKE ?
            ORDER BY id DESC
            LIMIT ?
        """
        c.execute(query, (f"%{process_name_filter}%", limit))
    else:
        query = """
            SELECT id, timestamp, process_name, pid, reason, connections, reputation, reputation_details, banner, purpose
            FROM events
            ORDER BY id DESC
            LIMIT ?
        """
        c.execute(query, (limit,))
    rows = c.fetchall()
    conn.close()
    
    events = []
    for row in rows:
        event = {
            "id": row[0],
            "timestamp": row[1],
            "process_name": row[2],
            "pid": row[3],
            "reason": row[4],
            "connections": row[5],
            "reputation": row[6],
            "reputation_details": row[7],
            "banner": row[8],
            "purpose": row[9],
        }
        events.append(event)
    return events

