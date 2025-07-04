import os
import sqlite3
from config import CONFIG_DIR

# Define the database file path.
DB_PATH = os.path.join(CONFIG_DIR, "lucky7.db")

def init_db():
    """Initializes the SQLite database and tables."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Table for process events
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            process_name TEXT,
            pid INTEGER,
            reason TEXT,
            connections TEXT,
            reputation TEXT,
            reputation_details TEXT
        )
        """
    )

    # Table for storing reputation lookup history
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS reputation_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            entity TEXT,
            entity_type TEXT,
            status TEXT,
            details TEXT
        )
        """
    )

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
        INSERT INTO events (timestamp, process_name, pid, reason, connections, reputation, reputation_details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event.get("timestamp"),
            event.get("process_name"),
            event.get("pid"),
            event.get("reason"),
            event.get("connections"),
            event.get("reputation"),
            event.get("reputation_details"),
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
        INSERT INTO events (timestamp, process_name, pid, reason, connections, reputation, reputation_details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
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
            SELECT id, timestamp, process_name, pid, reason, connections, reputation, reputation_details
            FROM events
            WHERE process_name LIKE ?
            ORDER BY id DESC
            LIMIT ?
        """
        c.execute(query, (f"%{process_name_filter}%", limit))
    else:
        query = """
            SELECT id, timestamp, process_name, pid, reason, connections, reputation, reputation_details
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
        }
        events.append(event)
    return events


def insert_reputation_history(entity, entity_type, status, details):
    """Stores a reputation lookup result."""
    from datetime import datetime

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO reputation_history (timestamp, entity, entity_type, status, details)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            entity,
            entity_type,
            status,
            details,
        ),
    )
    conn.commit()
    conn.close()


def purge_old_history(days):
    """Deletes reputation history older than the specified number of days."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """
        DELETE FROM reputation_history
        WHERE julianday('now') - julianday(timestamp) > ?
        """,
        (days,),
    )
    conn.commit()
    conn.close()


def fetch_reputation_history(limit=100):
    """Fetches recent reputation lookups."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """
        SELECT id, timestamp, entity, entity_type, status, details
        FROM reputation_history
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = c.fetchall()
    conn.close()
    history = []
    for row in rows:
        history.append(
            {
                "id": row[0],
                "timestamp": row[1],
                "entity": row[2],
                "entity_type": row[3],
                "status": row[4],
                "details": row[5],
            }
        )
    return history

