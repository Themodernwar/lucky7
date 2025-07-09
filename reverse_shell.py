from __future__ import annotations
import socket
from typing import Iterable
import time


def start_listener(port: int = 9001, timeout: int = 30) -> None:
    """Start a simulated reverse shell listener that logs incoming commands."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", port))
        s.listen(1)
        s.settimeout(timeout)
        print(f"[SIM] Reverse shell listener on 0.0.0.0:{port}")
        try:
            conn, addr = s.accept()
        except socket.timeout:
            print("[SIM] Listener timeout; no connection")
            return
        print(f"[SIM] Connection from {addr[0]}:{addr[1]}")
        with conn:
            conn.settimeout(timeout)
            while True:
                try:
                    data = conn.recv(1024)
                except socket.timeout:
                    print("[SIM] Connection timeout")
                    break
                if not data:
                    break
                cmd = data.decode(errors="ignore").strip()
                print(f"[SIM] Received command: {cmd}")
                conn.sendall(b"OK\n")
        print("[SIM] Connection closed")


def simulate_client(
    host: str,
    port: int,
    commands: Iterable[str],
    delay: float = 0.5,
) -> None:
    """Connect to a listener and send commands for simulation."""
    with socket.create_connection((host, port), timeout=10) as s:
        for cmd in commands:
            print(f"[SIM] Sending: {cmd}")
            s.sendall(cmd.encode() + b"\n")
            try:
                resp = s.recv(1024)
                resp_text = resp.decode(errors="ignore").strip()
                print(f"[SIM] Response: {resp_text}")
            except socket.timeout:
                print("[SIM] No response")
            time.sleep(delay)
