import yaml
import time
import requests
import reverse_shell


def run_scenario(path: str):
    """Execute a YAML scenario of simulated attacks."""
    try:
        with open(path, 'r') as f:
            scenario = yaml.safe_load(f) or {}
    except FileNotFoundError:
        print(f"[ERROR] Scenario file not found: {path}")
        return
    except yaml.YAMLError as e:
        print(f"[ERROR] Failed to parse scenario file {path}: {e}")
        return

    for step in scenario.get('steps', []):
        action = step.get('action')
        if action == 'delay':
            time.sleep(step.get('seconds', 1))
        elif action == 'http_get':
            url = step.get('url')
            if url:
                requests.get(url)
        elif action == 'http_post':
            url = step.get('url')
            data = step.get('data', {})
            if url:
                requests.post(url, data=data)
        elif action == 'reverse_shell':
            mode = step.get('mode', 'client')
            host = step.get('host', '127.0.0.1')
            port = int(step.get('port', 9001))
            if mode == 'listener':
                reverse_shell.start_listener(port)
            else:
                commands = step.get('commands', [])
                reverse_shell.simulate_client(host, port, commands)
        else:
            print(f"[SIM] Unknown action: {action}")

