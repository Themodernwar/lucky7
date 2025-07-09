import yaml
import time
import requests
import logging
import reverse_shell

logger = logging.getLogger(__name__)


def run_scenario(path: str):
    """Execute a YAML scenario of simulated attacks."""
    try:
        with open(path, 'r') as f:
            scenario = yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.error("Scenario file not found: %s", path)
        return
    except yaml.YAMLError as e:
        logger.error("Failed to parse scenario file %s: %s", path, e)
        return

    for step in scenario.get('steps', []):
        action = step.get('action')
        if action == 'delay':
            time.sleep(step.get('seconds', 1))
        elif action == 'http_get':
            url = step.get('url')
            if url:
                try:
                    requests.get(url, timeout=10)
                except requests.RequestException as e:
                    logger.warning("HTTP GET failed for %s: %s", url, e)
        elif action == 'http_post':
            url = step.get('url')
            data = step.get('data', {})
            if url:
                try:
                    requests.post(url, data=data, timeout=10)
                except requests.RequestException as e:
                    logger.warning("HTTP POST failed for %s: %s", url, e)
        elif action == 'reverse_shell':
            mode = step.get('mode', 'client')
            host = step.get('host', '127.0.0.1')
            port = int(step.get('port', 9001))
            try:
                if mode == 'listener':
                    reverse_shell.start_listener(port)
                else:
                    commands = step.get('commands', [])
                    reverse_shell.simulate_client(host, port, commands)
            except Exception as e:
                logger.warning("Reverse shell error: %s", e)
        else:
            logger.warning("Unknown action: %s", action)
