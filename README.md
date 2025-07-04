# lucky7 | Lightweight on-host monitoring tool
---------
lightweight on-host monitoring tool that tracks suspicious local activity
__________________________________________________________________________
python main.py init -- Generates Required Configuration Files

python main.py start -- Loads the Configuration Files & Begins Monitoring

python main.py events -- Displays the last 7 Security/Network events

Simple tool meant to ensure there are no active network connections associated with a process.
If network monitoring is enabled in `~/.lucky7/config.yml` (set `monitoring.network` to `true`),
new outbound connections are checked against an IP reputation service.
The scanner now grabs a short service banner from each new connection and
attempts to infer the device's purpose from that header information.

## Installation

Install the required Python packages using pip:

```bash
pip install -r requirements.txt
```

## Usage

Generate the configuration and database:

```bash
python main.py init
```

Start monitoring:

```bash
python main.py start
```

Display stored events:

```bash
python main.py events
```

