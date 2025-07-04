# lucky7 | Lightweight on-host monitoring tool
---------
lightweight on-host monitoring tool that tracks suspicious local activity
__________________________________________________________________________
python main.py init -- Generates Required Configuration Files

python main.py start -- Loads the Configuration Files & Begins Monitoring

python main.py events -- Displays the last 7 Security/Network events

Simple tool meant to ensure there are no active network connections associated with a process.

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

Continuous monitoring:

```bash
python main.py monitor --interval 60
```

Display stored events:

```bash
python main.py events
```

Check the reputation of an IP, domain, URL, or file:

```bash
python main.py check --ip 8.8.8.8
python main.py check --domain example.com
python main.py check --url https://example.com/big.jpg
    python main.py check --file /path/to/file.exe
```

### Configuration

The `~/.lucky7/config.yml` file contains reputation settings. You can provide
API keys for VirusTotal or AlienVault OTX and adjust how long reputation history
is stored:

```yaml
reputation:
  api_key: "YOUR_VT_KEY"
  otx_api_key: "YOUR_OTX_KEY"
  ipinfo_token: "YOUR_IPINFO_TOKEN"
  abuseipdb_key: "YOUR_ABUSEIPDB_KEY"
  method: virustotal  # or 'otx', 'abuseipdb', 'geofencing', 'heuristic'
  history_retention_days: 30
  large_image_threshold_mb: 100
```

Heuristic lookups consider multiple factors:
* IP address characteristics such as private or reserved ranges, hosting
  providers, VPN/TOR indicators (via ipinfo), and country-based geofencing.
* Domain traits including age, risky top-level domains, punycode or very long
  names, digits or hyphens, and repeated characters.
* File reputation based on extension types commonly used for malware or office
  documents with macros when no external service is used.

* URL checks flag unencrypted links and images larger than the configured threshold.
* Processes named like telemetry or analytics with outbound traffic are logged with encryption status.

