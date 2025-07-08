# lucky7 | Lightweight on-host monitoring tool
---------
a lightweight on-host monitoring tool that tracks suspicious local activity

> **Disclaimer**: Lucky7 is intended for authorized training and defensive simulation only. Do not use it for malicious purposes.
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

Score a website for phishing risk:

```bash
python main.py score <url>
```

The tool attempts to infer a website's intention category such as **Banking**,
**Entertainment**, **Shopping**, **Social**, **News**, **Education**, **Government**, **Adult**, or **General**. The score
is based on HTTPS usage, suspicious keywords, domain age and structure, reputation of the top-level domain, and additional heuristics like repeated characters or the use of an IP address.

Check the reputation of an IP, domain, URL, or file:

```bash
python main.py check --ip 8.8.8.8
python main.py check --domain example.com
python main.py check --url https://example.com/big.jpg
    python main.py check --file /path/to/file.exe
```

## Training server

These routes simulate attacker behavior for defensive research. Data such as browser fingerprints and login attempts are stored for analysis.

Start the web server with honeypot routes and fingerprint collection:

```bash
python main.py serve --port 5000
```

Run a YAML simulation scenario. Provide the path to your YAML file. An example is included in `scenarios/example.yml`:

```bash
python main.py simulate scenarios/example.yml
```

Reverse shell training (listener or client) can also be defined in scenarios.

Perform passive enrichment for a domain or IP:

```bash
python main.py enrich --domain example.com
python main.py enrich --ip 8.8.8.8
```

### Configuration

The `~/.lucky7/config.yml` file contains reputation settings. You can provide
API keys for VirusTotal or AlienVault OTX, and adjust how long the reputation history
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

Lucky7 is provided for educational use. Use it only in environments you own or have explicit permission to test.
