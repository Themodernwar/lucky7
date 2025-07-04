import requests
from datetime import datetime
import os
import ipaddress
from urllib.parse import urlparse
import db


def map_score_to_state(score: int) -> str:
    """Converts a 0-100 score into a textual state."""
    if score >= 80:
        return "Trusted"
    if score >= 50:
        return "Suspicious"
    if score >= 0:
        return "Malicious"
    return "Unknown"


def store_history(entity, entity_type, status, details, config):
    retention = config.get("history_retention_days", 30)
    db.insert_reputation_history(entity, entity_type, status, details)
    db.purge_old_history(retention)


# --- External lookup helpers -------------------------------------------------

def _virustotal_lookup(endpoint: str, api_key: str):
    headers = {"x-apikey": api_key}
    response = requests.get(endpoint, headers=headers, timeout=10)
    if response.status_code == 200:
        return response.json()
    return None


def _otx_lookup(url: str, api_key: str):
    headers = {"X-OTX-API-KEY": api_key}
    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code == 200:
        return response.json()
    return None


def _ipinfo_lookup(ip: str, token: str = ""):
    url = f"https://ipinfo.io/{ip}/json"
    if token:
        url += f"?token={token}"
    response = requests.get(url, timeout=5)
    if response.status_code == 200:
        return response.json()
    return None


def _abuseipdb_lookup(ip: str, api_key: str):
    url = (
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    )
    headers = {"Key": api_key, "Accept": "application/json"}
    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code == 200:
        return response.json()
    return None


def _domain_age(domain: str):
    try:
        resp = requests.get(f"https://api.whois.vu/?q={domain}", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            created = data.get("created")
            if created:
                created_dt = datetime.utcfromtimestamp(int(created))
                return (datetime.utcnow() - created_dt).days
    except Exception:
        pass
    return None


# --- Reputation checks -------------------------------------------------------

def get_ip_reputation(ip: str, config):
    rep_config = config.get("reputation", {})
    vt_key = rep_config.get("api_key", "").strip()
    otx_key = rep_config.get("otx_api_key", "").strip()
    abuse_key = rep_config.get("abuseipdb_key", "").strip()
    method = rep_config.get("method", "geofencing").lower()

    details = ""
    score = 50

    if method == "virustotal" and vt_key:
        data = _virustotal_lookup(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", vt_key)
        if data:
            rep = data.get("data", {}).get("attributes", {}).get("reputation", 0)
            score = 80 if rep >= 0 else 20
            details = f"VirusTotal reputation score: {rep}"
    elif method == "otx" and otx_key:
        data = _otx_lookup(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general", otx_key)
        if data:
            pulses = data.get("pulse_info", {}).get("count", 0)
            score = 20 if pulses > 0 else 80
            details = f"OTX pulses: {pulses}"
    elif method == "abuseipdb" and abuse_key:
        data = _abuseipdb_lookup(ip, abuse_key)
        if data:
            abuse_score = data.get("data", {}).get("abuseConfidenceScore", 0)
            score = 100 - abuse_score
            details = f"AbuseIPDB score: {abuse_score}"
    else:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                score = 90
                details = "Private IP"
            elif ip_obj.is_reserved or ip_obj.is_loopback or ip_obj.is_multicast:
                score = 90
                details = "Reserved/Loopback IP"
            else:
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
                if response.status_code == 200:
                    country = response.json().get("country", "Unknown")
                    trusted = rep_config.get("geofence_country", "United States")
                    score = 80 if country == trusted else 40
                    details = f"Country: {country}"
                else:
                    details = "Geofencing lookup failed"

                # hosting provider check via ipinfo
                token = rep_config.get("ipinfo_token", "")
                info = _ipinfo_lookup(ip, token)
                if info:
                    org = info.get("org", "").lower()
                    if any(p in org for p in ["amazon", "digitalocean", "google", "microsoft", "ovh", "cloud"]):
                        score -= 20
                        details += f"; Hosting: {org}"
                    privacy = info.get("privacy", {})
                    if any(privacy.get(k) for k in ["vpn", "proxy", "tor"]):
                        score -= 30
                        flags = ",".join([k for k in ["vpn", "proxy", "tor"] if privacy.get(k)])
                        details += f"; Privacy: {flags}"
        except Exception as e:
            details = f"Error: {e}"

    status = map_score_to_state(score)
    store_history(ip, "ip", status, details, rep_config)
    return status, details


def get_domain_reputation(domain: str, config):
    rep_config = config.get("reputation", {})
    vt_key = rep_config.get("api_key", "")
    otx_key = rep_config.get("otx_api_key", "")
    method = rep_config.get("method", "geofencing").lower()

    details = ""
    score = 50

    if method == "virustotal" and vt_key:
        data = _virustotal_lookup(f"https://www.virustotal.com/api/v3/domains/{domain}", vt_key)
        if data:
            malicious = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            score = 20 if malicious else 80
            details = f"VirusTotal malicious count: {malicious}"
    elif method == "otx" and otx_key:
        data = _otx_lookup(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general", otx_key)
        if data:
            pulses = data.get("pulse_info", {}).get("count", 0)
            score = 20 if pulses > 0 else 80
            details = f"OTX pulses: {pulses}"
    else:
        tld = domain.split(".")[-1].lower()
        if any(x in domain for x in ["malware", "phish", "spam"]):
            score = 30
            details = "Domain contains suspicious keywords"
        elif domain.endswith(".gov") or domain.endswith(".edu"):
            score = 85
            details = "Government/Education domain"
        else:
            score = 70
            details = "Generic domain"

        if domain.startswith("xn--"):
            score -= 15
            details += "; Punycode"
        if len(domain) > 25:
            score -= 5
            details += "; Long"
        if any(ch * 3 in domain for ch in set(domain)):
            score -= 5
            details += "; Repeated chars"

        age = _domain_age(domain)
        if age is not None:
            if age < 365:
                score -= 20
                details += f"; Age {age}d"
            elif age > 1825:
                score += 10
                details += f"; Age {age}d"
        if tld in ["ru", "cn", "xyz", "top", "info", "club"]:
            score -= 10
            details += "; Risky TLD"
        if any(char.isdigit() for char in domain):
            score -= 5
            details += "; Contains digits"
        if "-" in domain:
            score -= 5
            details += "; Contains hyphen"

    status = map_score_to_state(score)
    store_history(domain, "domain", status, details, rep_config)
    return status, details


def get_file_reputation(file_hash: str, config, file_path: str | None = None):
    rep_config = config.get("reputation", {})
    vt_key = rep_config.get("api_key", "")
    otx_key = rep_config.get("otx_api_key", "")
    method = rep_config.get("method", "geofencing").lower()

    details = ""
    score = 50

    if method == "virustotal" and vt_key:
        data = _virustotal_lookup(f"https://www.virustotal.com/api/v3/files/{file_hash}", vt_key)
        if data:
            malicious = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            score = 20 if malicious else 80
            details = f"VirusTotal malicious count: {malicious}"
    elif method == "otx" and otx_key:
        data = _otx_lookup(f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general", otx_key)
        if data:
            pulses = data.get("pulse_info", {}).get("count", 0)
            score = 20 if pulses > 0 else 80
            details = f"OTX pulses: {pulses}"
    else:
        score = 60
        details = "No external reputation lookup"
        if file_path:
            ext = os.path.splitext(file_path)[1].lower()
            if ext in [
                ".exe",
                ".dll",
                ".bat",
                ".cmd",
                ".js",
                ".vbs",
                ".scr",
                ".jar",
                ".ps1",
                ".sh",
                ".py",
            ]:
                score -= 10
                details += f"; Extension {ext}"
            elif ext in [
                ".pdf",
                ".doc",
                ".docx",
                ".xls",
                ".xlsx",
                ".ppt",
                ".pptx",
            ]:
                score -= 5
                details += f"; Possible macro {ext}"
            try:
                size = os.path.getsize(file_path)
                if size < 1024:
                    score -= 5
                    details += f"; Size {size}B"
            except OSError:
                pass

    status = map_score_to_state(score)
    store_history(file_hash, "file", status, details, rep_config)
    return status, details


def get_url_reputation(url: str, config):
    """Evaluate a URL for reputation issues such as large image downloads."""
    rep_config = config.get("reputation", {})
    threshold = rep_config.get("large_image_threshold_mb", 100)
    details = ""
    score = 50
    try:
        resp = requests.head(url, allow_redirects=True, timeout=10)
        if resp.status_code >= 400:
            score -= 20
            details += f"HTTP {resp.status_code}; "
        length = int(resp.headers.get("Content-Length", "0"))
        ctype = resp.headers.get("Content-Type", "").lower()
        is_image = "image" in ctype
        if length > threshold * 1024 * 1024 and is_image:
            score -= 40
            details += f"Image {length // (1024*1024)}MB; "
        if resp.url.startswith("http://"):
            score -= 10
            details += "Unencrypted HTTP; "
        domain = urlparse(resp.url).hostname
        if domain:
            dom_status, _ = get_domain_reputation(domain, config)
            if dom_status == "Malicious":
                score = 10
                details += "Domain malicious; "
    except Exception as e:
        return "Unknown", f"Error: {e}"

    details = details.strip().rstrip(";")
    status = map_score_to_state(score)
    store_history(url, "url", status, details, rep_config)
    return status, details


def get_event_reputation(connections_str: str, config):
    if not connections_str:
        return "Trusted", ""

    ips = [conn.strip().split(":")[0] for conn in connections_str.split(",") if conn.strip()]
    statuses = []
    details_list = []
    for ip in ips:
        status, details = get_ip_reputation(ip, config)
        statuses.append(status)
        details_list.append(f"{ip}: {details}")

    overall = "Trusted" if all(s == "Trusted" for s in statuses) else "Untrusted"
    aggregated_details = "; ".join(details_list)
    return overall, aggregated_details
