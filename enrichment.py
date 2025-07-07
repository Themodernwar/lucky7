import json
from typing import Dict, Any, List
from datetime import datetime

import requests
import whois
from ipwhois import IPWhois

import reputation


def whois_lookup(domain: str) -> str:
    """Return WHOIS text for a domain."""
    try:
        data = whois.whois(domain)
        return data.text if hasattr(data, 'text') else str(data)
    except Exception as e:
        return f"error: {e}"


def passive_dns(domain: str) -> List[str]:
    """Retrieve passive DNS hostnames using a public API."""
    try:
        resp = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10
        )
        if resp.status_code == 200:
            return resp.text.strip().splitlines()
    except Exception:
        pass
    return []


def enrich_ip(ip: str, config: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Collect IP info from ipinfo and whois/ASN data."""
    rep_cfg = (config or {}).get("reputation", {})
    token = rep_cfg.get("ipinfo_token", "")
    info: Dict[str, Any] = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
    }

    # ipinfo lookup
    ipinfo = reputation._ipinfo_lookup(ip, token)
    if ipinfo:
        info["ipinfo"] = ipinfo

    # ASN via ipwhois
    try:
        rdap = IPWhois(ip).lookup_rdap()
        info["asn"] = rdap.get("asn")
        info["asn_desc"] = rdap.get("asn_description")
    except Exception:
        pass

    # optional VT/OTX/AbuseIPDB
    vt_key = rep_cfg.get("api_key", "").strip()
    if vt_key:
        vt = reputation._virustotal_lookup(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", vt_key
        )
        if vt:
            info["virustotal"] = vt
    otx_key = rep_cfg.get("otx_api_key", "").strip()
    if otx_key:
        otx = reputation._otx_lookup(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            otx_key,
        )
        if otx:
            info["otx"] = otx
    abuse_key = rep_cfg.get("abuseipdb_key", "").strip()
    if abuse_key:
        abuse = reputation._abuseipdb_lookup(ip, abuse_key)
        if abuse:
            info["abuseipdb"] = abuse
    return info


def enrich_domain(domain: str, config: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Gather WHOIS and passive DNS for a domain."""
    result = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "domain": domain,
        "whois": whois_lookup(domain),
        "passive_dns": passive_dns(domain),
    }
    return result
