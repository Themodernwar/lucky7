import requests

def get_ip_reputation(ip, config):
    """
    Checks the reputation of an IP address.
    If a VirusTotal API key is provided and method is set to 'virustotal', queries VirusTotal.
    Otherwise, uses a geolocation API to determine if the IP is in the trusted country.
    
    Returns a tuple: (status, details)
      - status: "Trusted" or "Untrusted" (or "Unknown" if lookup fails)
      - details: A string with lookup details.
    """
    rep_config = config.get("reputation", {})
    api_key = rep_config.get("api_key", "").strip()
    method = rep_config.get("method", "geofencing").lower()
    
    if api_key and method == "virustotal":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": api_key}
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                # In VT v3, a negative reputation score may indicate malicious behavior.
                attributes = data.get("data", {}).get("attributes", {})
                reputation_score = attributes.get("reputation", 0)
                # Simple heuristic: negative score => untrusted.
                status = "Untrusted" if reputation_score < 0 else "Trusted"
                details = f"VirusTotal reputation score: {reputation_score}"
                return status, details
            else:
                # Fall through to geofencing if API fails.
                pass
        except Exception as e:
            # On error, fallback to geofencing.
            pass

    # Fallback to geofencing using ip-api.com
    try:
        geo_url = f"http://ip-api.com/json/{ip}"
        response = requests.get(geo_url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            country = data.get("country", "Unknown")
            trusted_country = rep_config.get("geofence_country", "United States")
            status = "Trusted" if country == trusted_country else "Untrusted"
            details = f"Country: {country}"
            return status, details
        else:
            return "Unknown", "Geofencing lookup failed"
    except Exception as e:
        return "Unknown", f"Error: {str(e)}"

def get_event_reputation(connections_str, config):
    """
    Given a comma-separated string of connections (in the format "IP:port, IP:port, ..."),
    checks the reputation of each IP and aggregates the results.
    
    Returns a tuple: (overall_status, aggregated_details)
      - overall_status: "Trusted" if all connections are trusted, otherwise "Untrusted"
      - aggregated_details: A semicolon-separated string of per-IP reputation details.
    
    If there are no connections, returns ("Trusted", "").
    """
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

