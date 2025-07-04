import re
from urllib.parse import urlparse
from datetime import datetime
import tldextract
import whois

# Keywords for heuristics
BANKING_KEYWORDS = [
    "bank",
    "banking",
    "paypal",
    "wallet",
    "account",
    "finance",
    "payment",
    "secure",
    "credit",
    "loan",
    "deposit",
    "capital",
    "investment",
]

ENTERTAINMENT_KEYWORDS = [
    "game",
    "video",
    "music",
    "movie",
    "stream",
    "entertainment",
    "tv",
    "show",
    "series",
    "comic",
    "casino",
    "bet",
]

SHOPPING_KEYWORDS = [
    "shop",
    "store",
    "buy",
    "sale",
    "cart",
    "checkout",
    "deal",
    "discount",
    "amazon",
    "ebay",
    "retail",
]

SOCIAL_KEYWORDS = [
    "social",
    "network",
    "chat",
    "connect",
    "facebook",
    "twitter",
    "instagram",
    "whatsapp",
    "tiktok",
]

NEWS_KEYWORDS = [
    "news",
    "press",
    "journal",
    "report",
    "daily",
    "times",
    "today",
]

PHISHING_KEYWORDS = [
    "login",
    "verify",
    "update",
    "security",
    "signin",
    "account",
    "password",
    "confirm",
    "payment",
    "ssn",
    "invoice",
    "urgent",
    "click",
]
SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "club",
    "click",
    "work",
    "gq",
    "loan",
    "tk",
    "cf",
    "ml",
    "ga",
    "men",
    "win",
    "biz",
    "zip",
    "ru",
    "su",
    "kim",
    "cn",
    "download",
    "live",
    "fit",
    "host",
    "icu",
    "site",
    "online",
    "shop",
    "monster",
    "buzz",
    "support",
}


def infer_intention(domain: str) -> str:
    """Infer the website's intention based on domain keywords."""
    lower = domain.lower()
    if any(k in lower for k in BANKING_KEYWORDS):
        return "Banking"
    if any(k in lower for k in ENTERTAINMENT_KEYWORDS):
        return "Entertainment"
    if any(k in lower for k in SHOPPING_KEYWORDS):
        return "Shopping"
    if any(k in lower for k in SOCIAL_KEYWORDS):
        return "Social"
    if any(k in lower for k in NEWS_KEYWORDS):
        return "News"
    return "General"


def get_domain_age(domain: str) -> int:
    """Return domain age in days or -1 if unknown."""
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, datetime):
            delta = datetime.utcnow() - creation_date
            return delta.days
    except Exception:
        pass
    return -1


def score_website(url: str):
    parsed = urlparse(url)
    https = parsed.scheme.lower() == "https"
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
    subdomain = extracted.subdomain

    intention = infer_intention(domain)

    score = 0
    features = {}

    # HTTPS check
    if not https:
        score += 10
        features["https"] = "no"
    else:
        features["https"] = "yes"

    # Suspicious TLD
    tld = extracted.suffix.lower()
    if tld in SUSPICIOUS_TLDS:
        score += 25
        features["tld"] = f"{tld} (suspicious)"
    else:
        features["tld"] = tld

    # Phishing keywords in domain or subdomain
    domain_str = f"{subdomain}.{domain}" if subdomain else domain
    if any(k in domain_str.lower() for k in PHISHING_KEYWORDS):
        score += 30
        features["keywords"] = "suspicious"
    else:
        features["keywords"] = "none"

    # Hyphen or numeric characters in domain
    if re.search(r"[-\d]", domain_str):
        score += 10
        features["hyphen_or_number"] = "yes"
    else:
        features["hyphen_or_number"] = "no"

    # Long or punycode domain
    if domain_str.startswith("xn--"):
        score += 20
        features["punycode"] = "yes"
    else:
        features["punycode"] = "no"

    if len(domain_str) > 25:
        score += 5
        features["domain_length"] = f"{len(domain_str)} (long)"
    else:
        features["domain_length"] = len(domain_str)

    # Deep subdomain chains (e.g., a.b.c.example.com)
    sub_depth = len(subdomain.split(".")) if subdomain else 0
    features["subdomain_depth"] = sub_depth
    if sub_depth > 1:
        score += 5

    # Domain age
    age_days = get_domain_age(domain)
    if age_days >= 0:
        features["domain_age_days"] = age_days
        if age_days < 180:
            score += 20
    else:
        features["domain_age_days"] = "unknown"
        score += 5  # Slight penalty for unknown age

    verdict = "Low"
    if score >= 70:
        verdict = "High"
    elif score >= 40:
        verdict = "Medium"

    return {
        "url": url,
        "intention": intention,
        "score": score,
        "verdict": verdict,
        "features": features,
    }
