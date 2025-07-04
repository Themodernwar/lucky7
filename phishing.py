import re
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, Set
import tldextract
import whois

# Keywords for heuristics
BANKING_KEYWORDS = {
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
    "transfer",
    "wire",
    "swift",
}

ENTERTAINMENT_KEYWORDS = {
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
    "concert",
    "festival",
    "radio",
}

SHOPPING_KEYWORDS = {
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
    "coupon",
    "goods",
    "product",
    "market",
}

SOCIAL_KEYWORDS = {
    "social",
    "network",
    "chat",
    "connect",
    "facebook",
    "twitter",
    "instagram",
    "whatsapp",
    "tiktok",
    "forum",
    "community",
    "blog",
}

NEWS_KEYWORDS = {
    "news",
    "press",
    "journal",
    "report",
    "daily",
    "times",
    "today",
    "magazine",
    "headline",
    "article",
}

EDUCATION_KEYWORDS = {
    "edu",
    "school",
    "college",
    "university",
    "academy",
    "course",
    "training",
    "learn",
    "study",
}

GOVERNMENT_KEYWORDS = {
    "gov",
    "government",
    "state",
    "county",
    "city",
    "ministry",
    "dept",
    "official",
}

ADULT_KEYWORDS = {
    "adult",
    "sex",
    "porn",
    "xxx",
    "erotic",
    "dating",
    "escort",
}

CATEGORY_KEYWORDS: Dict[str, Set[str]] = {
    "Banking": BANKING_KEYWORDS,
    "Entertainment": ENTERTAINMENT_KEYWORDS,
    "Shopping": SHOPPING_KEYWORDS,
    "Social": SOCIAL_KEYWORDS,
    "News": NEWS_KEYWORDS,
    "Education": EDUCATION_KEYWORDS,
    "Government": GOVERNMENT_KEYWORDS,
    "Adult": ADULT_KEYWORDS,
}

PHISHING_KEYWORDS = {
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
    "validate",
    "authenticate",
    "credentials",
}

PHISHING_PATTERN = re.compile("|".join(re.escape(k) for k in PHISHING_KEYWORDS), re.IGNORECASE)

DOMAIN_AGE_CACHE: Dict[str, int] = {}


def is_ip_domain(domain: str) -> bool:
    """Return True if the domain string looks like an IP address."""
    return re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", domain) is not None
SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "club",
    "click",
    "work",
    "gq",
    "loan",
    "cf",
    "ml",
    "ga",
    "men",
    "win",
    "zip",
    "ru",
    "su",
    "kim",
    "cn",
    "download",
    "fit",
    "host",
    "icu",
    "site",
    "online",
    "shop",
    "monster",
    "buzz",
    "support",
    "country",
    "bar",
    "live",
    "life",
    "biz",
    "link",
    "rest",
}


def infer_intention(domain: str) -> str:
    """Infer the website's intention based on domain keywords."""
    lower = domain.lower()
    for category, keywords in CATEGORY_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            return category
    return "General"


def get_domain_age(domain: str) -> int:
    """Return domain age in days or -1 if unknown. Results are cached."""
    if domain in DOMAIN_AGE_CACHE:
        return DOMAIN_AGE_CACHE[domain]
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, datetime):
            delta = datetime.utcnow() - creation_date
            age = delta.days
            DOMAIN_AGE_CACHE[domain] = age
            return age
    except Exception:
        pass
    DOMAIN_AGE_CACHE[domain] = -1
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
    if PHISHING_PATTERN.search(domain_str):
        score += 30
        features["keywords"] = "suspicious"
    else:
        features["keywords"] = "none"

    # Domain is an IP address
    if is_ip_domain(domain):
        score += 30
        features["ip_domain"] = "yes"
    else:
        features["ip_domain"] = "no"

    # Repeated characters (e.g., xxxyy)
    if re.search(r"(.)\1{2,}", domain_str):
        score += 5
        features["repeated_chars"] = "yes"
    else:
        features["repeated_chars"] = "no"

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
