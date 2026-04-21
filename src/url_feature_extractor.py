import re
import math
from urllib.parse import urlparse

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".tk", ".ml", ".cf", ".gq", ".ru", ".cn"
]

PHISHING_WORDS = [
    "login","secure","bank","verify","update",
    "account","password","confirm","signin"
]


# --------------------------------------------
# ENTROPY
# --------------------------------------------

def calculate_entropy(domain):
    probs = [float(domain.count(c)) / len(domain) for c in set(domain)]
    entropy = -sum([p * math.log2(p) for p in probs])
    return min(entropy / 5, 1.0)   # 🔥 normalized


# --------------------------------------------
# FEATURE EXTRACTION
# --------------------------------------------

def extract_url_features(url):

    parsed = urlparse(url)
    hostname = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()

    total_len = max(len(hostname), 1)

    features = {

        # -----------------------------------
        # BASIC
        # -----------------------------------
        "UrlLength": len(url),
        "HostnameLength": len(hostname),
        "PathLength": len(path),
        "QueryLength": len(query),

        # -----------------------------------
        # STRUCTURE
        # -----------------------------------
        "NumDots": url.count("."),
        "SubdomainLevel": max(hostname.count(".") - 1, 0),
        "PathLevel": path.count("/"),

        # -----------------------------------
        # SYMBOLS
        # -----------------------------------
        "NumDash": url.count("-"),
        "NumDashInHostname": hostname.count("-"),
        "NumUnderscore": url.count("_"),
        "NumPercent": url.count("%"),
        "NumHash": url.count("#"),
        "NumAmpersand": url.count("&"),

        # 🔥 FIXED
        "NumQueryComponents": query.count("&"),

        # -----------------------------------
        # SECURITY FLAGS
        # -----------------------------------
        "AtSymbol": int("@" in url),
        "TildeSymbol": int("~" in url),
        "DoubleSlashInPath": int("//" in path),

        # -----------------------------------
        # HTTPS / DOMAIN
        # -----------------------------------
        "NoHttps": int(parsed.scheme != "https"),
        "HttpsInHostname": int("https" in hostname),

        # -----------------------------------
        # NUMERIC / IP
        # -----------------------------------
        "NumNumericChars": sum(c.isdigit() for c in url),
        "IpAddress": int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}", hostname))),

        # -----------------------------------
        # ADVANCED 🔥
        # -----------------------------------
        "Entropy": calculate_entropy(hostname),

        "SuspiciousTLD": int(
            any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)
        ),

        # 🔥 binary instead of count (better for ML)
        "NumSensitiveWords": int(
            any(word in url.lower() for word in PHISHING_WORDS)
        ),

        "ManySubdomains": int(hostname.count(".") >= 3),

        "HyphenAbuse": int(hostname.count("-") >= 2),

        "DigitRatio": sum(c.isdigit() for c in hostname) / total_len,

        # -----------------------------------
        # 🔥 NEW HIGH-SIGNAL FEATURES
        # -----------------------------------

        # encoded URL attack
        "EncodedURL": int("%" in url),

        # suspicious port usage
        "SuspiciousPort": int(":" in hostname and not hostname.endswith(":80") and not hostname.endswith(":443")),

        # long query attack
        "LongQuery": int(len(query) > 50),

        # suspicious path keywords
        "PathPhishing": int(
            any(word in path for word in PHISHING_WORDS)
        )
    }

    return features