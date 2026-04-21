import re
import math
from urllib.parse import urlparse

# ============================================
# KEYWORDS
# ============================================

PHISHING_KEYWORDS = [
    "login","verify","secure","account","update","bank",
    "signin","confirm","password","recover","reset",
    "wallet","support","authenticate","identity",
    "billing","payment","suspended","unlock","security"
]

# ============================================
# BRANDS
# ============================================

BRANDS = [
    "paypal","google","facebook","microsoft","apple",
    "amazon","netflix","instagram","whatsapp",
    "sbi","icici","hdfc","axis",
    "coinbase","binance","metamask"
]

# ============================================
# SUSPICIOUS TLDS
# ============================================

SUSPICIOUS_TLDS = [
    ".xyz",".top",".tk",".ml",".cf",".gq",".ru",".cn"
]


# ============================================
# HELPER: DOMAIN
# ============================================

def get_domain(url):
    return urlparse(url).netloc.lower()


# ============================================
# ENTROPY (RANDOM DOMAIN DETECTION)
# ============================================

def entropy(domain):

    prob = [float(domain.count(c)) / len(domain) for c in set(domain)]
    return -sum([p * math.log2(p) for p in prob])


# ============================================
# KEYWORD SCORE
# ============================================

def keyword_score(url):

    url_lower = url.lower()

    matches = [k for k in PHISHING_KEYWORDS if k in url_lower]

    score = len(matches) * 0.12

    # stronger if multiple keywords
    if len(matches) >= 3:
        score += 0.2

    return min(score, 1.0)


# ============================================
# BRAND IMPERSONATION (SMART)
# ============================================

def brand_impersonation_score(url):

    domain = get_domain(url)

    score = 0

    for brand in BRANDS:

        if brand in domain:

            # legit domain cases
            if domain == f"{brand}.com":
                continue

            if domain.endswith("." + brand + ".com"):
                continue

            # suspicious cases
            if "-" in domain or "." in domain.replace(brand, ""):
                score += 0.6

            else:
                score += 0.4

    return min(score, 1.0)


# ============================================
# TYPOSQUATTING
# ============================================

def typosquat_score(url):

    domain = get_domain(url)

    score = 0

    for brand in BRANDS:

        patterns = [
            brand.replace("o","0"),
            brand.replace("l","1"),
            brand.replace("i","1"),
            brand.replace("e","3"),
            brand + "-secure",
            brand + "-login",
            brand + "-verify",
            brand + "-account"
        ]

        if any(p in domain for p in patterns):
            score += 0.7

    return min(score, 1.0)


# ============================================
# STRUCTURE SCORE (ADVANCED)
# ============================================

def structure_score(url):

    parsed = urlparse(url)

    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    score = 0

    # HTTP (unsafe)
    if parsed.scheme == "http":
        score += 0.3

    # long URL
    if len(url) > 75:
        score += 0.2

    # many subdomains
    if domain.count(".") >= 3:
        score += 0.3

    # suspicious path
    if any(k in path for k in PHISHING_KEYWORDS):
        score += 0.3

    # file extensions
    if re.search(r"\.(exe|scr|zip|rar|msi)", path):
        score += 0.5

    # IP address
    if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
        score += 0.5

    # suspicious TLD
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 0.5

    # hyphen abuse
    if domain.count("-") >= 2:
        score += 0.3

    # 🔥 entropy check (NEW)
    if entropy(domain) > 3.5:
        score += 0.3

    return min(score, 1.0)