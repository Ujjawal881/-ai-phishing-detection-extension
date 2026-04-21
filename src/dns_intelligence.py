import math
import re
from urllib.parse import urlparse

# ============================================
# CONFIG
# ============================================

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".gq", ".tk", ".ml", ".cf",
    ".click", ".work", ".ru", ".cn"
]

# ============================================
# NORMALIZE DOMAIN
# ============================================

def get_domain(url):

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # remove port
    if ":" in domain:
        domain = domain.split(":")[0]

    # remove www
    if domain.startswith("www."):
        domain = domain[4:]

    return domain


# ============================================
# ENTROPY
# ============================================

def calculate_entropy(domain):

    probabilities = [float(domain.count(c)) / len(domain) for c in set(domain)]
    return -sum([p * math.log2(p) for p in probabilities])


# ============================================
# DNS RISK SCORE (ADVANCED)
# ============================================

def dns_risk_score(url):

    domain = get_domain(url)

    if not domain:
        return 0

    score = 0.0
    signals = 0  # for combo logic

    # ----------------------------------------
    # 1️⃣ Suspicious TLD
    # ----------------------------------------
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 0.4
        signals += 1

    # ----------------------------------------
    # 2️⃣ Entropy (FIXED threshold)
    # ----------------------------------------
    ent = calculate_entropy(domain)

    if ent > 3.5:
        score += 0.25
        signals += 1

    # ----------------------------------------
    # 3️⃣ Digit ratio
    # ----------------------------------------
    digit_ratio = sum(c.isdigit() for c in domain) / len(domain)

    if digit_ratio > 0.25:
        score += 0.25
        signals += 1

    # ----------------------------------------
    # 4️⃣ Long domain
    # ----------------------------------------
    if len(domain) > 25:
        score += 0.2
        signals += 1

    # ----------------------------------------
    # 5️⃣ IP address detection
    # ----------------------------------------
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        score += 0.6
        signals += 1

    # ----------------------------------------
    # 6️⃣ Too many subdomains
    # ----------------------------------------
    if domain.count(".") >= 3:
        score += 0.25
        signals += 1

    # ----------------------------------------
    # 7️⃣ Hyphen abuse
    # ----------------------------------------
    if domain.count("-") >= 2:
        score += 0.25
        signals += 1

    # ----------------------------------------
    # 8️⃣ Random subdomain pattern (NEW 🔥)
    # ----------------------------------------
    subdomains = domain.split(".")[:-2]

    for sub in subdomains:
        if len(sub) > 8 and calculate_entropy(sub) > 3.5:
            score += 0.3
            signals += 1
            break

    # ----------------------------------------
    # 🔥 COMBO BOOST (VERY IMPORTANT)
    # ----------------------------------------
    if signals >= 3:
        score += 0.2

    return min(score, 1.0)