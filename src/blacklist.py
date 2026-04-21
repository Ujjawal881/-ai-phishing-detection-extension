# ============================================
# THREAT INTELLIGENCE ENGINE (FINAL)
# ============================================

import requests
import threading
import time
import json
import os

from urllib.parse import urlparse

# ============================================
# CONFIG
# ============================================

CACHE_FILE = "blacklist_cache.json"
UPDATE_INTERVAL = 3600  # 1 hour
MAX_DOMAINS = 200000


# ============================================
# TRUSTED DOMAINS
# ============================================

SAFE_DOMAINS = {
    "openphish.com",
    "urlhaus.abuse.ch",
    "phishtank.org",
    "testsafebrowsing.appspot.com",
    "github.com",
    "raw.githubusercontent.com"
}


# ============================================
# GLOBAL BLACKLIST
# ============================================

BLACKLIST = set()


# ============================================
# DOMAIN NORMALIZATION
# ============================================

def extract_domain(url):

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        if ":" in domain:
            domain = domain.split(":")[0]

        if domain.startswith("www."):
            domain = domain[4:]

        return domain.strip()

    except:
        return ""


# ============================================
# SAFE DOMAIN CHECK
# ============================================

def is_safe_domain(domain):

    for safe in SAFE_DOMAINS:
        if domain == safe or domain.endswith("." + safe):
            return True

    return False


# ============================================
# CACHE LOAD
# ============================================

def load_cache():

    if os.path.exists(CACHE_FILE):

        print("📦 Loading blacklist cache...")

        try:
            with open(CACHE_FILE, "r") as f:
                data = json.load(f)
                BLACKLIST.update(data)

            print(f"✅ Loaded {len(BLACKLIST)} cached domains")

        except:
            print("⚠ Cache corrupted, rebuilding...")


# ============================================
# CACHE SAVE
# ============================================

def save_cache():

    print("💾 Saving blacklist cache...")

    try:
        data = list(BLACKLIST)[:MAX_DOMAINS]

        with open(CACHE_FILE, "w") as f:
            json.dump(data, f)

    except:
        print("❌ Failed to save cache")


# ============================================
# GENERIC FEED LOADER
# ============================================

def load_feed(name, url, parser):

    print(f"🔄 Updating {name}...")

    try:

        res = requests.get(url, timeout=20)

        if res.status_code != 200:
            print(f"❌ {name} failed: HTTP {res.status_code}")
            return 0

        lines = res.text.splitlines()

        count = 0

        for line in lines:

            domain = parser(line)

            if domain and not is_safe_domain(domain):
                BLACKLIST.add(domain)
                count += 1

        print(f"✅ {name}: {count} domains added")

        return count

    except Exception as e:
        print(f"❌ {name} error:", e)
        return 0


# ============================================
# PARSERS
# ============================================

def parse_openphish(line):
    return extract_domain(line)


def parse_urlhaus(line):
    if line.startswith("#"):
        return None
    return extract_domain(line)


# ============================================
# 🔥 PHISHTANK LOADER (REPLACEMENT)
# ============================================

def load_phishtank():

    print("🔄 Updating PhishTank...")

    try:

        res = requests.get(
            "https://data.phishtank.com/data/online-valid.json",
            timeout=20
        )

        if res.status_code != 200:
            print("❌ PhishTank failed:", res.status_code)
            return 0

        data = res.json()

        count = 0

        for item in data:

            url = item.get("url")

            if not url:
                continue

            domain = extract_domain(url)

            if domain and not is_safe_domain(domain):
                BLACKLIST.add(domain)
                count += 1

        print(f"✅ PhishTank: {count} domains added")

        return count

    except Exception as e:
        print("❌ PhishTank error:", e)
        return 0


# ============================================
# UPDATE ENGINE
# ============================================

def update_blacklist():

    total = 0

    total += load_feed(
        "OpenPhish",
        "https://openphish.com/feed.txt",
        parse_openphish
    )

    total += load_feed(
        "URLHaus",
        "https://urlhaus.abuse.ch/downloads/text/",
        parse_urlhaus
    )

    # 🚫 Disabled (unstable)
    print("⚠ Skipping PhishTank (unreliable / requires API)")

    print(f"📊 Total new domains added: {total}")
    print(f"📊 Total blacklist size: {len(BLACKLIST)}")


# ============================================
# BACKGROUND THREAD
# ============================================

def updater():

    load_cache()

    while True:

        try:
            update_blacklist()
            save_cache()

        except Exception as e:
            print("🚨 Update error:", e)

        time.sleep(UPDATE_INTERVAL)


# ============================================
# START THREAD
# ============================================

def start_blacklist_updater():

    threading.Thread(
        target=updater,
        daemon=True
    ).start()


# ============================================
# BLACKLIST CHECK
# ============================================

def is_blacklisted(url):

    domain = extract_domain(url)

    if not domain:
        return False

    if is_safe_domain(domain):
        return False

    if domain in BLACKLIST:
        return True

    parts = domain.split(".")

    for i in range(len(parts)):

        test_domain = ".".join(parts[i:])

        if is_safe_domain(test_domain):
            return False

        if test_domain in BLACKLIST:
            return True

    return False