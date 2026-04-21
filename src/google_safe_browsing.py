import requests
import time

API_KEY = "AIzaSyBV-zinhcvYLWZV4247DfO1Up3f63wrJVg"

URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

CACHE = {}
CACHE_TTL = 600


def google_safe_check(url):

    print("🚀 Safe Browsing called for:", url)

    now = time.time()

    # ----------------------------------------
    # CACHE (USE FULL URL, NOT DOMAIN)
    # ----------------------------------------

    if url in CACHE:
        result, ts = CACHE[url]
        if now - ts < CACHE_TTL:
            print("⚡ Cache hit")
            return result

    body = {
        "client": {
            "clientId": "ai-phishing-guard",
            "clientVersion": "2.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:

        response = requests.post(
            f"{URL}?key={API_KEY}",
            json=body,
            timeout=5
        )

        print("📡 Status:", response.status_code)
        print("📦 Response:", response.text)

        # ----------------------------------------
        # HANDLE ERROR RESPONSE
        # ----------------------------------------

        if response.status_code != 200:
            print("❌ API ERROR → Check API key / billing")
            return False

        data = response.json()

        result = "matches" in data

        CACHE[url] = (result, now)

        return result

    except Exception as e:
        print("❌ Safe Browsing Exception:", e)
        return False