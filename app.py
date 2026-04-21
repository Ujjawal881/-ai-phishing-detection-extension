# ============================================
# AI PHISHING DETECTION ENGINE (FINAL PRODUCTION)
# ============================================

from flask import Flask, request, jsonify
from flask_cors import CORS

import joblib
import pandas as pd
import sqlite3
import re

from datetime import datetime
from urllib.parse import urlparse

# --------------------------------------------
# DETECTION MODULES
# --------------------------------------------

from src.google_safe_browsing import google_safe_check
from src.url_feature_extractor import extract_url_features
from src.dns_intelligence import dns_risk_score

from src.advanced_url_checks import (
    keyword_score,
    brand_impersonation_score,
    typosquat_score,
    structure_score
)

from src.blacklist import (
    is_blacklisted,
    start_blacklist_updater
)

# --------------------------------------------
# TRUSTED DOMAINS
# --------------------------------------------

TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "gmail.com",
    "microsoft.com", "apple.com", "amazon.com",
    "github.com", "raw.githubusercontent.com",
    "facebook.com", "instagram.com", "twitter.com"
}

# --------------------------------------------
# START BLACKLIST ENGINE
# --------------------------------------------

start_blacklist_updater()

# --------------------------------------------
# FLASK INIT
# --------------------------------------------

app = Flask(__name__)
CORS(app)

# --------------------------------------------
# LOAD MODEL
# --------------------------------------------

print("Loading ML model...")

model = joblib.load("models/url_only_model.pkl")
expected_columns = model.feature_names_in_

print("Model loaded")

# --------------------------------------------
# DATABASE
# --------------------------------------------

def init_db():
    conn = sqlite3.connect("logs.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            final_score REAL,
            verdict TEXT,
            timestamp TEXT
        )
    """)

    conn.commit()
    conn.close()

def log_scan(url, score, verdict):
    conn = sqlite3.connect("logs.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_logs (url, final_score, verdict, timestamp)
        VALUES (?, ?, ?, ?)
    """, (url, score, verdict, datetime.now().isoformat()))

    conn.commit()
    conn.close()

init_db()
# --------------------------------------------
# HELPERS
# --------------------------------------------

def is_local(url):
    host = urlparse(url).hostname or ""
    return host in ["127.0.0.1", "localhost"]

def is_trusted(domain):
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            return True
    return False

# --------------------------------------------
# CONTENT ANALYSIS
# --------------------------------------------

def content_analysis(text):
    text = text.lower()
    phrases = [
        "verify your account","confirm your identity",
        "update your payment","security alert",
        "account suspended","login to continue",
        "enter your password","verification required"
    ]
    score = sum(0.25 for p in phrases if p in text)
    return min(score, 1.0)

# --------------------------------------------
# CREDENTIAL DETECTION
# --------------------------------------------

def credential_detection(dom):
    score = 0
    if dom.get("passwordFields", 0) > 0:
        score += 0.6
    if dom.get("creditCardFields", 0) > 0:
        score += 0.8
    if dom.get("externalFormAction", 0):
        score += 0.6
    return min(score, 1.0)

# --------------------------------------------
# DOWNLOAD DETECTION
# --------------------------------------------

def download_detection(text):
    if re.search(r"\.(exe|msi|scr|zip|rar)", text):
        return 0.7
    return 0

# --------------------------------------------
# ROUTES
# --------------------------------------------

@app.route("/")
def home():
    return "AI Phishing Detection API Running"

# --------------------------------------------
# ANALYZE (CORE ENGINE)
# --------------------------------------------

@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json(silent=True) or {}
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL"})

    parsed = urlparse(url)
    domain = parsed.hostname or ""

    # ----------------------------------------
    # SAFE CHECKS
    # ----------------------------------------

    if is_trusted(domain):
        return jsonify({
            "url": url,
            "final_score": 0,
            "verdict": "Legitimate",
            "reason": "Trusted Domain"
        })

    if is_local(url):
        return jsonify({
            "url": url,
            "final_score": 0,
            "verdict": "Legitimate"
        })

    # ----------------------------------------
    # GOOGLE SAFE BROWSING
    # ----------------------------------------

    if google_safe_check(url):
        log_scan(url, 1, "Phishing")
        return jsonify({
            "url": url,
            "final_score": 1,
            "verdict": "Phishing",
            "reason": "Google Safe Browsing"
        })

    # ----------------------------------------
    # BLACKLIST
    # ----------------------------------------

    if is_blacklisted(url):
        log_scan(url, 1, "Phishing")
        return jsonify({
            "url": url,
            "final_score": 1,
            "verdict": "Phishing",
            "reason": "Threat Intelligence"
        })

    # ----------------------------------------
    # ML MODEL
    # ----------------------------------------

    features = extract_url_features(url)
    df = pd.DataFrame([features])

    for col in expected_columns:
        if col not in df:
            df[col] = 0

    df = df[expected_columns]

    legit_prob = model.predict_proba(df)[0][1]
    ml_score = 1 - legit_prob

    # ----------------------------------------
    # OTHER SIGNALS
    # ----------------------------------------

    dns_score = dns_risk_score(url)
    keyword = keyword_score(url)
    brand = brand_impersonation_score(url)
    typo = typosquat_score(url)
    structure = structure_score(url)

    page_text = data.get("page_text", "")
    content_score = content_analysis(page_text)

    dom = data.get("dom_features", {})
    credential_score = credential_detection(dom)

    download_score = download_detection(page_text)

    # ----------------------------------------
    # 🔥 SMART FUSION ENGINE
    # ----------------------------------------

    reasons = []

    if credential_score > 0.7:
        final_score = 1
        reasons.append("Credential harvesting detected")

    elif brand > 0.5 and keyword > 0.3:
        final_score = 0.95
        reasons.append("Brand impersonation + phishing keywords")

    elif structure > 0.5 and dns_score > 0.5:
        final_score = 0.9
        reasons.append("Suspicious structure + DNS risk")

    else:
        final_score = (
            0.30 * ml_score +
            0.15 * dns_score +
            0.10 * keyword +
            0.10 * brand +
            0.10 * typo +
            0.10 * structure +
            0.05 * content_score +
            0.07 * credential_score +
            0.03 * download_score
        )

        if ml_score > 0.7:
            final_score += 0.15
            reasons.append("High ML confidence")

        if dns_score > 0.6:
            final_score += 0.1
            reasons.append("High DNS risk")

        if content_score > 0.4:
            final_score += 0.1
            reasons.append("Suspicious page content")

    final_score = min(final_score, 1)

    verdict = "Phishing" if final_score >= 0.4 else "Legitimate"

    log_scan(url, final_score, verdict)

    return jsonify({
        "url": url,
        "final_score": final_score,
        "verdict": verdict,
        "reasons": reasons,
        "ml_score": ml_score,
        "dns_score": dns_score
    })

# --------------------------------------------
# DASHBOARD
# --------------------------------------------

@app.route("/dashboard")
def dashboard():

    conn = sqlite3.connect("logs.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT url, final_score, verdict, timestamp
        FROM scan_logs
        ORDER BY id DESC
        LIMIT 100
    """)

    rows = cursor.fetchall()
    conn.close()

    return jsonify([
        {
            "url": r[0],
            "score": r[1],
            "verdict": r[2],
            "time": r[3]
        }
        for r in rows
    ])

# --------------------------------------------
# RUN SERVER
# --------------------------------------------

if __name__ == "__main__":
    print("🚀 Starting AI Phishing Detection Server...")
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)