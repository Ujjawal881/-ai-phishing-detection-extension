console.log("🛡 AI Phishing Guard Engine Loaded:", window.location.href);

// ---------------------------------------------------
// SKIP LOCALHOST
// ---------------------------------------------------

const host = window.location.hostname;

if (
    host === "127.0.0.1" ||
    host === "localhost" ||
    host.startsWith("192.168.") ||
    host.startsWith("10.")
) {
    console.log("Skipping local environment");
}

// ---------------------------------------------------
// GLOBAL STATE
// ---------------------------------------------------

let lastScanTime = 0;
const SCAN_INTERVAL = 3000;
let pageBlocked = false;

// ---------------------------------------------------
// MAIN SCAN FUNCTION
// ---------------------------------------------------

function scanWebsite(force = false) {

    if (pageBlocked) return;

    const now = Date.now();

    if (!force && (now - lastScanTime < SCAN_INTERVAL)) {
        return;
    }

    lastScanTime = now;

    console.log("🔍 Scanning:", location.href);

    try {

        const domFeatures = {

            forms: document.forms.length,

            passwordFields:
                document.querySelectorAll("input[type='password']").length,

            emailFields:
                document.querySelectorAll("input[type='email']").length,

            usernameFields:
                document.querySelectorAll(
                    "input[name*='user'], input[name*='login'], input[name*='account']"
                ).length,

            creditCardFields:
                document.querySelectorAll(
                    "input[name*='card'], input[name*='cc'], input[name*='cvv']"
                ).length,

            iframes:
                document.querySelectorAll("iframe").length,

            hiddenInputs:
                document.querySelectorAll("input[type='hidden']").length,

            externalScripts:
                [...document.scripts].filter(
                    s => s.src && !s.src.includes(location.hostname)
                ).length,

            externalFormAction:
                [...document.forms].some(
                    f => f.action && !f.action.includes(location.hostname)
                ) ? 1 : 0
        };

        const pageText = document.body
            ? document.body.innerText.toLowerCase().substring(0, 10000)
            : "";

        chrome.runtime.sendMessage({
            type: "SCAN_URL",
            payload: {
                url: location.href,
                dom_features: domFeatures,
                page_text: pageText
            }
        }, handleResponse);

    } catch (err) {
        console.error("❌ Scan error:", err);
    }
}

// ---------------------------------------------------
// RESPONSE HANDLER
// ---------------------------------------------------

function handleResponse(response) {

    if (!response || !response.success) {
        console.warn("⚠ Scan failed:", response?.error);
        return;
    }

    const data = response.data;

    console.log("🧠 Result:", data);

    if (
        data.verdict === "Phishing" ||
        data.final_score >= 0.4
    ) {
        blockPage(data);
    }
}

// ---------------------------------------------------
// 🔥 AI EXPLANATION BUILDER
// ---------------------------------------------------

function buildReasons(data) {

    let reasons = [];

    // backend reasons
    if (data.reasons && data.reasons.length > 0) {
        reasons = data.reasons;
    }

    // fallback smart explanation
    if (reasons.length === 0) {

        if (data.credential_score > 0.6)
            reasons.push("Credential harvesting detected");

        if (data.brand > 0.5)
            reasons.push("Possible brand impersonation");

        if (data.dns_score > 0.5)
            reasons.push("Suspicious domain reputation");

        if (data.ml_score > 0.7)
            reasons.push("AI model detected phishing pattern");

        if (data.structure > 0.5)
            reasons.push("Suspicious URL structure");

        if (reasons.length === 0)
            reasons.push("Multiple risk signals detected");
    }

    return reasons;
}

// ---------------------------------------------------
// 🔥 BLOCK PAGE WITH AI UI
// ---------------------------------------------------

function blockPage(data) {

    if (pageBlocked) return;
    pageBlocked = true;

    const reasons = buildReasons(data);

    const reasonsHTML = reasons.map(r => `<li>✔ ${r}</li>`).join("");

    document.documentElement.innerHTML = `
    <html>
    <head>
        <title>⚠ Phishing Blocked</title>

        <style>
            body{
                margin:0;
                font-family:Arial, sans-serif;
                background:#0f0f0f;
                color:white;
                display:flex;
                align-items:center;
                justify-content:center;
                height:100vh;
            }

            .container{
                background:#1c1c1c;
                padding:40px;
                border-radius:12px;
                max-width:750px;
                text-align:center;
                box-shadow:0 0 30px rgba(0,0,0,0.6);
            }

            h1{
                color:#ff3b3b;
                font-size:40px;
                margin-bottom:20px;
            }

            .url{
                background:#2b2b2b;
                padding:10px;
                border-radius:6px;
                word-break:break-all;
                margin:20px 0;
                font-size:14px;
            }

            .score{
                font-size:18px;
                margin-bottom:20px;
            }

            .reasons{
                text-align:left;
                margin-top:20px;
                background:#222;
                padding:15px;
                border-radius:8px;
            }

            ul{
                padding-left:20px;
            }

            li{
                margin-bottom:8px;
            }

            button{
                padding:12px 24px;
                margin:10px;
                border:none;
                border-radius:6px;
                cursor:pointer;
                font-size:16px;
            }

            .back{
                background:#ff3b3b;
                color:white;
            }

            .proceed{
                background:#444;
                color:white;
            }

            .logo{
                margin-top:20px;
                color:#aaa;
                font-size:13px;
            }

        </style>

    </head>

    <body>

        <div class="container">

            <h1>⚠ Dangerous Website Blocked</h1>

            <p>This site may steal your personal data or credentials.</p>

            <div class="url">${location.href}</div>

            <div class="score">
                Threat Score: <b>${(data.final_score || 1).toFixed(2)}</b>
            </div>

            <div class="reasons">
                <h3>🔍 Why this site is dangerous:</h3>
                <ul>${reasonsHTML}</ul>
            </div>

            <button id="backBtn">Go Back</button>
            <button id="proceedBtn">Proceed Anyway</button>
            <button id="viewDetailsBtn">View Details</button>

            <div class="logo">
                🛡 Protected by AI Phishing Guard
            </div>

        </div>
    </body>
    </html>
    `;

    setTimeout(() => {

    // Go Back
    const backBtn = document.getElementById("backBtn");
    if (backBtn) {
        backBtn.addEventListener("click", () => {
            window.history.back();
        });
    }

    // Proceed Anyway
    const proceedBtn = document.getElementById("proceedBtn");
    if (proceedBtn) {
        proceedBtn.addEventListener("click", () => {
            pageBlocked = false;

            // 🔥 Temporarily disable blocking for this session
            sessionStorage.setItem("allowSite", location.hostname);

            alert("⚠ You chose to proceed. Be careful!");

            window.location.reload();

        });
    }

    // View Details
    const detailsBtn = document.getElementById("viewDetailsBtn");
    if (detailsBtn) {
        detailsBtn.addEventListener("click", () => {

            window.open(
                chrome.runtime.getURL("dashboard.html"),
                "_blank"
            );

        });
    }

}, 300);
}

// ---------------------------------------------------
// INITIAL SCAN
// ---------------------------------------------------

scanWebsite(true);

// ---------------------------------------------------
// FOLLOW-UP SCAN
// ---------------------------------------------------

setTimeout(() => scanWebsite(true), 1500);

// ---------------------------------------------------
// PERIODIC SCAN
// ---------------------------------------------------

setInterval(scanWebsite, 4000);

// ---------------------------------------------------
// DOM MONITOR
// ---------------------------------------------------

const observer = new MutationObserver(() => {
    scanWebsite();
});

observer.observe(document.body || document.documentElement, {
    childList: true,
    subtree: true
});