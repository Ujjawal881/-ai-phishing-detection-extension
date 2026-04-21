console.log("🧠 Background script running");

// -----------------------------------------
// SIMPLE CACHE (avoid repeated scans)
// -----------------------------------------

const scanCache = new Map();
const CACHE_TTL = 10000; // 10 sec


// -----------------------------------------
// MAIN LISTENER
// -----------------------------------------

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

    if (request.type === "SCAN_URL") {

        const url = request.payload.url;

        // ---------------------------------
        // CACHE CHECK
        // ---------------------------------

        if (scanCache.has(url)) {

            const cached = scanCache.get(url);

            if (Date.now() - cached.time < CACHE_TTL) {

                console.log("⚡ Using cached result");

                sendResponse({
                    success: true,
                    data: cached.data
                });

                return true;
            }
        }

        // ---------------------------------
        // FETCH WITH RETRY
        // ---------------------------------

        fetchWithRetry(request.payload, 2)
            .then((data) => {

                // save to cache
                scanCache.set(url, {
                    data: data,
                    time: Date.now()
                });

                sendResponse({
                    success: true,
                    data: data
                });

            })
            .catch((err) => {

                console.error("🚨 Final failure:", err);

                sendResponse({
                    success: false,
                    error: err.message || "Unknown error"
                });

            });

        return true;
    }
});


// -----------------------------------------
// FETCH WITH RETRY FUNCTION
// -----------------------------------------

async function fetchWithRetry(payload, retries = 2) {

    for (let attempt = 0; attempt <= retries; attempt++) {

        try {

            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 5000);

            const response = await fetch("http://127.0.0.1:5000/analyze", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(payload),
                signal: controller.signal
            });

            clearTimeout(timeout);

            // ❗ HTTP ERROR CHECK
            if (!response.ok) {
                throw new Error("Server error: " + response.status);
            }

            const text = await response.text();

            if (!text || text.trim() === "") {
                throw new Error("Empty response from backend");
            }

            let data;

            try {
                data = JSON.parse(text);
            } catch (err) {
                throw new Error("Invalid JSON response");
            }

            // ❗ VALIDATION
            if (!data || typeof data !== "object") {
                throw new Error("Malformed backend response");
            }

            return data;

        } catch (err) {

            console.warn(`⚠ Attempt ${attempt + 1} failed:`, err.message);

            // last attempt → throw error
            if (attempt === retries) {
                throw err;
            }

            // retry delay
            await new Promise(res => setTimeout(res, 500));
        }
    }
}