document.addEventListener("DOMContentLoaded", () => {

    const urlBox = document.getElementById("url");
    const statusBox = document.getElementById("status");
    const scoreBox = document.getElementById("score");

    const scanBtn = document.getElementById("scanBtn");
    const dashboardBtn = document.getElementById("dashboardBtn");


    // ----------------------------------------
    // GET CURRENT TAB URL
    // ----------------------------------------

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {

        const currentUrl = tabs[0].url;

        urlBox.innerText = currentUrl;

        scanWebsite(currentUrl);
    });


    // ----------------------------------------
    // SCAN FUNCTION
    // ----------------------------------------

    function scanWebsite(url) {

        statusBox.innerText = "Scanning...";
        statusBox.className = "status";

        fetch("http://127.0.0.1:5000/analyze", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url,
                dom_features: {},
                page_text: ""
            })

        })
        .then(res => res.json())
        .then(data => {

            console.log("Popup scan result:", data);

            if (data.verdict === "Phishing") {

                statusBox.innerText = "⚠ Dangerous Website";
                statusBox.classList.add("danger");

            } else {

                statusBox.innerText = "✅ Safe Website";
                statusBox.classList.add("safe");
            }

            scoreBox.innerText = "Threat Score: " + (data.final_score * 100).toFixed(0) + "%";
        })
        .catch(err => {

            console.error(err);

            statusBox.innerText = "⚠ Error connecting backend";
            statusBox.classList.add("danger");
        });
    }


    // ----------------------------------------
    // BUTTON: SCAN AGAIN
    // ----------------------------------------

    scanBtn.addEventListener("click", () => {

        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {

            const url = tabs[0].url;

            scanWebsite(url);
        });

    });


    // ----------------------------------------
    // BUTTON: OPEN DASHBOARD
    // ----------------------------------------

    dashboardBtn.addEventListener("click", () => {

        chrome.tabs.create({
            url: chrome.runtime.getURL("dashboard.html")
        });

    });

});