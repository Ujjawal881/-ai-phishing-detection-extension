let pieChart, barChart, lineChart;

document.addEventListener("DOMContentLoaded", () => {

    loadDashboard();

    setInterval(loadDashboard, 5000);
});

// ============================================
// LOAD DASHBOARD DATA
// ============================================

function loadDashboard() {

    fetch("http://127.0.0.1:5000/dashboard")

    .then(res => res.json())

    .then(data => {

        const tableBody = document.getElementById("logTable");
        tableBody.innerHTML = "";

        let safe = 0;
        let phishing = 0;

        let labels = [];
        let scores = [];

        data.slice(0, 10).forEach(item => {

            const row = document.createElement("tr");

            const statusClass =
                item.verdict === "Phishing" ? "danger-text" : "safe-text";

            if (item.verdict === "Phishing") phishing++;
            else safe++;

            labels.push(item.url.substring(0, 25));
            scores.push(item.score);

            row.innerHTML = `
                <td title="${item.url}">${item.url.substring(0, 50)}</td>
                <td>${item.score.toFixed(2)}</td>
                <td class="${statusClass}">${item.verdict}</td>
                <td>${new Date(item.time).toLocaleString()}</td>
            `;

            tableBody.appendChild(row);
        });

        // Update stats
        document.getElementById("safeCount").innerText = safe;
        document.getElementById("phishCount").innerText = phishing;
        document.getElementById("totalCount").innerText = data.length;

        updateCharts(safe, phishing, labels, scores);
    })

    .catch(err => {
        console.error("Dashboard load failed:", err);
    });
}


// ============================================
// UPDATE CHARTS (UPGRADED 🔥)
// ============================================

function updateCharts(safe, phishing, labels, scores) {

    // ---------------- PIE (DOUGHNUT)
    if (pieChart) pieChart.destroy();

    pieChart = new Chart(document.getElementById("pieChart"), {
        type: "doughnut",
        data: {
            labels: ["Safe", "Phishing"],
            datasets: [{
                data: [safe, phishing],
                backgroundColor: ["#00ff9f", "#ff3b3b"],
                borderWidth: 1
            }]
        },
        options: {
            animation: { duration: 1200 },
            plugins: {
                legend: {
                    labels: { color: "white" }
                }
            }
        }
    });


    // ---------------- BAR
    if (barChart) barChart.destroy();

    barChart = new Chart(document.getElementById("barChart"), {
        type: "bar",
        data: {
            labels: labels,
            datasets: [{
                label: "Risk Score",
                data: scores,
                backgroundColor: "#3b82f6"
            }]
        },
        options: {
            animation: { duration: 1200 },
            scales: {
                x: {
                    ticks: { color: "white" }
                },
                y: {
                    ticks: { color: "white" }
                }
            },
            plugins: {
                legend: {
                    labels: { color: "white" }
                }
            }
        }
    });


    // ---------------- LINE (NEW 🔥)
    if (lineChart) lineChart.destroy();

    lineChart = new Chart(document.getElementById("lineChart"), {
        type: "line",
        data: {
            labels: labels,
            datasets: [{
                label: "Threat Trend",
                data: scores,
                borderColor: "#ff3b3b",
                backgroundColor: "rgba(255,59,59,0.2)",
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            animation: { duration: 1200 },
            scales: {
                x: {
                    ticks: { color: "white" }
                },
                y: {
                    ticks: { color: "white" }
                }
            },
            plugins: {
                legend: {
                    labels: { color: "white" }
                }
            }
        }
    });
}