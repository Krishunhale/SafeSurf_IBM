// script.js
// Handles URL and Email analysis for SafeSurf frontend

// Icons for each result type
const ICONS = {
    Safe: "✅",
    Suspicious: "⚠️",
    Malicious: "🚨"
};

// Show loading state on button
function setLoading(isLoading) {
    const btn = document.getElementById("analyzeBtn");
    const spinner = document.getElementById("spinner");
    const btnText = document.getElementById("btnText");

    if (isLoading) {
        btn.disabled = true;
        spinner.style.display = "block";
        btnText.textContent = "Analyzing...";
    } else {
        btn.disabled = false;
        spinner.style.display = "none";
        btnText.textContent = btn.id === "analyzeBtn" ? "Analyze" : "Analyze";
    }
}

// Display result on the page
function showResult(data) {
    const box = document.getElementById("resultBox");
    const icon = document.getElementById("resultIcon");
    const title = document.getElementById("resultTitle");
    const score = document.getElementById("resultScore");
    const bar = document.getElementById("scoreBar");
    const list = document.getElementById("reasonsList");

    // Set result box color class
    box.className = "result-box " + data.result;
    box.style.display = "block";

    // Set icon and title
    icon.textContent = ICONS[data.result] || "🔍";
    title.textContent = data.result;
    title.className = "result-title " + data.result;

    // Set score text
    score.textContent = "Risk Score: " + data.score + " / 100";

    // Animate score bar
    setTimeout(() => {
        bar.style.width = Math.min(data.score, 100) + "%";
        bar.className = "score-bar-fill " + data.result;
    }, 100);

    // List reasons
    list.innerHTML = "";
    if (data.reasons && data.reasons.length > 0) {
        data.reasons.forEach(reason => {
            const li = document.createElement("li");
            li.textContent = reason;
            list.appendChild(li);
        });
    } else {
        const li = document.createElement("li");
        li.textContent = "No specific issues detected.";
        list.appendChild(li);
    }

    // Scroll result into view smoothly
    box.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// Show error message
function showError(msg) {
    const box = document.getElementById("resultBox");
    box.className = "result-box Malicious";
    box.style.display = "block";
    box.innerHTML = `<p style="color:#ef4444; font-weight:600;">⚠️ ${msg}</p>`;
}

// ── Analyze URL ──
async function analyzeURL() {
    const url = document.getElementById("urlInput").value.trim();
    if (!url) {
        showError("Please enter a URL to analyze.");
        return;
    }

    setLoading(true);

    try {
        const response = await fetch("/analyze/url", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            showError("Server error. Make sure Flask is running.");
            return;
        }

        const data = await response.json();
        showResult(data);

    } catch (err) {
        showError("Could not connect to server. Is Flask running?");
    } finally {
        setLoading(false);
    }
}

// ── Analyze Email ──
async function analyzeEmail() {
    const emailText = document.getElementById("emailInput").value.trim();
    if (!emailText) {
        showError("Please paste some email content to analyze.");
        return;
    }

    setLoading(true);

    try {
        const response = await fetch("/analyze/email", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email_text: emailText })
        });

        if (!response.ok) {
            showError("Server error. Make sure Flask is running.");
            return;
        }

        const data = await response.json();
        showResult(data);

    } catch (err) {
        showError("Could not connect to server. Is Flask running?");
    } finally {
        setLoading(false);
    }
}