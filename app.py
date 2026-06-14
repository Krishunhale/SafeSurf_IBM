# app.py
# Main Flask backend for SafeSurf

from flask import Flask, request, jsonify, render_template
from detector import check_url, check_email

app = Flask(__name__)


# ─────────────────────────────────────────────
# PAGE ROUTES (serve HTML pages)
# ─────────────────────────────────────────────

@app.route("/")
def home():
    """Serves the homepage."""
    return render_template("index.html")


@app.route("/url-checker")
def url_checker():
    """Serves the URL Checker page."""
    return render_template("url_checker.html")


@app.route("/email-checker")
def email_checker():
    """Serves the Email Checker page."""
    return render_template("email_checker.html")


# ─────────────────────────────────────────────
# API ROUTES (handle analysis requests)
# ─────────────────────────────────────────────

@app.route("/analyze/url", methods=["POST"])
def analyze_url():
    data = request.get_json()
    if not data or "url" not in data or not data["url"].strip():
        return jsonify({"error": "No URL provided."}), 400
    url = data["url"].strip()
    result = check_url(url)
    return jsonify(result)


@app.route("/analyze/email", methods=["POST"])
def analyze_email():
    data = request.get_json()
    if not data or "email_text" not in data or not data["email_text"].strip():
        return jsonify({"error": "No email content provided."}), 400
    email_text = data["email_text"].strip()
    result = check_email(email_text)
    return jsonify(result)


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    if not data or "input" not in data or not data["input"].strip():
        return jsonify({"error": "No input provided."}), 400
    user_input = data["input"].strip()
    if user_input.startswith("http://") or user_input.startswith("https://") or user_input.startswith("www."):
        result = check_url(user_input)
        result["type"] = "URL"
    else:
        result = check_email(user_input)
        result["type"] = "Email"
    return jsonify(result)


# ─────────────────────────────────────────────
# Run the app
# ─────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True)
