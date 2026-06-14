# detector.py
# Detection logic for SafeSurf — rule-based URL and Email checker

import re 

# ─────────────────────────────────────────────
# URL DETECTION
# ─────────────────────────────────────────────

PHISHING_URL_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "banking", "confirm", "password", "signin", "webscr",
    "ebayisapi", "paypal", "free", "lucky", "winner",
    "click", "redirect", "checkout", "order"
]

TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "github.com",
    "microsoft.com", "apple.com", "amazon.com", "wikipedia.org",
    "stackoverflow.com", "linkedin.com"
]


def check_url(url):
    reasons = []
    score = 0

    # Convert to lowercase string for comparison
    url_lower = url.lower()

    # Rule 1: HTTP instead of HTTPS
    if url_lower.startswith("http://"):
        reasons.append("URL uses HTTP instead of HTTPS (not encrypted).")
        score += 20

    # Rule 2: @ symbol in URL
    if "@" in url:
        reasons.append("URL contains '@' symbol — common phishing trick.")
        score += 30

    # Rule 3: URL is very long
    if len(url) > 75:
        reasons.append(f"URL is unusually long ({len(url)} characters).")
        score += 20

    # Rule 4: IP address used instead of domain
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    if ip_pattern.search(url):
        reasons.append("URL uses an IP address instead of a domain name.")
        score += 35

    # Rule 5: Suspicious keywords in URL
    found_keywords = [kw for kw in PHISHING_URL_KEYWORDS if kw in url_lower]
    if found_keywords:
        reasons.append(f"URL contains suspicious keywords: {', '.join(found_keywords)}.")
        score += len(found_keywords) * 10

    # Rule 6: Too many subdomains
    try:
        domain_part = url_lower.replace("https://", "").replace("http://", "").split("/")[0]
        subdomain_count = domain_part.count(".")
        if subdomain_count > 3:
            reasons.append(f"URL has too many subdomains ({subdomain_count} dots in domain).")
            score += 25
    except Exception:
        pass

    # Rule 7: Double slashes in unusual position
    cleaned = url.replace("https://", "").replace("http://", "")
    if "//" in cleaned:
        reasons.append("URL contains double slashes in unusual position.")
        score += 15

    # Rule 8: Trusted domain whitelist
    is_trusted = any(trusted in url_lower for trusted in TRUSTED_DOMAINS)
    if is_trusted and score < 30:
        return {
            "result": "Safe",
            "score": score,
            "reasons": ["URL belongs to a commonly trusted domain."]
        }

    # Final verdict
    if score == 0:
        result = "Safe"
        reasons.append("No suspicious patterns detected.")
    elif score < 40:
        result = "Suspicious"
    else:
        result = "Malicious"

    return {
        "result": result,
        "score": score,
        "reasons": reasons
    }


# ─────────────────────────────────────────────
# EMAIL DETECTION
# ─────────────────────────────────────────────

SPAM_KEYWORDS = [
    "you have won", "click here", "free money", "urgent",
    "act now", "limited time", "claim your prize", "you are selected",
    "dear customer", "verify your account", "update your payment",
    "suspended", "unusual activity", "confirm your identity",
    "your account will be closed", "winner", "lottery",
    "bank account", "transfer funds", "100% free", "risk free",
    "no credit card", "earn money", "work from home", "congratulations"
]

URGENCY_PHRASES = [
    "immediately", "within 24 hours", "your account has been",
    "action required", "response required", "final notice",
    "last chance", "expires today", "don't delay", "respond now"
]


def check_email(email_text):
    reasons = []
    score = 0

    email_lower = email_text.lower()

    # Rule 1: Spam keywords
    found_spam = [kw for kw in SPAM_KEYWORDS if kw in email_lower]
    if found_spam:
        reasons.append(f"Email contains spam phrases: '{', '.join(found_spam[:3])}'.")
        score += len(found_spam) * 12

    # Rule 2: Urgency phrases
    found_urgent = [phrase for phrase in URGENCY_PHRASES if phrase in email_lower]
    if found_urgent:
        reasons.append(f"Email uses urgency tactics: '{', '.join(found_urgent[:2])}'.")
        score += len(found_urgent) * 15

    # Rule 3: Suspicious links inside email
    url_pattern = re.compile(r'http[s]?://\S+')
    found_urls = url_pattern.findall(email_text)
    if found_urls:
        for link in found_urls:
            link_result = check_url(link)
            if link_result["result"] in ["Suspicious", "Malicious"]:
                reasons.append(f"Email contains a suspicious link: {link[:50]}")
                score += 25
                break

    # Rule 4: Too many capital letters
    words = email_text.split()
    if len(words) > 5:
        caps_words = [w for w in words if w.isupper() and len(w) > 2]
        caps_ratio = len(caps_words) / len(words)
        if caps_ratio > 0.3:
            reasons.append("Email contains excessive capital letters (common spam tactic).")
            score += 20

    # Rule 5: Fake reward language
    reward_phrases = ["you have been selected", "claim now", "gift card",
                      "prize", "reward", "bonus", "cash prize", "free gift"]
    found_rewards = [rp for rp in reward_phrases if rp in email_lower]
    if found_rewards:
        reasons.append(f"Email contains fake reward language: '{', '.join(found_rewards[:2])}'.")
        score += len(found_rewards) * 15

    # Rule 6: Requests for personal information
    personal_requests = ["social security", "credit card number", "bank details",
                         "date of birth", "mother's maiden name", "password",
                         "pin number", "account number"]
    found_personal = [pr for pr in personal_requests if pr in email_lower]
    if found_personal:
        reasons.append(f"Email asks for sensitive personal information: '{', '.join(found_personal[:2])}'.")
        score += 40

    # Final verdict
    if score == 0:
        result = "Safe"
        reasons.append("No spam or phishing patterns detected in this email.")
    elif score < 40:
        result = "Suspicious"
    else:
        result = "Malicious"

    return {
        "result": result,
        "score": score,
        "reasons": reasons
    }