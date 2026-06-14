<img width="1920" height="1008" alt="image" src="https://github.com/user-attachments/assets/b70fa3a7-9558-4ad7-8725-e9411993810c" />
<img width="1920" height="1008" alt="image" src="https://github.com/user-attachments/assets/0b9289fb-9778-4784-adfd-a3af20541442" />
<img width="1920" height="1008" alt="image" src="https://github.com/user-attachments/assets/d16c2ebf-4fa3-44ed-b4f4-9575cbcfe9ff" />
<img width="1920" height="1008" alt="image" src="https://github.com/user-attachments/assets/a84e1401-f984-42d9-9106-b0916e66d71c" />
<img width="1920" height="1008" alt="image" src="https://github.com/user-attachments/assets/cb712b21-1280-4973-a08e-8c1e9174b3d2" />


SafeSurf is a beginner-friendly cybersecurity web application that detects phishing URLs and spam emails using rule-based detection logic. Built as an academic project by second-year BTech IT students.
🌐 Live Demo: [safesurf-ibm.onrender.com](https://safesurf-ibm.onrender.com/)
About the Project
SafeSurf is a web-based cybersecurity tool designed to help everyday users identify:
Phishing URLs — fake websites designed to steal your credentials
Spam Emails — deceptive messages trying to scam or mislead you
The goal of this project is to provide a simple, fast, and explainable detection system without relying on complex machine learning or paid APIs. All detection is rule-based, making it easy to understand, maintain, and present in academic reviews.

 How It Works

URL Detection Rules

SafeSurf checks the following indicators for every URL:


HTTP vs HTTPS — Unsecured HTTP URLs get flagged
@ Symbol — Common phishing trick to disguise real destination
URL Length — URLs longer than 75 characters are suspicious
IP Address — Using raw IP instead of domain name is a red flag
Suspicious Keywords — Words like login, verify, free, winner, password
Too Many Subdomains — More than 3 dots in domain is unusual
Double Slashes — Unusual double slashes in URL path
Trusted Domain Whitelist — Known safe domains like google.com, github.com


Email Detection Rules

SafeSurf checks the following for every email:

Spam Keywords — Phrases like "you have won", "click here", "free money"
Urgency Phrases — "act now", "within 24 hours", "final notice"
Suspicious Links — Embedded URLs are also scanned using URL checker
Excessive Capitals — More than 30% words in ALL CAPS
Fake Reward Language — "gift card", "cash prize", "claim now"
Personal Info Requests — Asking for bank details, passwords, SSN
