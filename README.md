# Phish-Defender AI 🛡️

Phish-Defender AI is a multi-agent cybersecurity intelligence system designed to detect phishing and malicious websites. Instead of relying on a single detection method, it orchestrates four specialized AI agents to analyze domains, perform DNS/WHOIS lookups, scrape live website content, and evaluate brand similarity in real-time.

## 🌟 Project Overview

The system accepts a domain or URL, validates it against Server-Side Request Forgery (SSRF) attempts, and analyzes it concurrently. It calculates a weighted risk score and outputs a final classification, confidence level, and detailed explanation. 

The entire backend and the visual "Command Center" frontend are seamlessly integrated, with the Python Flask server directly hosting the UI natively and updating live telemetry data.

---

## 🏗️ System Architecture & Workflow

### 1. The Pipeline (`core/pipeline.py`)
When a scan initializes, the pipeline starts a `ThreadPoolExecutor` to run all four intelligence agents fully in parallel. It isolates errors per agent—meaning if one agent fails (e.g., a WHOIS timeout), it falls back to a safe default rather than crashing the scan. It also calculates granular latency metadata for the frontend.

### 2. The Specialized Agents
- **Google Safe Browsing Agent (`safe_browsing_agent.py`)** 
  - Queries Google's Safe Browsing API v4.
  - **Authoritative Override:** If Google flags the URL as a threat, it triggers an immediate pipeline override, forcing a `1.0` (CRITICAL) risk score and a `PHISHING` classification, bypassing other agent opinions.
- **Domain Similarity Agent (`domain_similarity_agent.py`)** 
  - Detects typosquatting, brand impersonation, and homograph attacks.
  - Normalizes Unicode homoglyphs (e.g., `g00gle`, `paypaI`) and cross-references them against a centralized list of 75+ high-value corporate brands.
  - Utilizes `rapidfuzz` for multi-algorithmic fuzzy matching (Levenshtein distance, token sorting, and strict-length partial matching). Includes non-linear risk generation for >85% similarity matches.
- **Domain Intelligence Agent (`domain_intelligence_agent.py`)** 
  - Evaluates infrastructure legitimacy via `python-whois` and `dnspython`.
  - Checks domain age on a graduated 5-tier risk scale (from `<7 days` old to established).
  - Checks for the presence of Mail Exchange (MX) records, Name Servers (NS), and DNSSEC configurations.
  - Identifies contextual WHOIS privacy protections and short-expiry domains (registered for only 1 year and expiring within 30 days).
- **Website Content Agent (`website_content_agent.py`)** 
  - Scrapes the target website's live HTML code (capped at 500KB to prevent bomb-attacks).
  - Searches for high-risk credential harvesting indicators, such as cross-domain `<form>` submissions, excessive hidden `<input>` fields, iframe injections, and automated Meta/JS redirects.

### 3. The Decision Engine (`decision_agent.py`)
- Aggregates the numerical risk scores (0.0 to 1.0) from all four agents.
- **Dynamic Weight Redistribution:** If Google Safe Browsing returns "safe", the algorithm dynamically redistributes its heavy mathematical weight entirely to the custom Similarity (40%), Intelligence (30%), and Content (30%) agents, allowing them to independently catch zero-day attacks.
- Applies a **30% Corroboration Boost** to the final score if two or more agents independently detect high risk.
- Outputs the classification based on strict thresholds (`>=0.60`: PHISHING, `>=0.30`: SUSPICIOUS, `<0.30`: SAFE) alongside severity labels (LOW to CRITICAL).

### 4. The Frontend Command Center (`frontend/index.html`)
- A glassmorphic, cyberpunk-style dashboard served directly by the backend.
- Features live, real-world metrics (no hardcoded/fake stats), including session **Scans Completed**, **Live Pipeline Latency (MS)**, and **API Key Configuration Status**.

---

## 💻 Tech Stack
- **Backend**: Python 3.8+, Flask, Flask-CORS
- **Concurrency**: Python `concurrent.futures`
- **Scraping & Parsing**: `requests`, `beautifulsoup4`, `lxml`
- **String Matching**: `rapidfuzz` (Levenshtein based fuzzy matching)
- **Domain/DNS tools**: `python-whois`, `dnspython`, `tldextract`
- **Environment**: `python-dotenv`
- **Frontend**: HTML5, Vanilla CSS (Tailwind via CDN for utility), Vanilla JavaScript (Fetch API)

---

## 🚀 Setup & Installation

### Prerequisites
- Python 3.8 or higher.
- A free [Google Safe Browsing API Key](https://developers.google.com/safe-browsing) (Optional, but highly recommended for the override layer).

### Instructions
1. **Clone the repository:**
   ```bash
   git clone https://github.com/FASTANDEXTREME/Phish-Defender-AI.git
   cd Phish-Defender-AI
   ```
2. **Setup virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # macOS/Linux
   .venv\Scripts\activate     # Windows
   ```
3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
4. **Configure API Keys:**
   Create a `.env` file in the root directory and add your key. Without it, the Safe Browsing Agent gracefully fails-open and relies entirely on the custom AI agents.
   ```env
   GOOGLE_SAFE_BROWSING_API_KEY=your_api_key_here
   ```
5. **Launch the Analyzer:**
   ```bash
   python app.py
   ```
   The application will automatically boot the server and open your default system browser to the Command Center UI (`http://127.0.0.1:5000`).

---

## 🛡️ Important Security Considerations
- **No Browser Execution**: The Content Agent uses standard HTTP `requests` and BeautifulSoup for parsing. It cannot execute JavaScript challenges (e.g., Cloudflare Turnstile, CAPTCHAs). Domains protected by automated bot mitigation will trigger a `403 Forbidden` response, meaning the content agent will safely bypass analysis for that layer rather than crashing. 
- **SSRF Protection**: The backend enforces strict validation, automatically blocking local/private IP ranges (`127.x.x.x`, `10.x.x.x`, `192.168.x.x`, `localhost`) before scanning.

---
*Disclaimer: Phish-Defender AI is intended for educational, defensive cybersecurity, and threat intelligence research purposes.*
