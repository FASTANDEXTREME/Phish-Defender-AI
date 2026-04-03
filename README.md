# Phish-Defender AI 🛡️

Phish-Defender AI is a multi-agent cybersecurity intelligence system designed to detect phishing and malicious websites. It orchestrates five specialized AI agents to analyze domains, perform DNS/WHOIS lookups, scrape live website content via a modern headless browser, and cross-reference multiple global threat intelligence databases in real-time.

---

## 🌟 Project Overview

The system accepts a domain or URL, validates it against Server-Side Request Forgery (SSRF) attempts, and analyzes it concurrently. It calculates a weighted risk score and outputs a final classification, confidence level, and detailed explanation. 

The latest version features a **completely reworked modern UI** and integrated **PhishTank Threat Intelligence**, providing a robust defense against zero-day phishing attacks.

---

## 🔥 Key Features (v2.2.0)

- ✅ **New UI / Command Center**: Rebuilt from the ground up using **Vite, React, and Tailwind CSS** for a premium, high-performance experience.
- ✅ **PhishTank Integration**: Real-time cross-referencing against the PhishTank global phishing database.
- ✅ **Dynamic API Toggles**: Ability to enable/disable **Google Safe Browsing** and **PhishTank** intelligence layers on-the-fly.
- ✅ **5-Way Parallel Pipeline**: Concurrent execution of all intelligence agents with per-agent error isolation.
- ✅ **Headless JS Rendering**: Full JavaScript execution via Playwright Chromium to catch obfuscated phishing kits.

---

## 🏗️ System Architecture & Workflow

### 1. The Pipeline (`core/pipeline.py`)
When a scan initializes, the pipeline starts a `ThreadPoolExecutor` to run all specialized intelligence agents fully in parallel. It isolates errors per agent—meaning if one agent fails (e.g., a network timeout), it falls back to a safe default rather than crashing the scan. It also calculates granular latency metadata for the frontend.

### 2. The Specialized Agents
- **PhishTank Intelligence Agent (`phishtank_agent.py`)** [NEW]
  - Queries the PhishTank global database of confirmed phishing URLs.
  - **Zero-Latency Lookups**: Operates on a local O(1) set-based cache for millisecond response times.
  - **Automated Sync**: Performs non-blocking background refreshes of the threat dataset every hour.
  - **No API Key Required**: Works out-of-the-box with public data downloads.
- **Google Safe Browsing Agent (`safe_browsing_agent.py`)** 
  - Queries Google's Safe Browsing API v4.
  - **Authoritative Override**: If Google flags the URL as a threat, it triggers an immediate pipeline override, forcing a `1.0` (CRITICAL) risk score and a `PHISHING` classification.
- **Domain Similarity Agent (`domain_similarity_agent.py`)** 
  - Detects typosquatting, brand impersonation, and homograph attacks.
  - Evaluates the **entire subdomain string**, catching impersonated brands deeply nested on free hosting platforms (e.g., `kucoin.webflow.io`).
  - Normalizes Unicode homoglyphs (e.g., `g00gle`, `paypaI`) and cross-references them against a centralized list of 75+ high-value corporate and Web3 brands.
  - Utilizes `rapidfuzz` for multi-algorithmic fuzzy matching (Levenshtein distance, token sorting, and strict-length partial matching). Includes non-linear risk generation for >85% similarity matches.
- **Domain Intelligence Agent (`domain_intelligence_agent.py`)** 
  - Evaluates infrastructure legitimacy via `python-whois`, `tldextract`, and `dnspython`.
  - Intelligently parses registered domains, applying heavy penalties if WHOIS data is deliberately hidden on known free hosting platforms (e.g., Vercel, Wix, Github Pages).
  - Checks domain age on a graduated 5-tier risk scale (from `<7 days` old to established).
  - Checks for the presence of Mail Exchange (MX) records, Name Servers (NS), and DNSSEC configurations.
  - Identifies contextual WHOIS privacy protections and short-expiry domains (registered for only 1 year and expiring within 30 days).
- **Website Content Agent (`website_content_agent.py`)** 
  - Utilizes **Playwright Headless Chromium** to render obfuscated, dynamically loaded, or JavaScript-heavy pages fully before analysis.
  - Recognizes generic `email`, `tel`, and `code` inputs frequently abused for OTPs and credential harvesting.
  - Tracks cross-domain `<form>` submissions, iframe injections, and automated Meta/JS redirects.

### 3. The Decision Engine (`decision_agent.py`)
- Aggregates the numerical risk scores (0.0 to 1.0) from all **five** specialized agents.
- **Deadly Combo Multipliers:** Applies immediate, massive risk multipliers for known zero-day heuristics (e.g., New Domain + Login Form, or Brand Similarity + Free Hosting Platform), instantly bypassing simple algorithm masking to score as `PHISHING/SUSPICIOUS`.
- **Dynamic Weight Redistribution:** If Google Safe Browsing returns "safe", the algorithm dynamically redistributes its mathematical weight entirely to the custom Intelligence (45%), Content (40%), and Similarity (15%) agents, allowing them to independently catch zero-day attacks.
- Applies a **50% Corroboration Boost** to the final score if two or more agents independently detect high risk (score `>= 0.40`).
- Outputs the classification based on strict thresholds (`>=0.45`: PHISHING, `>=0.30`: SUSPICIOUS, `<0.30`: SAFE) alongside severity labels (LOW to CRITICAL).

### 4. The Frontend Command Center (`frontend/index.html`)
- A glassmorphic, cyberpunk-style dashboard served directly by the backend.
- Features live, real-world metrics (no hardcoded/fake stats), including session **Scans Completed**, **Live Pipeline Latency (MS)**, and **API Key Configuration Status**.

---

## 📊 Performance & Accuracy

To validate the model's independent heuristics, Phish-Defender AI was benchmarked against a live dataset consisting entirely of **confirmed phishing links** sourced directly from [PhishTank's Developer API](https://www.phishtank.com/developer_info.php). 

For this rigorous stress test, **Google Safe Browsing was completely disabled**, forcing the system to rely purely on its own proprietary AI agents (Content, Similarity, and Intelligence) to detect zero-day threat patterns.

### 🧪 Live Batch Test Results (100 URLs)

| Classification | Count | Description |
|:---|:---:|:---|
| 🔴 **PHISHING** | 65 | Confirmed immediate threats triggered by high-risk indicators. |
| 🟡 **SUSPICIOUS** | 16 | Moderate-to-high risk indicators requiring extreme caution. |
| 🟢 **SAFE** | 19 | Successfully evaded detection heuristics. |

**Final Detection Rate:** The system successfully caught and flagged **81 out of 100 (81%)** confirmed active phishing links based purely on zero-day heuristic intelligence, functioning entirely independent of standard blacklists.

---

## 💻 Tech Stack
- **Backend**: Python 3.8+, Flask, Flask-CORS
- **Frontend**: **Vite, React, Tailwind CSS** (Modern High-Performance Stack)
- **Concurrency**: Python `concurrent.futures`
- **Dynamic Rendering**: `playwright`
- **Scraping & Parsing**: `requests`, `beautifulsoup4`, `lxml`
- **String Matching**: `rapidfuzz` (Levenshtein based fuzzy matching)
- **Domain/DNS tools**: `python-whois`, `dnspython`, `tldextract`

---

## 🚀 Setup & Installation

### Prerequisites
- Python 3.8 or higher.
- Node.js (for frontend development, optional for production if using bundled `dist`).
- A [Google Safe Browsing API Key](https://developers.google.com/safe-browsing) (Optional).

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
   playwright install chromium
   ```
4. **Configure API Keys:**
   Create a `.env` file in the root directory. Safe Browsing is optional; PhishTank requires no key.
   ```env
   GOOGLE_SAFE_BROWSING_API_KEY=your_api_key_here
   ```
5. **Launch the Analyzer:**
   ```bash
   python app.py
   ```

### Dynamic Toggles
The system supports dynamic enabling/disabling of intelligence layers via query parameters:
- `?safebrowsing=false`: Disable Google Safe Browsing layer.
- `?phishtank=false`: Disable PhishTank layer.

Example: `http://127.0.0.1:5000/analyze?domain=example.com&safebrowsing=true&phishtank=false`

---

## 🛡️ Important Security Considerations
- **SSRF Protection**: The backend enforces strict validation, automatically blocking local/private IP ranges (`127.x.x.x`, `10.x.x.x`, `192.168.x.x`, `localhost`) before scanning.
- **Automated Processing**: The Website Content Agent utilizes a headless browser to render dynamically generated malicious content. It applies evasive bot-detection headers but performs no interactive behavior with the website.

---
*Disclaimer: Phish-Defender AI is intended for educational, defensive cybersecurity, and threat intelligence research purposes.*
