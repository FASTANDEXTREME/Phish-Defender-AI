# Phish-Defender AI 🛡️

> **Now fully compatible with Headless Linux Terminal Deployment!** 🐧

Phish-Defender AI is a multi-agent cybersecurity intelligence system designed to detect phishing and malicious websites. It orchestrates five specialized AI agents to analyze domains, perform DNS/WHOIS lookups, scrape live website content via a modern headless browser, and cross-reference multiple global threat intelligence databases in real-time.

---

## 🌟 Project Overview

The system accepts a domain or URL, validates it against Server-Side Request Forgery (SSRF) attempts, and analyzes it concurrently. It calculates a weighted risk score and outputs a final classification, confidence level, and detailed explanation. 

The latest version features a **completely reworked modern UI** and integrated **PhishTank Threat Intelligence**, providing a robust defense against zero-day phishing attacks.

---

## 🔥 Key Features (v2.5.0)

- ✅ **New UI / Command Center**: Rebuilt from the ground up using **Vite, React, and Tailwind CSS** for a premium, high-performance experience.
- ✅ **Cross-Reference Engine (CRE)**: Dedicated correlation module that cross-references brand impersonation signals across content, infrastructure, and domain heuristics.
- ✅ **PhishTank Integration**: Real-time cross-referencing against the PhishTank global phishing database.
- ✅ **Dynamic API Toggles**: Ability to enable/disable **Google Safe Browsing** and **PhishTank** intelligence layers on-the-fly.
- ✅ **6-Agent Parallel Pipeline**: Concurrent execution of all intelligence agents, ending in a cross-reference synchronization step and per-agent error isolation.
- ✅ **Headless JS Rendering**: Full JavaScript execution via Playwright Chromium (with a 4-tier fallback) to catch obfuscated phishing kits.
- ✅ **Production-Ready**: Gunicorn WSGI server support, rate limiting, request timeouts, and health check endpoints.
- ✅ **Headless Linux Deployment**: Fully compatible with terminal-only servers — no GUI required.

---

## 🏗️ System Architecture & Workflow

### 1. The Pipeline (`core/pipeline.py`)
When a scan initializes, the pipeline starts a `ThreadPoolExecutor` to run all specialized intelligence agents fully in parallel. It isolates errors per agent—meaning if one agent fails (e.g., a network timeout), it falls back to a safe default rather than crashing the scan. It then aggregates their results using the **Cross-Reference Engine (CRE)** before passing them to the final Decision Engine. It also calculates granular latency metadata for the frontend.

### 2. The Specialized Agents
- **PhishTank Intelligence Agent (`phishtank_agent.py`)**
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
  - Utilizes **Playwright Headless Chromium** to render obfuscated, dynamically loaded, or JavaScript-heavy pages fully before analysis (with a robust 4-tier fallback: `networkidle` → `domcontentloaded` → `selectors` → `text`).
  - Features **Brand Impersonation Detection** by scanning page content (titles, alt text, meta tags) to ensure they match the domain.
  - Recognizes generic `email`, `tel`, and `code` inputs frequently abused for OTPs and credential harvesting, featuring a new 3-layer detection check for payment/credit card forms (including iframes like Stripe).
  - Identifies **Tech Support Scams** using deep keyword matching and regex-based toll-free phone number correlation.
  - Tracks cross-domain `<form>` submissions, iframe injections, and automated Meta/JS redirects.

### 3. The Cross-Reference Engine (`core/cross_reference_engine.py`)
- Acts as a dedicated stage between the parallel analysis agents and the decision agent.
- Explicitly correlates signals across Content, Similarity, and Intelligence agents (e.g., matching a brand impersonation signal from the Content Agent against a free-hosting indicator from the Intelligence Agent).
- Produces an independent `cross_ref_risk_score` (0.0 to 1.0) along with context on brand/content mismatches.

### 4. The Decision Engine (`decision_agent.py`)
- Aggregates the numerical risk scores (0.0 to 1.0) from all agents, including the new **Cross-Reference Engine**.
- **Deadly Combo Multipliers:** Applies immediate, massive risk multipliers for known zero-day heuristics instantly bypassing simple algorithm masking to score as `PHISHING/SUSPICIOUS`.
- **Dynamic Weight Redistribution:** If Google Safe Browsing returns "safe", the algorithm dynamically redistributes its mathematical weight to the custom Intelligence, Content, Similarity, and CRE agents. Uses a 4-way weight distribution explicitly factoring in the CRE signal when non-zero.
- Applies a **50% Corroboration Boost** to the final score if multiple agents independently detect high risk.
- Outputs the classification based on strict thresholds (`>=0.45`: PHISHING, `>=0.30`: SUSPICIOUS, `<0.30`: SAFE) alongside severity labels (LOW to CRITICAL).

### 5. The Frontend Command Center
- A glassmorphic, cyberpunk-style dashboard served directly by the backend as a pre-built Vite/React SPA.
- Features live, real-world metrics (no hardcoded/fake stats), including session **Scans Completed**, **Live Pipeline Latency (MS)**, and **API Key Configuration Status**.
- Displays the new **Cross-Reference Engine** metric card for brand impersonation context.
- No Node.js or npm is required on the server — the frontend is pre-compiled and served as static files.

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
- **Backend**: Python 3.10+, Flask, Flask-CORS, Gunicorn (WSGI)
- **Frontend**: **Vite, React, Tailwind CSS** (Pre-built SPA — no Node.js needed on server)
- **Concurrency**: Python `concurrent.futures`
- **Dynamic Rendering**: `playwright` (Headless Chromium)
- **Scraping & Parsing**: `requests`, `beautifulsoup4`, `lxml`
- **String Matching**: `rapidfuzz` (Levenshtein based fuzzy matching)
- **Domain/DNS tools**: `python-whois`, `dnspython`, `tldextract`

---

## 🚀 Setup & Installation

### Quick Start (Local Development — Windows/macOS)

```bash
# 1. Clone the repository
git clone https://github.com/FASTANDEXTREME/Phish-Defender-AI.git
cd Phish-Defender-AI

# 2. Setup virtual environment
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate   # Windows

# 3. Install dependencies
pip install -r requirements.txt
playwright install chromium

# 4. Configure environment
cp .env.example .env
# Edit .env and add your Google Safe Browsing API key (optional)

# 5. Launch (opens browser automatically)
HEADLESS=false python app.py
```

---

## 🐧 Linux Server Deployment (Headless — Complete Guide)

This section provides **every command** you need to run on a fresh Ubuntu/Debian Linux server to get Phish-Defender AI running in production.

### Prerequisites

- A Linux server (Ubuntu 22.04+ / Debian 12+ recommended)
- SSH access with sudo privileges
- Python 3.10 or higher
- Git installed

### Step 1 — Install System Dependencies

```bash
# Update packages
sudo apt update && sudo apt upgrade -y

# Install Python, pip, git, and essential build tools
sudo apt install -y python3 python3-pip python3-venv git curl wget

# Install whois binary (needed by the Domain Intelligence Agent)
sudo apt install -y whois
```

### Step 2 — Clone the Repository

```bash
cd /opt   # or your preferred directory
sudo git clone https://github.com/FASTANDEXTREME/Phish-Defender-AI.git
cd Phish-Defender-AI

# Set ownership to your user (replace 'youruser' with your username)
sudo chown -R $(whoami):$(whoami) /opt/Phish-Defender-AI
```

### Step 3 — Create Virtual Environment & Install Python Deps

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4 — Install Playwright (Headless Chromium)

```bash
# Install the Chromium browser binary
playwright install chromium

# Install system libraries required by Chromium (critical for headless servers)
playwright install-deps
```

> **Note:** `playwright install-deps` will install ~30 system packages (libx11, libnss3, libatk, etc.) that Chromium needs even in headless mode. This requires sudo access and is typically only needed once.

### Step 5 — Configure Environment Variables

```bash
nano .env
```

Edit the `.env` file with your settings:

```env
# Required for Google Safe Browsing checks (optional — system works without it)
GOOGLE_SAFE_BROWSING_API_KEY=your_api_key_here

# MUST be true for headless servers
HEADLESS=true

# Server port
PORT=8080

# Optional: resolve server's public IP on startup
RESOLVE_SERVER_IP=false
```

Save and exit (`Ctrl+X → Y → Enter` in nano).

### Step 6 — Ensure Data Directory Is Writable

```bash
# The PhishTank agent writes cached data here
mkdir -p data
chmod 755 data
```

### Step 7 — Launch with Gunicorn (Production)

```bash
# Activate venv if not already
. .venv/bin/activate

# Start the production server
gunicorn \
  --workers 1 \
  --threads 4 \
  --bind 0.0.0.0:8080 \
  --timeout 120 \
  --graceful-timeout 30 \
  --access-logfile - \
  --error-logfile - \
  app:app
```

**Why these settings?**
| Flag | Reason |
|------|--------|
| `--workers 1` | Playwright's Chromium process is not fork-safe — must use 1 worker |
| `--threads 4` | Allows 4 concurrent requests within the single worker |
| `--timeout 120` | Hard kill for requests taking longer than 2 minutes |
| `--graceful-timeout 30` | Gives in-flight requests 30s to finish on shutdown |
| `--bind 0.0.0.0:8080` | Listen on all interfaces |

The server will be accessible at `http://your-server-ip:8080`.

### Step 8 — Verify it Works

```bash
# Health check
curl http://localhost:8080/healthz
# Expected: {"status":"ok","timestamp":...}

# Test a scan
curl "http://localhost:8080/analyze?domain=google.com"
# Expected: JSON with classification, risk scores, etc.

# Test the frontend
curl -I http://localhost:8080/
# Expected: HTTP/1.1 200 OK with text/html
```

---

## 🔄 Running as a Systemd Service (Auto-Start on Boot)

Create a systemd unit file so the app starts automatically on boot and restarts on crash:

```bash
sudo nano /etc/systemd/system/phishdefender.service
```

Paste:

```ini
[Unit]
Description=Phish-Defender AI - Phishing Detection Service
After=network.target

[Service]
Type=notify
User=youruser
Group=youruser
WorkingDirectory=/opt/Phish-Defender-AI
Environment="PATH=/opt/Phish-Defender-AI/.venv/bin:/usr/bin:/bin"
EnvironmentFile=/opt/Phish-Defender-AI/.env
ExecStart=/opt/Phish-Defender-AI/.venv/bin/gunicorn \
    --workers 1 \
    --threads 4 \
    --bind 0.0.0.0:8080 \
    --timeout 120 \
    --graceful-timeout 30 \
    --access-logfile - \
    --error-logfile - \
    app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

> **Important:** Replace `youruser` with your actual Linux username in both `User=` and `Group=` fields.

Then enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable phishdefender
sudo systemctl start phishdefender

# Check status
sudo systemctl status phishdefender

# View live logs
sudo journalctl -u phishdefender -f
```

---

## 🌐 Nginx Reverse Proxy (Optional — HTTPS + Domain Name)

If you want HTTPS and a domain name:

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
```

Create Nginx config:

```bash
sudo nano /etc/nginx/sites-available/phishdefender
```

```nginx
server {
    listen 80;
    server_name yourdomain.com;   # Replace with your domain

    # Serve static assets directly for better performance
    location /assets/ {
        alias /opt/Phish-Defender-AI/frontend/dist/assets/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    location /favicon.svg {
        alias /opt/Phish-Defender-AI/frontend/dist/favicon.svg;
        expires 30d;
    }

    # Proxy everything else to Gunicorn
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
```

Enable and get SSL:

```bash
sudo ln -s /etc/nginx/sites-available/phishdefender /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

# Get free HTTPS certificate from Let's Encrypt
sudo certbot --nginx -d yourdomain.com
```

---

## 🐳 Docker Deployment (Alternative)

```bash
# Build
docker build -t phishdefender .

# Run (note: --shm-size is critical for Playwright Chromium)
docker run -d \
  --name phishdefender \
  --shm-size=256m \
  -p 8080:8080 \
  -e HEADLESS=true \
  -e GOOGLE_SAFE_BROWSING_API_KEY=your_key_here \
  phishdefender
```

> **Note:** `--shm-size=256m` is required because Playwright Chromium uses `/dev/shm` for shared memory. Docker defaults to 64MB which causes crashes.

---

## 🔧 API Reference

### `GET /analyze`

Analyze a domain for phishing.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `domain` | string | required | Domain or URL to analyze |
| `safebrowsing` | boolean | `true` | Enable/disable Google Safe Browsing |
| `phishtank` | boolean | `true` | Enable/disable PhishTank lookup |

**Example:**
```bash
curl "http://localhost:8080/analyze?domain=suspicious-site.com&safebrowsing=true&phishtank=true"
```

### `GET /server_info`
Returns server metadata and API key status.

### `GET /healthz`
Health check endpoint for load balancers and monitoring. Returns `{"status": "ok"}`.

### `GET /`
Serves the frontend SPA.

---

## ⚙️ Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GOOGLE_SAFE_BROWSING_API_KEY` | _(none)_ | Google Safe Browsing API v4 key |
| `HEADLESS` | `true` | Set to `false` to auto-open browser on local dev |
| `PORT` | `8080` | Server port |
| `RESOLVE_SERVER_IP` | `false` | Set to `true` to fetch public IP on startup |

---

## 🛡️ Security Considerations

- **SSRF Protection**: The backend enforces strict validation, automatically blocking local/private IP ranges (`127.x.x.x`, `10.x.x.x`, `192.168.x.x`, `localhost`) before scanning.
- **Rate Limiting**: Built-in rate limiter (10 requests/minute per IP) with automatic stale IP eviction.
- **API Key Safety**: Never commit `.env` — use `.env.example` as a template. The `.gitignore` already excludes `.env`.
- **Automated Processing**: The Website Content Agent utilizes a headless browser to render dynamically generated malicious content. It applies evasive bot-detection headers but performs no interactive behavior with the website.

---

## 📁 Project Structure

```
Phish-Defender-AI/
├── app.py                      # Flask entry point + routes
├── requirements.txt            # Python dependencies (pinned)
├── .env.example                # Environment variable template
├── .gitignore
├── agents/
│   ├── decision_agent.py       # Final risk aggregation & classification
│   ├── domain_similarity_agent.py  # Brand impersonation detection
│   ├── domain_intelligence_agent.py # WHOIS/DNS/SSL analysis
│   ├── website_content_agent.py    # HTML + Playwright content analysis
│   ├── safe_browsing_agent.py      # Google Safe Browsing API
│   └── phishtank_agent.py          # PhishTank database lookup
├── core/
│   ├── config.py               # Centralized configuration constants
│   ├── cross_reference_engine.py # Brand signal correlation across agents
│   ├── pipeline.py             # Concurrent agent orchestration
│   └── user_input_domain.py    # Input validation & cleaning
├── data/
│   ├── dist/                   # Pre-built SPA (served in production)
│   │   ├── index.html
│   │   └── assets/
│   ├── src/                    # React source (dev only)
│   ├── package.json
│   └── vite.config.js
├── data/
│   └── phishtank.json.gz       # PhishTank cache (auto-refreshed)
├── CHANGELOG.md
└── README.md
```

---

## 🔄 Updating the Frontend

The frontend is a pre-built React SPA. The server does NOT need Node.js. However, if you make changes to `frontend/src/`:

```bash
cd frontend
npm install
npm run build    # Outputs to frontend/dist/
cd ..
```

Then restart the server. The new build will be served automatically.

---

*Disclaimer: Phish-Defender AI is intended for educational, defensive cybersecurity, and threat intelligence research purposes.*
