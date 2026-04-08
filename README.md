# Phish-Defender AI 🛡️

A highly concurrent, multi-agent cybersecurity intelligence system that orchestrates specialized AI agents to analyze, cross-reference, and classify zero-day phishing domains in real-time.

## Key Features

- **Concurrent 6-Agent Pipeline:** Evaluates Domain Similarity, Infrastructure Intelligence, Website Content, Google Safe Browsing, PhishTank, and Cross-Reference Engine signals in parallel.
- **Deep Content Analysis with Playwright:** Uses headless Chromium with a 4-tier fallback retry mechanism to render obfuscated JavaScript, identify injected login/payment forms, and extract OTP requests over dynamic pages.
- **Cross-Reference Engine (CRE):** A dedicated correlation layer combining brand intelligence, domain similarity, and content anomalies to detect sophisticated impersonations on hosted subdomains.
- **Dynamic Threat Intelligence:** Native real-time lookups using both Google Safe Browsing v4 and the PhishTank API, incorporating transparent fail-open/fail-closed states.
- **Advanced Heuristic Decision Models:** Features adaptive weight redistribution, deadly phishing signature combo multipliers, trust anchor breaking, and graceful degradation for legitimate apps.
- **Production-Ready Web Dashboard:** A premium glassmorphic Vite/React SPA frontend integrated seamlessly into a Flask WSGI backend with robust memory-safe rate limiting.

## Tech Stack

- **Backend:** Python 3.10+, Flask, Gunicorn
- **Orchestration:** `threading.Event`, isolated daemon threads
- **Frontend:** React, Vite, Tailwind CSS
- **Browser/Scraping:** Playwright (Chromium), BeautifulSoup4
- **Domain Intelligence:** `python-whois`, `dnspython`, `tldextract`, `rapidfuzz`

## Architecture Overview

The system relies on an isolated multi-agent pipeline executing concurrently:
1. **Pipeline Watchdog:** Bounds execution to a strict 30s global deadline, triggering hard timeouts via thread Events to prevent application blocks while maintaining system stability.
2. **Analysis Agents:** Five specialized agents independently evaluate Domain Similarity, Infrastructure Intelligence, HTML/JS Content, Safe Browsing, and PhishTank lookups.
3. **Cross-Reference Engine (CRE):** Acts as the correlation intelligence layer, fusing conflicting or overlapping signals across different agents (e.g. content brands vs actual domain structures).
4. **Decision Agent:** Aggregates findings, applies categorical combo multipliers, redistributes scoring weights based on signal availability, and produces the final classification (SAFE, SUSPICIOUS, or PHISHING) packed with human-readable causal explanations.

## Project Structure

- `app.py`: Main Flask WSGI server application serving the frontend and API `/analyze` routes with built-in sliding-window rate limiting.
- `agents/`: Contains all modular intelligence and classification agents (`domain_similarity_agent.py`, `website_content_agent.py`, `decision_agent.py`, etc.).
- `core/`: Core pipeline orchestration (`pipeline.py`), configuration constants (`config.py`), user input validation (`user_input_domain.py`), and the Cross-Reference Engine (`cross_reference_engine.py`).
- `data/`: Caching directory used for storing the local PhishTank database components for O(1) rapid lookups.
- `frontend/`: Source code for the premium React/Vite web dashboard UI/UX.

## Configuration

Phish-Defender AI is entirely controlled via environment configuration within the `.env` file.

| Variable | Default | Description |
|----------|---------|-------------|
| `GOOGLE_SAFE_BROWSING_API_KEY` | `""` | Google Safe Browsing API v4 key. |
| `HEADLESS` | `true` | Set to `false` for automatic browser launch to the dashboard on startup. |
| `PORT` | `8080` | Local or Server port binding. |
| `RESOLVE_SERVER_IP` | `false` | Fetch public IP and location in background threads upon startup. |

## 📊 Output / Results

To validate the model's independent heuristics, Phish-Defender AI was benchmarked against a live dataset consisting entirely of **confirmed phishing links** sourced directly from [PhishTank's Developer API](https://www.phishtank.com/developer_info.php). 

For this rigorous stress test, **Google Safe Browsing was completely disabled**, forcing the system to rely purely on its own proprietary AI agents (Content, Similarity, and Intelligence) to detect zero-day threat patterns.

### 🧪 Live Batch Test Results (100 URLs)

| Classification | Count | Description |
|:---|:---:|:---|
| 🔴 **PHISHING** | 68 | Confirmed immediate threats triggered by high-risk indicators. |
| 🟡 **SUSPICIOUS** | 15 | Moderate-to-high risk indicators requiring extreme caution. |
| 🟢 **SAFE** | 17 | Successfully evaded detection heuristics. |

**Final Detection Rate:** The system successfully caught and flagged **83 out of 100 (83%)** confirmed active phishing links based purely on zero-day heuristic intelligence, functioning entirely independent of standard blacklists.

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
#Install NPM
sudo apt-get update && sudo apt-get install nodejs npm

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
. .venv/bin/activate

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


## Usage

Interact with the engine natively via the full-scale web application interface. Alternatively, perform programmatic security scans by directly triggering `GET` calls to the `/analyze` route:

```bash
curl "http://localhost:8080/analyze?domain=suspicious-site.com&safebrowsing=true&phishtank=true"
```


## Known Issues / Limitations

- **JavaScript Rendering Latencies:** Highly obfuscated JS-heavy frameworks may occasionally trigger Playwright timeouts during analysis, though the platform intelligently handles this using a degraded non-JS DOM extraction fallback mechanism to prevent blocking.
- **Process Worker Limitations:** Playwright's Headless Chromium necessitates strict hardware memory boundaries. Because it is not intrinsically fork-safe, the system mandates that Gunicorn executes continuously restricted under `--workers 1`.

## Future Improvements

- Architect scale-out capacity through remote headless browser swarms running independently inside orchestrated container clusters.
- Expand detection layers to ingest Vision-Language Models (VLMs) tailored for visual layout and deep-fake CSS brand impersonation analysis.
