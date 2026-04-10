# Changelog: Phish-Defender AI

This changelog documents all structural, architectural, algorithmic, and UI improvements made to transform the Intelligent Phishing Domain Detection System MVP into a robust, production-ready security tool.

## [2.7.0] - 10th April 2026
### Many Bug Fixes
  - Fixed many bugs related to general working.

### 🛡️ Anti-Bot Evasion & Scraping Reliability
- **Comprehensive Browser Header Impersonation**: 
  - Replaced hardcoded and minimal HTTP headers across the entire scraping and verification pipeline with a detailed, modern Chromium (v124) signature, including `sec-ch-ua` hints, `Sec-Fetch-*` directives, and extensive `Accept` encodings.
- **Reduced 403 Forbidden Rate**: 
  - Dramatically improved the ability to successfully pull live HTML content from strictly bot-protected, Cloudflare-fronted, or WAF-protected websites without triggering blocks.
- **Dynamic Header Management (`agents/website_content_agent.py`)**: 
  - Centralized connection headers into a `_MODERN_HEADERS` global dictionary. Integrated safe copying mechanics (`.copy()`) during secondary HTTP `User-Agent` fallback parsing to ensure clean session state.
- **Pre-Check WAF Bypassing (`batch_test.py`)**: 
  - Overhauled the `is_live` fast pre-check utility to leverage full browser headers. This prevents WAFs from instantly dropping un-headered connection sweeps, eliminating false "DEAD" initial classifications.

## [2.6.1] - 7th April 2026

### 🛡️ Security Hardening
- **RCE Elimination (`agents/domain_intelligence_agent.py`)**: 
  - Eradicated critical remote code execution vulnerability by replacing dangerous string interpolation with proper, sandboxed `sys.executable` argument arrays.
- **SSRF Blocklist Expansion (`app.py`)**: 
  - Greatly expanded the URL validation regex to strictly block parsing of malicious loopbacks (`[::1]`), AWS metadata injection endpoints (`169.254.169.254`), and Docker/Azure container subnets (`172.x`).
- **Data Protection**:
  - **Metadata:** Eliminated the `/server_info` API endpoint to stop exposing internal Docker routing and SafeBrowsing API key inclusion status.
  - **Exception Scrubbing:** Restructured Safe Browsing error flows to ensure API keys are never printed alongside exceptions in production logs.
- **Execution Path Security (`app.py`)**: 
  - Centralized global component warmup (Playwright instances, `.env` imports, and server resolution) strictly into `init_app()`, mitigating floating import-time execution risks.
- **Advanced SSRF Protection (`website_content_agent.py`)**: 
  - Rewrote internal fetching to manually intercept raw HTTP redirects recursively up to 3 hops, deeply validating bounds via `socket.getaddrinfo` to block dynamic cloud metadata bouncing.

### 🧪 Automated Testing & CI/CD
- **Testing Framework (`tests/`)**:
  - Implemented the first phase of an automated `pytest`-driven testing harness, introducing exact validation coverage for SSRF blocks and brand impersonation false-negative traps.
- **CI/CD Quality Gates (`.github/workflows/main_phish-defender-ai.yml`)**:
  - Gated the main deployment pipeline; automated checks now spin up a virtual environment and run the Pytest suite. Deployment is aborted immediately if tests fail.
- **Frontend Quality Gates (`frontend/`, CI)**:
  - Validated ESLint states preventing React concurrent render mutations and wrapped Vite processes correctly through `loadEnv`. Deployed `npm ci` and `npm run lint` checks gracefully into the core GitHub Actions pipeline.

### 🐛 Algorithmic & Logic Bug Fixes
- **Exact Brand Subdomains (`agents/domain_similarity_agent.py`)**:
  - Fixed a logic error where spoofing an exact brand string on an alternate TLD (e.g., `paypal.net`) erroneously triggered the safe domain bypass hook.
- **Brand Substring Evasion (`agents/website_content_agent.py`)**:
  - Fixed a false-negative bypass where an adversarial domain (e.g., `openai-support.com`) could slip the impersonation check simply because it contained the text "openai" via substring matching; resolution relies on `tldextract` registrable domain verification.
- **Frontend URL Path Preservation (`frontend/src/App.jsx`)**:
  - Stopped frontend input fields from aggressively canonicalizing and pruning URL queries and subdirectory payloads, restoring full context for path-based backend heuristics.
- **Threat Intel Degradation State**:
  - Rebuilt intelligence agents and frontend dashboards to correctly expose `Disabled` and `Degraded` states rather than failing open and rendering an erroneous "Safe" classification when Safe Browsing API or Phishtank servers crash.
- **PhishTank Routing Resilience (`agents/phishtank_agent.py`)**:
  - Shifted update target explicitly onto safe `HTTPS` connections to protect cache syncing against MITM degradation.
  
### 🧹 Housekeeping
- Dropped hardcoded DNS resolvers (1.1.1.1) to allow fallback to native system resolvers for enterprise networks.
- Cleaned the repository of dead documentation (`frontend/README.md`) and unsafe live-reconnaissance artifacts (`takess.py`).
- Overhauled `.gitignore` explicitly blocking tracking of compiled `/dist/` files and `/data/` caches natively via `git rm --cached`.
- Detailed scrubbing of the `README.md` clearing obsolete deployment assets (e.g., `concurrent.futures`, `Dockerfile`, `lxml` bindings).
- Synchronized missing pipeline dependencies securely bounding `python-dateutil>=2.8.2` onto `requirements.txt`.

## [2.6.0] - 5th April 2026

### 🚀 Performance & Stability (Pipeline Hardening)
- **Absolute Thread Timeouts (`core/pipeline.py`)**: 
  - Eliminated complex `concurrent.futures` bottlenecks in favor of a highly reliable timeout strategy using `threading.Event` inside daemon threads. This guarantees isolated per-agent timeouts and prevents thread leakage when blocked by adversarial sites.
- **Global Pipeline Deadline**: 
  - Imposed a strict 30-second global execution deadline protected by a secondary asynchronous watchdog.
- **Heavy Rendering Early Exit**: 
  - Implemented an early exit optimization. If the fast intelligence layer (Google Safe Browsing or PhishTank) definitively confirms a malicious threat, the computationally expensive Playwright JS rendering phase is gracefully bypassed to heavily decrease overall response time.

### 📚 Documentation
- **Complete README Overhaul**: 
  - Rewrote the documentation with a structured outline detailing the architecture, technology stack, project structure, and known limitations, while thoroughly preserving all production setup and deployment commands.

---

## [2.5.0] - 4th April 2026

### 🚀 Major Upgrades & Audit Remediations
- **Cross-Reference Engine (`core/cross_reference_engine.py`)**: 
  - Introduced a dedicated Cross-Reference Engine (CRE) as a new pipeline stage between analysis agents and the Decision Agent.
  - Correlates brand signals across Content, Similarity, and Intelligence agents to detect impersonation patterns that no single agent can identify alone.
  - Produces an independent `cross_ref_risk_score` (0.0–1.0) that feeds into the Decision Agent as a 4th scoring dimension.
  - Moved Combos 6–9 (brand impersonation + hosted platform, payment on disposable, scam indicators) from the Decision Agent into the CRE for cleaner separation of concerns.
- **Content Brand Impersonation Engine**: 
  - Added robust detection for brand impersonation by scanning page content (title, text, image alt tags, meta tags) and cross-referencing it against the actual domain.
- **Enhanced Sensitive Field Detection**: 
  - Added 3-layer detection for payment/credit card forms (including iframes like Stripe/Braintree) and OTP/verification codes.
- **Tech Support Scam Detection**: 
  - Implemented advanced tech support scam detection featuring keyword matching and regex-based toll-free phone number correlation.

### 🏗️ Architecture
- **6-Agent Pipeline with CRE**:
  - Pipeline now runs: 5 concurrent agents → Cross-Reference Engine → Decision Agent (was: 5 agents → Decision Agent).
  - CRE execution adds <1ms latency (pure CPU computation, no I/O).
  - Decision Agent scoring now supports 4-way weight distribution (Similarity/Intelligence/Content/CRE) when CRE has a non-zero signal.
- **Frontend: CRE Dashboard Card**:
  - Added a new "Cross-Reference Engine" metric card to the results dashboard showing brand impersonation status and CRE risk percentage.
  - New `cross_reference` category in the Risk Factor Breakdown explanation list.

### 🛡️ Algorithmic Improvements
- **Playwright Reliability & Fallbacks**: 
  - Added a 4-tier fallback retry mechanism (`networkidle` → `domcontentloaded` → `selectors` → `text`) to ensure reliable JS rendering, along with shadow DOM extraction. Added visible warnings when Playwright is unavailable.
- **Hosted Platform Suffix Matching**: 
  - Improved `is_hosted_platform` to match via suffix/endswith, correctly identifying subdomains on free hosting platforms. 
  - Expanded `KNOWN_HOSTING_PLATFORMS` with several new services (weeblysite.com, vercel, r2.dev, etc.).
- **Expanded Brand Catalog**: 
  - Added key heavily-phished brands including AT&T, Xfinity, OpenAI, and many others.
- **Rebalanced Scoring & Combos**: 
  - Adjusted base scoring weights (`0.30` Similarity, `0.30` Intelligence, `0.40` Content) and implemented dynamic reallocation when hosted platforms are detected.
  - CRE-aware weight distribution: `0.20` Similarity, `0.20` Intelligence, `0.30` Content, `0.30` CRE when cross-reference signals are present.
- **Tightened Legitimate App Guardrails**: 
  - Hardened the `legitimate_app_behavior` check with 4 new blockers (blocking reduction if critical vectors like brand impersonation or payment forms are detected).
- **URL Path Analytics**: 
  - Added deep URL path analysis including suspicious path mapping and Shannon entropy scoring to detect randomized throwaway endpoints.

### 🧰 Tooling & Data Fixes

- **PhishTank Data Synchronization (`agents/phishtank_agent.py`)**: 
  - Resolved a critical bug causing the background update thread to fail to propagate the refreshed in-memory cache to the live agent, resulting in the use of stale intelligence.


---

## [2.2.0] - 3rd April 2026

### 🚀 Major Features & Architectural Changes
- **Major Frontend Rework**: 
  - Fully migrated the legacy Vanilla HTML/JS frontend to a modern **Vite + React + Tailwind CSS** stack.
  - Implemented a premium, high-performance UI with enhanced glassmorphism and real-time state management.
- **PhishTank Threat Intelligence Integration (`agents/phishtank_agent.py`)**: 
  - Added a fifth intelligence agent that cross-references URLs against the official PhishTank global phishing database.
  - Features O(1) set-based lookups and automated, non-blocking background dataset refreshes (1-hour interval).
- **Dynamic Intelligence Toggles**:
  - Implemented query parameter support (`?safebrowsing=true/false` and `?phishtank=true/false`) for granular control over intelligence layers.
  - Updated the backend pipeline and decision agent to dynamically redistribute scoring weights when specific layers are disabled.
- **Headless Linux Terminal Support**:
  - Fully hardened for production-grade headless Linux server deployment.
  - Supports terminal-only environments (no DISPLAY needed) with resource-efficient Playwright pooling and Gunicorn WSGI readiness.

### 🛡️ Algorithmic Improvements
- **5-Way Parallel Pipeline (`core/pipeline.py`)**: 
  - Expanded the concurrent execution engine to support 5 agents (Similarity, Intelligence, Content, Google Safe Browsing, PhishTank) with per-agent error isolation.
- **Decision Score Integration (`agents/decision_agent.py`)**: 
  - Integrated PhishTank signals into the decision engine, providing high-risk overrides that work in tandem with Google Safe Browsing.

---

## [2.1.1] - 2nd April 2026

### 🚀 Major Upgrades
- **Playwright JS Rendering Engine (`agents/website_content_agent.py`)**: 
  - Upgraded the static DOM scraper to a full headless browser (Playwright Chromium) to evaluate obfuscated, dynamically loaded, or JavaScript-heavy React/Vue phishing sites. Includes anti-bot evasion headers.

### 🛡️ Algorithmic Improvements & Bug Fixes
- **Deep Subdomain Brand Detection (`agents/domain_similarity_agent.py`)**: 
  - Fixed a critical evasion tactic where phishers hid brands in long subdomains (e.g., `kucoin-login-auth.webflow.io`). The similarity agent now evaluates the entire subdomain string, instead of solely querying the root framework provider.
- **Deadly Combo Multipliers (`agents/decision_agent.py`)**: 
  - Restructured decision scoring to instantly bump known phishing vectors into the RED threshold based on categorical combinations (e.g., *Brand Impersonation + Hosted Platform*, or *New Domain + Login Form*).
- **Free Hosting Platform Awareness (`agents/domain_intelligence_agent.py`, `core/config.py`)**: 
  - Integrated `tldextract` to correctly retrieve WHOIS data for root domains spanning public suffix platforms (Vercel, Wix, Replit). If WHOIS intentionally fails for a known hosting platform, it receives a severe penalty.
- **Modern Input Harvester Detection (`agents/website_content_agent.py`)**: 
  - Expanded parsing logic beyond raw `<input type="password">` to flag suspicious `text`, `email`, `tel`, and `number` inputs frequently abused for OTPs and credit card harvesting. Includes mapping to `<title>` tags for brand impersonation context.
- **Expanded Brand Catalog (`core/config.py`)**: 
  - Added new high-value targeted brands spanning global ecommerce, international telecom arrays, and Web3 crypto exchanges (e.g., Kucoin, Trezor, Ledger).

---

## [2.1.0] - 2nd April 2026

### 🔧 Production-Level Codebase Optimization

Deep refactor and optimization pass across the entire codebase for production readiness — **15 targeted improvements** with zero behavioral changes.

### 🐛 Bug Fixes
- **Fixed fail-closed logic bug (`agents/safe_browsing_agent.py`)**: When the Safe Browsing API was unreachable and `fail_open=False`, the agent incorrectly returned `is_safe=True`. Now correctly returns `is_safe=False` with `risk_score=0.3`, matching the documented fail-closed intent.

### ⚡ Performance Improvements
- **Non-blocking server startup (`app.py`)**: Server IP/geolocation resolution moved from a synchronous blocking call (up to 5s delay) to a daemon background thread. Flask now starts instantly.
- **Streaming memory fix (`agents/website_content_agent.py`)**: Replaced `resp.content[:N]` (which buffers the entire HTTP response into memory) with proper `iter_content()` chunked reading that actually respects the 500KB size limit.
- **Eliminated redundant `tldextract.extract()` calls (`agents/domain_similarity_agent.py`)**: Previously called 4× per domain scan on the same input. Now extracted once in `run()` and passed to all downstream methods — ~4× fewer DNS/parsing operations per scan.
- **Connection pooling for Safe Browsing API (`agents/safe_browsing_agent.py`)**: Added `requests.Session` for HTTP connection reuse instead of creating new connections per API call.
- **Lazy `argparse` import (`core/pipeline.py`)**: Moved `import argparse` inside `main()` so it's only loaded when the CLI is used, saving import overhead for web server requests.
- **Cached DOM element references (`frontend/index.html`)**: 20+ `document.getElementById()` calls that ran on every scan are now cached at initialization time.

### 🧹 Code Quality & Cleanup
- **Removed unused imports**: `Tuple` from `core/user_input_domain.py`, top-level `argparse` from `core/pipeline.py`.
- **Top-level `import os` (`app.py`)**: Moved from inline route handler import to module-level per PEP 8.
- **Streamlined error collection (`core/pipeline.py`)**: Replaced 4 repetitive if-blocks for agent error/timing collection with a single data-driven loop.
- **Module-level warning suppression (`agents/website_content_agent.py`)**: `InsecureRequestWarning` filter moved from per-call inside `_fetch_html()` to module-level (runs once).
- **Static methods (`agents/domain_similarity_agent.py`)**: Converted `_extract_root_domain` and `_detect_phishing_keywords` to `@staticmethod` since they don't use instance state.
- **List comprehension (`agents/domain_similarity_agent.py`)**: Replaced imperative loop in `_detect_phishing_keywords` with a list comprehension.
- **Removed duplicate stylesheet (`frontend/index.html`)**: Material Symbols Outlined font was loaded twice via identical `<link>` tags.

### 🎨 UI/UX Improvements
- **Dynamic risk bar color coding (`frontend/index.html`)**: Similarity, Intelligence, and Content risk bars now dynamically change color based on risk percentage — 🟢 green (<30%), 🟡 yellow (30–60%), 🔴 red (≥60%) — instead of always displaying in cyan.

---

## [2.0.0] - 1st April 2026

### 🚀 Major Features & Architectural Changes
- **Frontend-Backend Integration (`app.py`)**: 
  - Integrated the standalone frontend directory to be served dynamically by the Flask backend at exactly `http://127.0.0.1:5000/`.
  - Added an auto-launch browser mechanism on startup.
- **Centralized Configuration (`core/config.py`)**: 
  - Abstracted all tunable constants, brand arrays (expanded to 75+ brands), keyword sets, homoglyph mapping dictionaries, scoring weights (now separate sets for with/without Safe Browsing), and threshold settings into a single configuration file for easy maintenance.
- **Pipeline Overhaul (`core/pipeline.py`)**:
  - Implemented singleton agent instances to improve performance and reduce initialization overhead.
  - Added per-agent concurrent execution with error isolation (a failure in one agent falls back to default zero-risk values instead of crashing the pipeline).
  - Included a `pipeline_metadata` payload in the JSON response measuring individual agent latency to the millisecond.
- **Google Safe Browsing Override (`agents/decision_agent.py`, `agents/safe_browsing_agent.py`)**: 
  - Safe Browsing output is no longer diluted by simple weighted averages. If Google flags a URL as malicious, it triggers a mandatory override forcing `classification: PHISHING`, `confidence: HIGH`, `severity: CRITICAL`, and `risk_score: 1.0`.
  - The Safe Browsing agent now dynamically loads its `API_KEY` from a project root `.env` file and handles missing keys gracefully (fail-open vs. fail-closed modes).

### 🛡️ Algorithmic Improvements & Bug Fixes 
*(from Deep Scoring Integrity Audit)*
- **Non-Linear Similarity Scoring (`agents/domain_similarity_agent.py`)**: 
  - Fixed a critical false-negative bug where blatant typosquats (e.g., `gooogle.com`) and homoglyphs (e.g., `g00gle.com`) scored `0.29` (SAFE). High matches (`>0.85`) now scale non-linearly to output much higher risk (`0.75`), properly pushing them into the SUSPICIOUS or PHISHING thresholds.
- **Short Brand Protection (`agents/domain_similarity_agent.py`)**: 
  - Implemented a `len(brand) >= 4` filter for generic partial matching, and a standalone segment regex check for containment matching. This eliminated false-positives where short brands like `dhl` or `x.com` were spuriously triggered by innocent domains (e.g., `xn--py5a.com`, `dhl-track.com`).
- **Graduated Domain Age Scoring (`agents/domain_intelligence_agent.py`)**: 
  - Removed binary scoring. Implementation now uses a 5-tier graduated risk model assessing domain age (Unknown, <7 days, <30 days, <90 days, <365 days, Established).
  - Reduced the risk weight given to simply missing or failing WHOIS data (`age=None`) from `0.30` down to `0.15` to stop punishing innocent domains with network timeouts.
- **Double Counting Resolution (`agents/website_content_agent.py`)**: 
  - `login_form_detected` and `password_field_detected` were merged to stop double-penalizing legitimate login pages across the web.
  - Greatly increased the weight payload on `cross_domain_forms` parameter (up to `0.35`) as it's the strongest signal of credential harvesting.
- **Dynamic Weight Redistribution (`agents/decision_agent.py`)**: 
  - Added dynamic weight adjustment. When `safe_browsing_agent` returns zero threat (safe), its heavy 30-35% weight factor is redistributed to the remaining 3 agents (now weighted 40/30/30). This allows the other 3 agents to independently reach the PHISHING threshold without relying exclusively on Google.
  - Lowered static thresholds (`PHISHING` to `0.60`, `SUSPICIOUS` to `0.30`) to better align with the new scoring mathematical constraints. Increased corroboration boost to `1.30` (30%).

### 🎨 Frontend Integrity & UI Updates (`frontend/index.html`)
- **Restored UI Authenticity:** Removed 5 completely fake, hardcoded UI data points from the MVP and replaced them with live dynamic tracking.
  1. Replaced static "System Integrity 94.8% Pure" bar with a live **Scans Completed** session counter.
  2. Replaced "LATENCY: 24MS" footer metric with the **real execution latency** provided by `pipeline_metadata.total_ms`. 
  3. Replaced "DB CONNECTED" with a live status check indicating if the Google Safe Browsing **API Key is ACTIVE or MISSING**.
  4. Corrected footer to properly display **v2.0.0 and © 2026**.
  5. Neutralized the default UI state before a scan (no longer reads "HIGH RISK DETECTED" by default).
- Added rendering support for `severityBadge` and `confidenceLabel` metrics now outputted directly by the `decision_agent`.
- Restructured all API requests to use relative paths (`/analyze`, `/server_info`) instead of hardcoded `localhost:5000`.

### 🔒 Security
- **Server Side Request Forgery (SSRF)**: Added mitigation steps to cleanly block resolving local addresses (`localhost`, `127.0.0.1`, `0.0.0.0`, `10.x.x.x`).
- Enforced a `253` max character length on domain validation to restrict abuse cases.
