# Changelog: Phish-Defender AI v2.0.0

This changelog documents all structural, architectural, algorithmic, and UI improvements made to transform the Intelligent Phishing Domain Detection System MVP into a robust, production-ready security tool.

## [2.0.0] - April 2026

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
