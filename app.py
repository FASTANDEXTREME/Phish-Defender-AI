import logging
import os
import re
import threading
import time
from collections import defaultdict

from flask import Flask, request, jsonify, g
from flask_cors import CORS

from core.pipeline import run_pipeline

# ---------------------------------------------------------------------------
# App setup — serve frontend/dist as static root so index.html is at "/"
# ---------------------------------------------------------------------------
app = Flask(__name__, static_folder='frontend/dist', static_url_path='')
CORS(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-process rate limiter (no external dependency required)
# ---------------------------------------------------------------------------
class RateLimiter:
    """
    Simple sliding-window rate limiter keyed by client IP.
    Thread-safe via a lock. No external dependency (Redis etc.) needed.
    Periodically evicts stale IPs to prevent memory growth.
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self._max = max_requests
        self._window = window_seconds
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()
        self._last_cleanup = time.monotonic()
        self._cleanup_interval = 300  # Evict stale IPs every 5 minutes

    def is_allowed(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            # Periodic full cleanup of stale IPs
            if now - self._last_cleanup > self._cleanup_interval:
                self._evict_stale(now)
                self._last_cleanup = now

            timestamps = self._hits[key]
            # Prune expired entries for this key
            cutoff = now - self._window
            self._hits[key] = [t for t in timestamps if t > cutoff]
            if len(self._hits[key]) >= self._max:
                return False
            self._hits[key].append(now)
            return True

    def _evict_stale(self, now: float) -> None:
        """Remove IPs with no recent activity to prevent unbounded memory growth."""
        cutoff = now - self._window
        stale_keys = [
            key for key, timestamps in self._hits.items()
            if not timestamps or max(timestamps) < cutoff
        ]
        for key in stale_keys:
            del self._hits[key]


# 10 analysis requests per minute per IP — generous for humans, blocks bots
_rate_limiter = RateLimiter(max_requests=10, window_seconds=60)

# ---------------------------------------------------------------------------
# Request timeout middleware
# ---------------------------------------------------------------------------
MAX_REQUEST_TIMEOUT = 120  # seconds — hard cap for analysis requests


@app.before_request
def _start_timer():
    g.start_time = time.monotonic()


@app.after_request
def _check_timeout(response):
    """Log a warning if a request exceeded the soft timeout threshold."""
    start = getattr(g, "start_time", None)
    if start is not None:
        elapsed = time.monotonic() - start
        if elapsed > MAX_REQUEST_TIMEOUT:
            logger.warning(
                "Request to %s took %.1fs (exceeds %ds timeout)",
                request.path, elapsed, MAX_REQUEST_TIMEOUT,
            )
    return response


# ---------------------------------------------------------------------------
# Resolve server identity on startup (opt-in, disabled by default)
# Set RESOLVE_SERVER_IP=true to enable — sends server IP to ipapi.co
# ---------------------------------------------------------------------------
server_info = {"ip": "Unknown", "location": "Unknown"}


def _resolve_server_identity() -> None:
    """Fetch public IP/location in a background thread so startup isn't blocked."""
    try:
        import requests as _req
        resp = _req.get("https://ipapi.co/json/", timeout=5).json()
        server_info["ip"] = resp.get("ip", "Unknown")
        city = resp.get("city", "")
        country = resp.get("country_code", "")
        server_info["location"] = f"{city}, {country}".strip(", ")
        logger.info("Resolved server identity: %s | %s", server_info["ip"], server_info["location"])
    except Exception as exc:
        logger.warning("Failed to fetch server IP: %s", exc)


if os.environ.get("RESOLVE_SERVER_IP", "false").lower() == "true":
    threading.Thread(target=_resolve_server_identity, daemon=True).start()

# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------
_BLOCKED_PATTERNS = re.compile(
    r"^(localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|0\.0\.0\.0|\[::1\])",
    re.IGNORECASE,
)
MAX_DOMAIN_LENGTH = 253


def _validate_domain(raw: str) -> str:
    """Return cleaned domain or raise ValueError."""
    domain = raw.strip()
    if not domain:
        raise ValueError("Missing domain parameter")
    if len(domain) > MAX_DOMAIN_LENGTH:
        raise ValueError(f"Domain exceeds maximum length ({MAX_DOMAIN_LENGTH} chars)")
    if _BLOCKED_PATTERNS.match(domain):
        raise ValueError("Local/private domains are not allowed")
    return domain


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route('/')
def serve_frontend():
    """Serve the frontend single-page app."""
    return app.send_static_file('index.html')


@app.route('/healthz', methods=['GET'])
def health_check():
    """Health check endpoint for load balancers, monitoring, and container orchestration."""
    return jsonify({"status": "ok", "timestamp": time.time()}), 200


@app.route('/server_info', methods=['GET'])
def get_server_info():
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", os.environ.get("API_KEY", ""))
    return jsonify({**server_info, "api_key_active": bool(api_key)})


@app.route('/analyze', methods=['GET'])
def analyze():
    # --- Rate limiting ---
    client_ip = request.remote_addr or "unknown"
    if not _rate_limiter.is_allowed(client_ip):
        logger.warning("Rate limit exceeded for %s", client_ip)
        return jsonify({"error": "Rate limit exceeded. Please wait before making another request."}), 429

    raw_domain = request.args.get('domain', '')
    safebrowsing_enabled = request.args.get('safebrowsing', 'true').lower() == 'true'
    phishtank_enabled = request.args.get('phishtank', 'true').lower() == 'true'
    try:
        domain = _validate_domain(raw_domain)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    logger.info("Analyzing domain: %s | safebrowsing=%s | phishtank=%s", domain, safebrowsing_enabled, phishtank_enabled)

    try:
        result = run_pipeline(domain, safebrowsing_enabled=safebrowsing_enabled, phishtank_enabled=phishtank_enabled)
        return jsonify(result)
    except ValueError as e:
        logger.error("Validation error for %s: %s", domain, e)
        return jsonify({"error": str(e)}), 400
    except Exception:
        logger.exception("Unexpected error analyzing %s", domain)
        return jsonify({"error": "An internal error occurred during analysis"}), 500


# ---------------------------------------------------------------------------
# Entry point — for local development only.
# Production: use gunicorn -w 1 --threads 4 -b 0.0.0.0:8080 --timeout 120 app:app
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    PORT = int(os.environ.get("PORT", 8080))
    # Default to headless=true so forgetting to set it on a server doesn't open a browser
    HEADLESS = os.environ.get("HEADLESS", "true").lower() == "true"

    if not HEADLESS:
        try:
            import webbrowser
            threading.Timer(1.5, lambda: webbrowser.open(f"http://127.0.0.1:{PORT}")).start()
        except Exception:
            pass  # Silently skip if no browser available

    logger.info("Starting Phish-Defender AI on port %d (headless=%s)", PORT, HEADLESS)
    logger.info("NOTE: For production, use: gunicorn -w 1 --threads 4 -b 0.0.0.0:%d --timeout 120 app:app", PORT)
    app.run(debug=False, host="0.0.0.0" if HEADLESS else "127.0.0.1", port=PORT, use_reloader=False)
