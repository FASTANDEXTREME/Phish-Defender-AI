import logging
import os
import re
import threading
import webbrowser

from flask import Flask, request, jsonify
from flask_cors import CORS

from core.pipeline import run_pipeline

# ---------------------------------------------------------------------------
# App setup — serve frontend/ as static root so index.html is at "/"
# ---------------------------------------------------------------------------
app = Flask(__name__, static_folder='frontend', static_url_path='')
CORS(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Resolve server identity on startup (non-blocking fallback)
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


@app.route('/server_info', methods=['GET'])
def get_server_info():
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", os.environ.get("API_KEY", ""))
    return jsonify({**server_info, "api_key_active": bool(api_key)})


@app.route('/analyze', methods=['GET'])
def analyze():
    raw_domain = request.args.get('domain', '')
    try:
        domain = _validate_domain(raw_domain)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    logger.info("Analyzing domain: %s", domain)

    try:
        result = run_pipeline(domain)
        return jsonify(result)
    except ValueError as e:
        logger.error("Validation error for %s: %s", domain, e)
        return jsonify({"error": str(e)}), 400
    except Exception:
        logger.exception("Unexpected error analyzing %s", domain)
        return jsonify({"error": "An internal error occurred during analysis"}), 500


# ---------------------------------------------------------------------------
# Entry point — auto-launch browser
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    PORT = 5000
    # Open browser after a short delay so Flask has time to bind
    threading.Timer(1.5, lambda: webbrowser.open(f"http://127.0.0.1:{PORT}")).start()
    app.run(debug=True, port=PORT, use_reloader=False)
