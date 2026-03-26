from flask import Flask, request, jsonify
from flask_cors import CORS
from core.pipeline import run_pipeline
import logging

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend interaction

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

server_info = {"ip": "Unknown", "location": "Unknown"}
try:
    import requests
    resp = requests.get("https://ipapi.co/json/", timeout=5).json()
    server_info["ip"] = resp.get("ip", "Unknown")
    city = resp.get("city", "")
    country = resp.get("country_code", "")
    server_info["location"] = f"{city}, {country}".strip(", ")
    logger.info(f"Resolved server identity: {server_info['ip']} | {server_info['location']}")
except Exception as e:
    logger.warning(f"Failed to fetch server IP: {e}")

@app.route('/server_info', methods=['GET'])
def get_server_info():
    return jsonify(server_info)

@app.route('/analyze', methods=['GET'])
def analyze():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error": "Missing domain parameter"}), 400
    
    logger.info(f"Analyzing domain: {domain}")
    
    try:
        # Run the existing pipeline
        result = run_pipeline(domain)
        return jsonify(result)
    except ValueError as e:
        logger.error(f"Validation error for {domain}: {str(e)}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception(f"Unexpected error analyzing {domain}")
        return jsonify({"error": "An internal error occurred during analysis"}), 500

if __name__ == '__main__':
    # Run on default port 5000
    app.run(debug=True, port=5000)
