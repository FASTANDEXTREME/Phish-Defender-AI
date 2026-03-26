# Phish-Defender AI 🛡️

Phish-Defender AI is an intelligent, multi-agent phishing domain detection system. It analyzes suspicious URLs and domains using several specialized AI agents, aggregating their risk scores to determine whether a domain is legitimate, suspicious, or an active phishing threat.

## 🌟 Key Features
- **Intelligent Risk Scoring**: Aggregates signals from multiple specialized security agents into a final confidence score.
- **Dynamic Frontend Dashboard**: A cyberpunk-themed, glassmorphic UI ("Command Center") that visualizes the AI agent pipeline, threat intelligence metadata, and server identity in real-time.
- **Asynchronous Analysis**: Powered by Python's `concurrent.futures`, enabling rapid parallel execution of agents.
- **Self-Aware**: The backend dynamically resolves and displays its own hosting server identity natively in the UI.

---

## 🏗️ Architecture & Folder Structure

The application follows a modular architecture separating the web server, core pipeline logic, intelligence agents, and UI.

```text
├── app.py                      # Flask API server & Entry point
├── requirements.txt            # Python dependencies
├── core/
│   ├── pipeline.py             # Orchestrates the concurrent execution of all agents
│   └── user_input_domain.py    # Normalizes and cleans the raw user URL/domain input
├── agents/                     # Specialized Intelligence Agents
│   ├── decision_agent.py             # Weighs outputs from all agents to produce a final verdict
│   ├── domain_intelligence_agent.py  # Checks WHOIS privacy, domain age, and DNS records (MX/NS/A)
│   ├── domain_similarity_agent.py    # Fuzzy string matching against high-value targets (e.g. PayPal, Apple)
│   ├── safe_browsing_agent.py        # Validates against the Google Safe Browsing API
│   └── website_content_agent.py      # Parses live HTML for suspicious keywords and hidden credential forms
└── frontend/
    └── index.html              # The standalone Command Center UI
```

---

## 🚀 How It Works

1. **Input Normalization**: A user inputs a suspicious URL in the UI. The `user_input_domain.py` module cleans it (removing protocols, paths, etc.) to extract the base domain.
2. **Parallel Execution**: `pipeline.py` spins up the four main intelligence agents concurrently:
   - **Similarity Agent**: Checks if the domain is trying to mimic a known brand.
   - **Intelligence Agent**: Looks up DNS records and WHOIS registrations to see if the domain was registered hours ago or uses privacy protectors.
   - **Content Agent**: Scrapes the live webpage looking for password inputs or suspicious keywords.
   - **Safe Browsing Agent**: Cross-references the URL with Google's Safe Browsing database.
3. **Decision & Classification**: The `decision_agent.py` aggregates the risk scores from the pipeline assigning weights. It outputs a classification (`SAFE`, `SUSPICIOUS`, `PHISHING`), a confidence score, and a human-readable explanation.
4. **UI Visualization**: The `/analyze` endpoint of `app.py` returns this payload to the frontend, which animatingly steps through the pipeline stages and displays the threat intelligence metadata.

---

## 💻 Getting Started

### Prerequisites
- Python 3.8+
- Active internet connection (for WHOIS, DNS, and HTTP lookups)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/FASTANDEXTREME/Phish-Defender-AI.git
   cd Phish-Defender-AI
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # macOS/Linux:
   source .venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the App
1. **Start the Backend:**
   ```bash
   python app.py
   ```
   The Flask API will start running on `http://localhost:5000`.

2. **Open the Frontend:**
   Double-click `frontend/index.html` in your file explorer to open it in your web browser. Type a suspicious domain into the search bar and hit **INITIALIZE SCAN** to see the AI in action!

---
*Disclaimer: This tool is intended for educational and defensive cybersecurity purposes.*
