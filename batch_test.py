import os
import json
import sys
import requests
import gzip
from collections import Counter
import time

# ==============================================================================
# TEE LOGGER: Write exactly what's printed to both console and a log file
# ==============================================================================
class TeeLogger:
    def __init__(self, filename):
        self.terminal = sys.stdout
        self.log = open(filename, "w", encoding="utf-8")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)
        self.flush()

    def flush(self):
        self.terminal.flush()
        self.log.flush()

sys.stdout = TeeLogger("batch_test_results.log")
sys.stderr = sys.stdout

from core.pipeline import run_pipeline
import core.pipeline



# ==============================================================================
# FAST PRE-CHECK helper
# ==============================================================================
def is_live(url: str) -> bool:
    try:
        r = requests.get(url, timeout=2.5, allow_redirects=True)
        return r.status_code < 400
    except Exception:
        return False

# ==============================================================================
# BATCH TEST LOGIC
# ==============================================================================
def run_batch_test(file_path: str, max_live_links: int = 100):
    if not os.path.exists(file_path):
        print(f"Error: Could not find '{file_path}'.")
        return

    print("Loading links from file...")
    all_links = []
    
    open_func = gzip.open if file_path.endswith('.gz') else open
    
    with open_func(file_path, 'rt', encoding='utf-8', errors='replace') as f:
        if file_path.endswith('.json') or file_path.endswith('.json.gz'):
            try:
                data = json.load(f)
                for item in data:
                    if isinstance(item, dict) and 'url' in item:
                        all_links.append(item['url'])
            except Exception as e:
                print(f"Error reading JSON: {e}")
        else:
            all_links = [line.strip() for line in f if line.strip()]

    if not all_links:
        print("The file is empty.")
        return

    print(f"Loaded {len(all_links)} total links.")
    print(f"Bypassing SafeBrowsing & PhishTank & sweeping file for {max_live_links} LIVE links...")
    print("="*80)
    
    classification_counts = Counter()
    severity_counts = Counter()
    sb_detected_count = 0 
    
    results = []
    live_tested = 0

    for i, link in enumerate(all_links, 1):
        if live_tested >= max_live_links:
            break
            
        print(f"\n[Scanning #{i}] {link}")
        print("  -> Pre-checking connection...", end="", flush=True)
        
        if not is_live(link):
            print(" DEAD. Skipping.")
            continue
            
        print(" LIVE! Running AI Pipeline...")
        
        try:
            output = run_pipeline(link, safebrowsing_enabled=False, phishtank_enabled=False)
            
            # Double check that the website content agent actually reached the page
            page_reachable = output.get("raw_content", {}).get("page_reachable", False)
            if not page_reachable:
                print("  -> Actually DEAD (Content Agent could not load it properly). Skipping.")
                continue
                
            live_tested += 1
            
            classification = output.get("classification", "UNKNOWN")
            severity = output.get("severity", "UNKNOWN")
            score = output.get("final_risk_score", 0.0)
            explanations = output.get("explanation", [])
            
            classification_counts[classification] += 1
            severity_counts[severity] += 1
            
            sb_safe = output.get("raw_safe_browsing", {}).get("is_safe", True)
            if not sb_safe:
                sb_detected_count += 1
            
            print(f"  ====== [SUCCESS # {live_tested}/{max_live_links} LIVE DOMAIN] ======")
            print(f"  Classification : {classification}")
            print(f"  Risk Level     : {severity} (Score: {score})")
            print("  Reasons/Explanations:")
            for exp in explanations:
                exp_clean = str(exp).replace('\u2192', '->')
                print(f"    - {exp_clean}")
                
            results.append({
                "link": link,
                "classification": classification,
                "severity": severity,
                "score": score,
                "sb_safe": sb_safe,
                "explanations": explanations
            })
            
        except Exception as e:
            print(f"  Error analyzing {link}: {e}")

    print("\n" + "="*60)
    print("BATCH TEST SUMMARY (LIVE LINKS ONLY - EXTERNAL APIs OFF)")
    print("="*60)
    print(f"Total LIVE links successfully tested: {live_tested}")
    
    print("\n--- By Classification ---")
    print(f"SAFE:       {classification_counts.get('SAFE', 0)}")
    print(f"SUSPICIOUS: {classification_counts.get('SUSPICIOUS', 0)}")
    print(f"PHISHING:   {classification_counts.get('PHISHING', 0)}")
    
    print("\n--- By Risk Level (Severity) ---")
    print(f"INFO:       {severity_counts.get('INFO', 0)}")
    print(f"LOW:        {severity_counts.get('LOW', 0)}")
    print(f"MEDIUM:     {severity_counts.get('MEDIUM', 0)}")
    print(f"HIGH:       {severity_counts.get('HIGH', 0)}")
    print(f"CRITICAL:   {severity_counts.get('CRITICAL', 0)}")
    
    print("\n--- Links classified as PHISHING (Detected by AI Agents) ---")
    phishing_links_agent = [r["link"] for r in results if r["classification"] == "PHISHING"]
    if phishing_links_agent:
        for pl in phishing_links_agent:
            print(f" - {pl}")
    else:
        print(" None")

    print("\n--- Links classified as SUSPICIOUS (Evaded model partially) ---")
    suspicious_links = [r["link"] for r in results if r["classification"] == "SUSPICIOUS"]
    if suspicious_links:
        for sl in suspicious_links:
            print(f" - {sl}")
    else:
        print(" None")

    print("\n--- Links classified as SAFE (Evaded model completely) ---")
    safe_links = [r["link"] for r in results if r["classification"] == "SAFE"]
    if safe_links:
        for sl in safe_links:
            print(f" - {sl}")
    else:
        print(" None")
        
    print("\nSaving complete detailed results...")
    detailed_file = "batch_test_detailed_results.json"
    with open(detailed_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)
    print(f"Saved {len(results)} analyzed links detailed records to {detailed_file}")

if __name__ == '__main__':
    input_file = sys.argv[1] if len(sys.argv) > 1 else os.path.join('data', 'phishtank.json.gz')
    # Default to 100 live links to ensure test finishes in reasonable timeframe
    max_live = 100
    if len(sys.argv) > 2:
        try:
            max_live = int(sys.argv[2])
        except ValueError:
            pass
    run_batch_test(input_file, max_live)
