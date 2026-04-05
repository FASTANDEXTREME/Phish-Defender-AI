import json
from core.pipeline import PhishingDetectionPipeline

def run_test():
    pipeline = PhishingDetectionPipeline()
    url = "https://buonobuono.jp/zribpuf/amlcnqt/1itzfnu/FFBB/checkpoint.php"
    
    print(f"Running pipeline on: {url}")
    result = pipeline.run(url)
    
    print("\n" + "="*50)
    print(f"FINAL CLASSIFICATION: {result['classification']}")
    print(f"CONFIDENCE: {result.get('confidence', 'N/A')}")
    print(f"RISK SCORE: {result.get('final_risk_score', 'N/A')}")
    print("="*50 + "\n")
    
    print("EXPLANATION ITEMS:")
    explanations = result.get('explanation_details', [])
    for idx, item in enumerate(explanations, 1):
        print(f"[{idx}] (Impact: {item['impact'].upper()}) - {item['signal']}")
    
    print("\nRAW AGENT OUTPUTS:")
    # Pretty print the final dictionary for deeper insights without cluttering the screen
    important_metrics = {
        "Similarity": result.get("similarity_risk", 0),
        "Intelligence": result.get("intelligence_risk", 0),
        "Content": result.get("content_risk", 0),
        "Cross_Reference": result.get("cross_reference_risk", 0),
    }
    print(json.dumps(important_metrics, indent=4))

if __name__ == "__main__":
    run_test()
