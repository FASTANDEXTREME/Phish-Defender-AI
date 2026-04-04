import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.pipeline import run_pipeline

LINKS = [
    "https://att-sgin100145.weeblysite.com/",
    "https://ipfs.io/ipfs/bafybeia5u6j2nce2pssuyf3os3yrgp5xlazy6fpzsayqsanutkz4npur5q?filename=Ondedriveokp.html",
    "https://bellsouth-att-signing-22025d.webflow.io/",
    "https://dre-us.cnapess-gouv.com",
    "https://fintshisher.blogspot.com/?m=1",
    "https://fintshisher.blogspot.com/",
    "https://americanas-rho.vercel.app/",
    "https://transcorpbank.com/accounts_subdomain/product/online-banking-and-bill-pay/_26_osid_1_hl_en.html",
    "https://buonobuono.jp/zribpuf/amlcnqt/1itzfnu/FFBB/checkpoint.php",
    "https://dodilolaw.z38.web.core.windows.net/",
    "https://dodilolaw.z38.web.core.windows.net/center-output/action-boot.html",
    "https://regis-bbiq-jp.duckdns.org",
    "https://arrangehimalayas.com/wp-forms/2/",
    "https://trans-personal-projects.appwrite.network/",
    "http://tandan-sawit.github.io/in",
    "https://tandan-sawit.github.io/in/",
    "http://mtbrewards.click",
    "https://openai-onlineayx.dafleek.com/ai/app/key.php",
    "https://trzsute.zapier.app/",
    "http://trzsute.zapier.app",
    "https://sign-in-to-xfinity-101463.weeblysite.com/",
    "http://pub-5f42dfaab80a4e1583ad07d911dd504d.r2.dev/ofifceaccesseslogologoinsonnlicrozotft.html",
    "https://pub-5f42dfaab80a4e1583ad07d911dd504d.r2.dev/ofifceaccesseslogologoinsonnlicrozotft.html",
    "https://gravatar.com/profoundlyhumble27442d4ac5",
    "https://talktalknet-104275.weeblysite.com/",
    "https://gravatar.com/cyberearthquake36e2e12106",
    "https://etruio.weeblysite.com/",
    "https://gravatar.com/casually6710dce55d"
]

def main():
    print(f"Testing {len(LINKS)} URLs...")
    results = []

    # Run without APIs to test the AI pipeline purely, sequentially to avoid Playwright thread crashes
    for url in LINKS:
        try:
            res = run_pipeline(url, safebrowsing_enabled=False, phishtank_enabled=False)
            score = res.get("risk_score", 0.0)
            classification = res.get("classification", "UNKNOWN")
            
            print(f"[{classification}] {url} (Score: {score:.3f})")
            print(f"  -> Pipeline ms: {res.get('pipeline_metadata', {}).get('total_ms')}")
            
            results.append({
                "link": url,
                "classification": classification,
                "score": score,
                "explanations": res.get("explanation", [])
            })

        except Exception as exc:
            print(f"[ERROR] {url} generated an exception: {exc}")
            results.append({
                "link": url,
                "classification": "ERROR",
                "score": -1,
                "error": str(exc)
            })

    # Sort results to be predictable
    results.sort(key=lambda x: x["link"])
    
    with open("custom_batch_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)
        
    print(f"\\nDone. Detailed output saved to custom_batch_results.json")

if __name__ == "__main__":
    main()
