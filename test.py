import aiohttp
import asyncio
import gzip
import json
import time
from urllib.parse import urlparse

PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.json.gz"
UPDATE_INTERVAL = 3600  # 1 hour

class PhishTankLookup:
    def __init__(self):
        self.phish_set = set()
        self.last_updated = 0
        self._lock = asyncio.Lock()

    async def _download_data(self):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(PHISHTANK_URL) as resp:
                compressed = await resp.read()

        data = gzip.decompress(compressed)
        return json.loads(data)

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")

    async def _refresh_if_needed(self):
        now = time.time()

        # 🚫 Skip if still fresh
        if now - self.last_updated < UPDATE_INTERVAL:
            return

        async with self._lock:
            # Double-check inside lock (avoid duplicate refresh)
            if now - self.last_updated < UPDATE_INTERVAL:
                return

            print("🔄 Updating PhishTank data...")

            try:
                entries = await self._download_data()

                # ⚡ Build set once
                self.phish_set = {
                    self._normalize_url(entry["url"])
                    for entry in entries
                }

                self.last_updated = time.time()

                print(f"✅ Loaded {len(self.phish_set)} phishing URLs")

            except Exception as e:
                print(f"❌ Failed to update PhishTank: {e}")

    async def is_phishing(self, url: str) -> bool:
        await self._refresh_if_needed()
        return self._normalize_url(url) in self.phish_set

async def main():
    checker = PhishTankLookup()

    url = "https://ecojoulesltd.com/"

    result = await checker.is_phishing(url)

    if result:
        print("🚨 Phishing detected!")
    else:
        print("✅ Safe")

asyncio.run(main())