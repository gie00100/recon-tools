#!/usr/bin/env python3
"""
Module: SaaS Hunter
Fuzzes third-party SaaS platforms to find misconfigured or leaked instances
associated with the target company.
"""

import argparse
import asyncio
import sys
import ssl
from pathlib import Path
from typing import List, Dict

import aiohttp
import tldextract

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import log_info, log_success, log_warning, log_finding, banner, write_lines, RateLimiter

SAAS_PLATFORMS = {
    "jira": "{name}.atlassian.net",
    "confluence": "{name}.atlassian.net/wiki",
    "slack": "{name}.slack.com",
    "zendesk": "{name}.zendesk.com",
    "s3": "{name}.s3.amazonaws.com",
    "okta": "{name}.okta.com",
    "zoom": "{name}.zoom.us",
    "salesforce": "{name}.my.salesforce.com",
    "sharepoint": "{name}.sharepoint.com",
    "servicenow": "{name}.service-now.com",
    "freshdesk": "{name}.freshdesk.com",
}

class SaasHunter:
    def __init__(self, domain: str):
        self.domain = domain
        ext = tldextract.extract(self.domain)
        self.company_name = ext.domain
        self.findings = []
        self.rate_limiter = RateLimiter(50)
        self._session = None

    async def _get_session(self):
        if self._session is None or self._session.closed:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_ctx)
            self._session = aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=10))
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def _check_endpoint(self, service: str, url: str) -> Dict:
        await self.rate_limiter.acquire()
        session = await self._get_session()
        try:
            async with session.get(url, allow_redirects=True) as resp:
                if resp.status < 400:
                    text = await resp.text()
                    title_match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE)
                    title = title_match.group(1).strip() if title_match else ""
                    
                    # Heuristics for "Not Found" vs "Active" on shared platforms
                    if "Not Found" in title or "doesn't exist" in text.lower() or "no such" in text.lower():
                        return None
                        
                    return {
                        "service": service,
                        "url": url,
                        "status": resp.status,
                        "title": title
                    }
        except Exception:
            pass
        return None

    async def hunt(self) -> List[Dict]:
        import time
        import re
        start = time.time()
        banner("SaaS Misconfiguration Hunter")
        log_info(f"Targeting: {self.company_name} ({self.domain})")

        # Create permutations of the company name
        names = set([
            self.company_name,
            self.company_name.replace("-", ""),
            f"{self.company_name}hq",
            f"{self.company_name}app",
            f"{self.company_name}-internal",
            f"{self.company_name}corp",
        ])

        urls_to_check = []
        for name in names:
            for service, template in SAAS_PLATFORMS.items():
                host = template.format(name=name)
                urls_to_check.append((service, f"https://{host}"))

        log_info(f"Checking {len(urls_to_check)} SaaS permutations...")

        tasks = [self._check_endpoint(service, url) for service, url in urls_to_check]
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res:
                self.findings.append(res)
                log_finding(f"[SaaS] Found {res['service']}: {res['url']} (Status: {res['status']}) - {res['title']}")

        await self.close()
        log_success(f"SaaS Hunt completed. Found {len(self.findings)} external services.")
        return self.findings

def main():
    parser = argparse.ArgumentParser(description="SaaS Hunter")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    args = parser.parse_args()
    
    hunter = SaasHunter(args.domain)
    asyncio.run(hunter.hunt())

if __name__ == "__main__":
    main()
