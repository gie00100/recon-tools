#!/usr/bin/env python3
"""
Module: Semantic API Fuzzer (The "Acquisition & Context" Module)
Generates highly targeted, context-aware API wordlists by extracting
meaningful keywords from public text (Wikipedia, About Pages) related
to the target company.
"""

import argparse
import asyncio
import re
import sys
import ssl
from pathlib import Path
from typing import List, Set

import aiohttp
from bs4 import BeautifulSoup
import tldextract

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import log_info, log_success, log_warning, banner, elapsed_str, write_lines

class SemanticFuzzer:
    def __init__(self, domain: str, extra_urls: List[str] = None):
        self.domain = domain.lower()
        self.extra_urls = extra_urls or []
        self.keywords: Set[str] = set()
        self.api_wordlist: Set[str] = set()

        ext = tldextract.extract(self.domain)
        self.company_name = ext.domain

    async def _fetch_text(self, url: str) -> str:
        """Fetch and extract visible text from a URL."""
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_ctx)) as session:
                async with session.get(url, timeout=10, headers={"User-Agent": Config.USER_AGENT}) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        soup = BeautifulSoup(html, "html.parser")
                        # Remove scripts and styles
                        for script in soup(["script", "style", "noscript", "header", "footer", "nav"]):
                            script.decompose()
                        return soup.get_text(separator=" ", strip=True)
        except Exception as e:
            log_warning(f"Failed to fetch {url}: {e}")
        return ""

    def _extract_keywords(self, text: str) -> Set[str]:
        """Extract potential API context words from text."""
        words = set()
        
        # Look for CamelCase or Title Case words (potential product names, acquisitions)
        title_case_words = re.findall(r'\b[A-Z][a-z0-9]+\b', text)
        for w in title_case_words:
            if len(w) > 3 and len(w) < 20:
                words.add(w.lower())
                
        # Look for specific keywords around acquisition/products
        contexts = ["acquired", "merger", "product", "launch", "project", "subsidiary", "platform", "app"]
        text_lower = text.lower()
        tokens = re.split(r'\W+', text_lower)
        
        for i, token in enumerate(tokens):
            if token in contexts:
                # Grab surrounding words
                start = max(0, i - 3)
                end = min(len(tokens), i + 4)
                for w in tokens[start:end]:
                    if len(w) > 3 and not w.isnumeric():
                        words.add(w)

        # Basic filtering of common stop words
        stop_words = {"this", "that", "with", "from", "your", "have", "they", "will", "would", "about", "their"}
        return {w for w in words if w not in stop_words}

    async def generate(self) -> List[str]:
        start = time.time() if 'time' in sys.modules else 0
        banner("Semantic API Fuzzer")
        log_info(f"Targeting: {self.company_name} ({self.domain})")

        # Wikipedia URL heuristic
        wiki_url = f"https://en.wikipedia.org/wiki/{self.company_name.capitalize()}"
        urls_to_scrape = [wiki_url, f"https://www.{self.domain}/about", f"https://www.{self.domain}/press"]
        urls_to_scrape.extend(self.extra_urls)

        log_info(f"Scraping context from {len(urls_to_scrape)} sources...")
        tasks = [self._fetch_text(url) for url in urls_to_scrape]
        results = await asyncio.gather(*tasks)

        full_text = " ".join(results)
        if not full_text.strip():
            log_warning("No context text gathered. Fuzzer will only use generic fallbacks.")
            
        self.keywords = self._extract_keywords(full_text)
        
        # Always include the company name itself
        self.keywords.add(self.company_name)
        
        log_success(f"Extracted {len(self.keywords)} contextual keywords.")

        # Build permutations for API paths
        prefixes = ["api", "v1", "v2", "v3", "internal", "corp", "dev", "beta", "legacy", "mobile"]
        suffixes = ["api", "service", "svc", "admin", "gateway"]

        for kw in self.keywords:
            self.api_wordlist.add(kw)
            for p in prefixes:
                self.api_wordlist.add(f"{p}/{kw}")
                self.api_wordlist.add(f"{kw}/{p}")
                self.api_wordlist.add(f"{p}-{kw}")
                self.api_wordlist.add(f"{kw}-{p}")
            for s in suffixes:
                self.api_wordlist.add(f"{kw}-{s}")
                self.api_wordlist.add(f"{kw}{s}")
                
        # Format as absolute paths
        final_list = [f"/{w}" for w in self.api_wordlist]
        final_list.extend([f"/{w}/" for w in self.api_wordlist])
        
        # Sort and deduplicate
        final_list = sorted(list(set(final_list)))
        log_success(f"Generated semantic wordlist with {len(final_list)} entries.")
        return final_list

def main():
    import time
    parser = argparse.ArgumentParser(description="Semantic API Fuzzer Wordlist Generator")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-u", "--url", action="append", help="Extra URLs to scrape for context")
    parser.add_argument("-o", "--output", help="Output file")
    
    args = parser.parse_args()
    
    fuzzer = SemanticFuzzer(args.domain, args.url)
    results = asyncio.run(fuzzer.generate())
    
    if args.output:
        write_lines(args.output, results, deduplicate=True)
    else:
        for r in results[:20]:
            print(r)
        print(f"... and {len(results) - 20} more.")

if __name__ == "__main__":
    main()
