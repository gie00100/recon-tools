#!/usr/bin/env python3
"""
Module: Mobile App APK Extractor
Automatically finds the target's Android app on Google Play, downloads the APK
from a mirror, decompiles it, and extracts hardcoded API endpoints and secrets.

Falls back to ZIP-based extraction if apktool is not available.
"""

import argparse
import asyncio
import os
import re
import sys
import subprocess
import zipfile
from pathlib import Path
from typing import List, Dict

import aiohttp
import ssl

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import log_info, log_success, log_warning, log_error, banner, write_lines

# Try importing google-play-scraper for automatic app lookup
try:
    from google_play_scraper import search as gplay_search
    GPLAY_AVAILABLE = True
except ImportError:
    GPLAY_AVAILABLE = False


# Secret patterns to hunt for inside APK files
APK_SECRET_PATTERNS = {
    "Firebase_API_Key": r"AIza[0-9A-Za-z\-_]{35}",
    "AWS_Access_Key": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "Google_OAuth_Client": r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com",
    "Slack_Token": r"xox[bpoa]-[0-9]{10,13}-[a-zA-Z0-9-]+",
    "Stripe_Key": r"(?:sk_live|pk_live|rk_live)_[a-zA-Z0-9]{24,}",
    "Private_Key": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "Generic_Secret": r'(?i)(?:api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
}


class APKExtractor:
    def __init__(self, domain: str, apk_path: str = None):
        self.domain = domain
        self.company_name = domain.split('.')[0]
        
        # If no explicit path, look in targets directory
        if apk_path:
            self.apk_path = Path(apk_path)
        else:
            self.apk_path = Config.PROJECT_ROOT.parent / "targets" / f"{self.company_name}.apk"
            
        self.output_dir = Config.PROJECT_ROOT.parent / "output" / f"{self.company_name}_apk_decompiled"
        self.targets_dir = Config.PROJECT_ROOT.parent / "targets"
        self.targets_dir.mkdir(parents=True, exist_ok=True)
        self.endpoints = set()
        self.secrets = []

    def _check_apktool(self) -> bool:
        try:
            subprocess.run(["apktool", "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    async def _find_package_id(self) -> str:
        """Use google-play-scraper to find the app's package ID."""
        if not GPLAY_AVAILABLE:
            return ""
        
        log_info(f"Searching Google Play for '{self.company_name}' apps...")
        try:
            results = gplay_search(self.company_name, n_hits=10, lang="en", country="us")
            
            # Try to find an exact or close match
            for app in results:
                app_id = app.get("appId", "") or ""
                developer = (app.get("developer") or "").lower()
                title = (app.get("title") or "").lower()
                
                # Match by company name in package ID, developer, or title
                if (self.company_name.lower() in app_id.lower() or
                    self.company_name.lower() in developer or
                    self.company_name.lower() in title):
                    log_success(f"Found app: {app.get('title')} ({app_id}) by {app.get('developer')}")
                    return app_id
            
            # If no exact match, return the first result as a candidate
            if results:
                first = results[0]
                app_id = first.get("appId", "") or ""
                log_info(f"Best candidate: {first.get('title')} ({app_id}) by {first.get('developer')}")
                return app_id
                
        except Exception as e:
            log_warning(f"Google Play search failed: {e}")
        
        return ""

    async def _download_apk(self, package_id: str) -> bool:
        """Try to download APK from APKPure mirror."""
        if not package_id:
            return False
        
        log_info(f"Attempting to download APK for {package_id}...")
        
        # APKPure direct download endpoint
        download_urls = [
            f"https://d.apkpure.com/b/APK/{package_id}?version=latest",
            f"https://d.apkpure.net/b/APK/{package_id}?version=latest",
        ]
        
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Accept": "application/vnd.android.package-archive,application/octet-stream,*/*",
        }
        
        for url in download_urls:
            try:
                timeout = aiohttp.ClientTimeout(total=120)
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_ctx), timeout=timeout) as session:
                    async with session.get(url, headers=headers, allow_redirects=True) as resp:
                        if resp.status == 200:
                            content_type = resp.headers.get("Content-Type", "")
                            if "android" in content_type or "octet-stream" in content_type or "application/zip" in content_type:
                                data = await resp.read()
                                if len(data) > 100_000:  # At least 100KB to be a real APK
                                    self.apk_path = self.targets_dir / f"{self.company_name}.apk"
                                    with open(self.apk_path, "wb") as f:
                                        f.write(data)
                                    log_success(f"Downloaded APK ({len(data) // 1024}KB) → {self.apk_path}")
                                    return True
                            else:
                                log_warning(f"Mirror returned non-APK content type: {content_type}")
            except asyncio.TimeoutError:
                log_warning(f"Download timed out from {url.split('/')[2]}")
            except Exception as e:
                log_warning(f"Download failed from {url.split('/')[2]}: {e}")
        
        return False

    def _extract_via_zip(self) -> bool:
        """Fallback: extract strings from APK as a ZIP without apktool."""
        log_info("Using ZIP-based extraction (apktool not available)...")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                # Extract text-based files that commonly contain endpoints
                interesting_extensions = ('.xml', '.json', '.properties', '.yml', '.yaml', '.txt', '.cfg', '.conf')
                
                for name in zf.namelist():
                    if name.endswith(interesting_extensions):
                        try:
                            data = zf.read(name).decode("utf-8", errors="ignore")
                            self._scan_content(data, name)
                        except Exception:
                            pass
                    
                    # Also scan .dex files for string literals
                    if name.endswith('.dex'):
                        try:
                            data = zf.read(name)
                            # Extract printable ASCII strings from binary
                            strings = re.findall(rb'[\x20-\x7e]{8,}', data)
                            text = "\n".join(s.decode("ascii", errors="ignore") for s in strings)
                            self._scan_content(text, name)
                        except Exception:
                            pass
                            
            return True
        except zipfile.BadZipFile:
            log_error(f"File is not a valid APK/ZIP: {self.apk_path}")
            return False

    def _scan_content(self, content: str, source_file: str):
        """Extract URLs and secrets from text content."""
        # URL extraction
        url_pattern = re.compile(r'https?://[a-zA-Z0-9._\-]+\.[a-zA-Z]{2,}(?:/[a-zA-Z0-9_.~:/?#\[\]@!$&\'()*+,;=\-]*)?')
        urls = url_pattern.findall(content)
        for u in urls:
            # Keep URLs related to target domain or generic API patterns
            if (self.company_name.lower() in u.lower() or
                "api" in u.lower() or
                "internal" in u.lower() or
                "staging" in u.lower() or
                "dev." in u.lower()):
                self.endpoints.add(u)
        
        # Secret extraction
        for secret_type, pattern in APK_SECRET_PATTERNS.items():
            for match in re.finditer(pattern, content):
                value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                # Avoid duplicates
                if not any(s["value"] == value for s in self.secrets):
                    self.secrets.append({
                        "type": secret_type,
                        "value": value,
                        "file": source_file,
                    })

    async def extract(self) -> Dict:
        banner("Mobile APK API Extractor")
        
        # Step 1: If no APK on disk, try to find and download it
        if not self.apk_path.exists():
            log_warning(f"No APK found at {self.apk_path}")
            
            # Try automatic lookup + download
            package_id = await self._find_package_id()
            
            if package_id:
                downloaded = await self._download_apk(package_id)
                if not downloaded:
                    # Download failed — print manual instructions
                    log_warning("Automatic download failed (CDN blocked or captcha).")
                    log_info(f"Please manually download the APK:")
                    log_info(f"  - https://apkpure.com/search?q={self.company_name}")
                    log_info(f"  - https://apps.evozi.com/apk-downloader/?id={package_id}")
                    log_info(f"  Place it at: {self.targets_dir / f'{self.company_name}.apk'}")
                    return {"endpoints": list(), "secrets": list()}
            else:
                log_warning("Could not find the app on Google Play.")
                log_info(f"Place the APK manually at: {self.targets_dir / f'{self.company_name}.apk'}")
                return {"endpoints": list(), "secrets": list()}

        # Step 2: Decompile or extract
        log_info(f"Processing {self.apk_path.name} ({self.apk_path.stat().st_size // 1024}KB)...")
        
        if self._check_apktool():
            # Full decompilation with apktool
            log_info("Decompiling with apktool...")
            cmd = ["apktool", "d", "-f", "-o", str(self.output_dir), str(self.apk_path)]
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                if process.returncode != 0:
                    log_error(f"apktool failed: {stderr.decode(errors='ignore')[:200]}")
                    log_info("Falling back to ZIP extraction...")
                    self._extract_via_zip()
                else:
                    log_success("Decompilation complete. Scanning files...")
                    # Walk the decompiled directory
                    for root, dirs, files in os.walk(self.output_dir):
                        for file in files:
                            if file.endswith((".xml", ".smali", ".json", ".properties", ".yml")):
                                filepath = Path(root) / file
                                try:
                                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                                        content = f.read()
                                        self._scan_content(content, file)
                                except Exception:
                                    pass
            except Exception as e:
                log_error(f"Error running apktool: {e}")
                self._extract_via_zip()
        else:
            # Fallback to ZIP extraction (works everywhere)
            self._extract_via_zip()

        log_success(f"Extracted {len(self.endpoints)} API endpoints and {len(self.secrets)} hardcoded secrets from APK.")
        
        return {
            "endpoints": sorted(self.endpoints),
            "secrets": self.secrets
        }

def main():
    parser = argparse.ArgumentParser(description="Mobile APK Extractor")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-f", "--file", help="Path to APK file")
    args = parser.parse_args()
    
    extractor = APKExtractor(args.domain, args.file)
    results = asyncio.run(extractor.extract())
    
    if results["endpoints"]:
        print("\n[+] Mobile Endpoints Found:")
        for ep in sorted(results["endpoints"])[:20]:
            print(f"  {ep}")
    if results["secrets"]:
        print(f"\n[+] {len(results['secrets'])} Secrets Found!")

if __name__ == "__main__":
    main()
