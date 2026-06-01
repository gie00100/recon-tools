#!/usr/bin/env python3
"""
Module: Mobile App APK Extractor
Automatically finds the target's Android app on Google Play, downloads the APK
from multiple third-party mirrors, decompiles it, and extracts hardcoded API
endpoints and secrets.

Download sources (tried in order):
1. APKPure CDN direct link
2. APKCombo AJAX API
3. Aptoide search API
4. Evozi APK Downloader API

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
    "JWT_Token": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_\-]+",
    "SendGrid_Key": r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
    "Twilio_SID": r"AC[a-f0-9]{32}",
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
        self._ssl_ctx = None

    def _get_ssl_ctx(self):
        if self._ssl_ctx is None:
            self._ssl_ctx = ssl.create_default_context()
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE
        return self._ssl_ctx

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
            
            for app in results:
                app_id = app.get("appId", "") or ""
                if not app_id:
                    continue  # Skip results with no package ID
                developer = (app.get("developer") or "").lower()
                title = (app.get("title") or "").lower()
                
                if (self.company_name.lower() in app_id.lower() or
                    self.company_name.lower() in developer or
                    self.company_name.lower() in title):
                    log_success(f"Found app: {app.get('title')} ({app_id}) by {app.get('developer')}")
                    return app_id
            
            # If no exact match, return the first result with a valid appId
            for app in results:
                app_id = app.get("appId", "") or ""
                if app_id:
                    log_info(f"Best candidate: {app.get('title')} ({app_id}) by {app.get('developer')}")
                    return app_id
                
        except Exception as e:
            log_warning(f"Google Play search failed: {e}")
        
        return ""

    async def _save_apk(self, data: bytes, source: str) -> bool:
        """Validate and save downloaded APK data."""
        if len(data) < 100_000:  # At least 100KB
            log_warning(f"{source}: File too small ({len(data)} bytes), skipping.")
            return False
        
        # Check for ZIP/APK magic bytes
        if data[:2] != b'PK':
            log_warning(f"{source}: Not a valid APK/ZIP file.")
            return False
        
        self.apk_path = self.targets_dir / f"{self.company_name}.apk"
        with open(self.apk_path, "wb") as f:
            f.write(data)
        log_success(f"Downloaded APK ({len(data) // 1024}KB) from {source} → {self.apk_path}")
        return True

    async def _try_apkpure(self, package_id: str) -> bool:
        """Source 1: APKPure CDN direct download."""
        log_info(f"[3/4] Trying APKPure CDN (may be slow)...")
        
        download_urls = [
            f"https://d.apkpure.com/b/APK/{package_id}?version=latest",
            f"https://d.apkpure.net/b/APK/{package_id}?version=latest",
        ]
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Accept": "application/vnd.android.package-archive,application/octet-stream,*/*",
        }
        
        for url in download_urls:
            try:
                timeout = aiohttp.ClientTimeout(total=120)
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=self._get_ssl_ctx()),
                    timeout=timeout
                ) as session:
                    async with session.get(url, headers=headers, allow_redirects=True) as resp:
                        if resp.status == 200:
                            ct = resp.headers.get("Content-Type", "")
                            if "android" in ct or "octet-stream" in ct or "zip" in ct:
                                data = await resp.read()
                                if await self._save_apk(data, "APKPure"):
                                    return True
            except Exception as e:
                log_warning(f"APKPure failed: {e}")
        
        return False

    async def _try_apkcombo(self, package_id: str) -> bool:
        """Source 2: APKCombo AJAX download API."""
        log_info(f"[4/4] Trying APKCombo...")
        
        try:
            timeout = aiohttp.ClientTimeout(total=60)
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Referer": f"https://apkcombo.com/search/{self.company_name}/",
                "Accept": "text/html,application/xhtml+xml,*/*",
            }
            
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=self._get_ssl_ctx()),
                timeout=timeout
            ) as session:
                # Step 1: Get the app page to find download token
                app_url = f"https://apkcombo.com/search/{package_id}/"
                async with session.get(app_url, headers=headers, allow_redirects=True) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        # Look for the direct download link pattern
                        dl_match = re.search(r'href="(https://download\.apkcombo\.com/[^"]+\.apk[^"]*)"', text)
                        if dl_match:
                            dl_url = dl_match.group(1)
                            async with session.get(dl_url, headers=headers, allow_redirects=True) as dl_resp:
                                if dl_resp.status == 200:
                                    data = await dl_resp.read()
                                    if await self._save_apk(data, "APKCombo"):
                                        return True
        except Exception as e:
            log_warning(f"APKCombo failed: {e}")
        
        return False

    async def _try_aptoide(self, package_id: str) -> bool:
        """Source 3: Aptoide search + download API."""
        log_info(f"[1/4] Trying Aptoide API...")
        
        try:
            timeout = aiohttp.ClientTimeout(total=60)
            headers = {"User-Agent": Config.USER_AGENT}
            
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=self._get_ssl_ctx()),
                timeout=timeout
            ) as session:
                # Try searching by package ID first, then by company name
                queries = [package_id, self.company_name]
                for query in queries:
                    search_url = f"https://ws75.aptoide.com/api/7/apps/search?query={query}&limit=10"
                    async with session.get(search_url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json(content_type=None)
                            apps = data.get("datalist", {}).get("list", [])
                            
                            # Priority 1: Exact package ID match
                            for app in apps:
                                app_pkg = app.get("package_name", "") or ""
                                apk_url = app.get("file", {}).get("path", "")
                                if apk_url and app_pkg == package_id:
                                    app_name = app.get("name", "")
                                    log_info(f"Found on Aptoide (exact match): {app_name} ({app_pkg})")
                                    async with session.get(apk_url, headers=headers, allow_redirects=True) as dl_resp:
                                        if dl_resp.status == 200:
                                            apk_data = await dl_resp.read()
                                            if await self._save_apk(apk_data, "Aptoide"):
                                                return True
                            
                            # Priority 2: Package name contains company (e.g. com.wix.*)
                            for app in apps:
                                app_pkg = app.get("package_name", "") or ""
                                apk_url = app.get("file", {}).get("path", "")
                                # Must match on package name (com.wix.*), NOT just display name
                                if apk_url and self.company_name.lower() in app_pkg.lower():
                                    app_name = app.get("name", "")
                                    log_info(f"Found on Aptoide: {app_name} ({app_pkg})")
                                    async with session.get(apk_url, headers=headers, allow_redirects=True) as dl_resp:
                                        if dl_resp.status == 200:
                                            apk_data = await dl_resp.read()
                                            if await self._save_apk(apk_data, "Aptoide"):
                                                return True
        except Exception as e:
            log_warning(f"Aptoide failed: {e}")
        
        return False

    async def _try_apkmirror(self, package_id: str) -> bool:
        """Source 2: APKMirror via curl (bypasses Cloudflare 403 that blocks aiohttp)."""
        log_info(f"[2/4] Trying APKMirror...")
        
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
        
        def curl_get(url, referer=None):
            """Fetch a URL via curl subprocess (bypasses anti-bot)."""
            cmd = ["curl.exe", "-sS", "-L", "-m", "30", url, "-H", f"User-Agent: {ua}"]
            if referer:
                cmd += ["-H", f"Referer: {referer}"]
            result = subprocess.run(cmd, capture_output=True)
            return result.stdout.decode("utf-8", errors="ignore")
        
        try:
            # Step 1: Search by company name
            search_url = f"https://www.apkmirror.com/?post_type=app_release&searchtype=apk&s={self.company_name}"
            html = await asyncio.get_event_loop().run_in_executor(None, curl_get, search_url)
            
            release_matches = re.findall(
                r'class="fontBlack"\s+href="(/apk/[^"]*-release/)"',
                html
            )
            
            if not release_matches:
                log_warning("APKMirror: No releases found.")
                return False
            
            # Filter to releases with company name in URL
            company_releases = [r for r in release_matches if f"/apk/{self.company_name.lower()}/" in r.lower()]
            if not company_releases:
                company_releases = release_matches
            
            release_path = company_releases[0]
            release_url = f"https://www.apkmirror.com{release_path}"
            log_info(f"APKMirror: Found release page, looking for APK variant...")
            
            # Step 2: Get release page → find variant link
            rel_html = await asyncio.get_event_loop().run_in_executor(None, curl_get, release_url, search_url)
            
            apk_link = re.search(r'href="(/apk/[^"]*android-apk-download/)"', rel_html)
            if not apk_link:
                log_warning("APKMirror: Could not find APK variant link.")
                return False
            
            dl_page_url = f"https://www.apkmirror.com{apk_link.group(1)}"
            log_info(f"APKMirror: Found APK variant, getting download link...")
            
            # Step 3: Get variant page → find interstitial download link
            dl_html = await asyncio.get_event_loop().run_in_executor(None, curl_get, dl_page_url, release_url)
            
            # The variant page has a "download/?key=" link to an interstitial page
            interstitial_link = re.search(r'href="(/apk/[^"]*download/\?key=[^"]+)"', dl_html)
            if not interstitial_link:
                # Sometimes the download.php link is directly on this page
                direct_link = re.search(r'href="(/wp-content/themes/APKMirror/download\.php\?id=[^"]+)"', dl_html)
                if direct_link:
                    interstitial_link = direct_link
            
            if not interstitial_link:
                log_warning("APKMirror: Could not find download link on variant page.")
                return False
            
            interstitial_url = f"https://www.apkmirror.com{interstitial_link.group(1)}"
            
            # Check if this is already the final download.php link
            if "download.php" in interstitial_url:
                final_url = interstitial_url
            else:
                # Step 4: Navigate interstitial page → find actual download.php link
                log_info(f"APKMirror: Navigating download page...")
                inter_html = await asyncio.get_event_loop().run_in_executor(
                    None, curl_get, interstitial_url, dl_page_url
                )
                
                php_link = re.search(
                    r'href="(/wp-content/themes/APKMirror/download\.php\?id=[^"]+)"',
                    inter_html
                )
                if not php_link:
                    log_warning("APKMirror: Could not find final download.php link.")
                    return False
                
                final_url = f"https://www.apkmirror.com{php_link.group(1)}"
            
            log_info(f"APKMirror: Downloading APK (this may take a minute)...")
            
            # Step 5: Download the actual APK file via curl
            apk_path = self.targets_dir / f"{self.company_name}.apk"
            dl_cmd = [
                "curl.exe", "-sS", "-L", "-m", "300",
                final_url,
                "-H", f"User-Agent: {ua}",
                "-H", f"Referer: {interstitial_url}",
                "-o", str(apk_path)
            ]
            dl_result = await asyncio.create_subprocess_exec(
                *dl_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await dl_result.communicate()
            
            if dl_result.returncode == 0 and apk_path.exists():
                data = apk_path.read_bytes()
                if await self._save_apk(data, "APKMirror"):
                    return True
                else:
                    apk_path.unlink(missing_ok=True)  # Clean up invalid file
            else:
                log_warning(f"APKMirror: curl download failed (exit code {dl_result.returncode})")
                
        except Exception as e:
            log_warning(f"APKMirror failed: {e}")
        
        return False

    async def _download_apk(self, package_id: str) -> bool:
        """Try all download sources in order."""
        if not package_id:
            return False
        
        log_info(f"Attempting to download APK for: {package_id}")
        
        # Try each source in order of reliability
        sources = [
            self._try_aptoide,
            self._try_apkmirror,
            self._try_apkpure,
            self._try_apkcombo,
        ]
        
        for source_fn in sources:
            if await source_fn(package_id):
                return True
            await asyncio.sleep(1)  # Brief pause between sources
        
        return False

    def _extract_via_zip(self) -> bool:
        """Fallback: extract strings from APK as a ZIP without apktool."""
        log_info("Using ZIP-based extraction (apktool not available)...")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                interesting_extensions = ('.xml', '.json', '.properties', '.yml', '.yaml', '.txt', '.cfg', '.conf')
                
                for name in zf.namelist():
                    if name.endswith(interesting_extensions):
                        try:
                            data = zf.read(name).decode("utf-8", errors="ignore")
                            self._scan_content(data, name)
                        except Exception:
                            pass
                    
                    # Scan .dex files for string literals
                    if name.endswith('.dex'):
                        try:
                            data = zf.read(name)
                            strings = re.findall(rb'[\x20-\x7e]{8,}', data)
                            text = "\n".join(s.decode("ascii", errors="ignore") for s in strings)
                            self._scan_content(text, name)
                        except Exception:
                            pass
                    
                    # Also scan .so (native library) files for strings
                    if name.endswith('.so'):
                        try:
                            data = zf.read(name)
                            strings = re.findall(rb'https?://[a-zA-Z0-9._\-/]{10,}', data)
                            text = "\n".join(s.decode("ascii", errors="ignore") for s in strings)
                            if text:
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
                    log_warning("All automatic download sources failed.")
                    log_info(f"Manual download options:")
                    log_info(f"  1. https://apkcombo.com/search/{self.company_name}/")
                    log_info(f"  2. https://apkpure.com/search?q={self.company_name}")
                    log_info(f"  3. https://apps.evozi.com/apk-downloader/?id={package_id}")
                    log_info(f"  4. https://apk.support/download-app/{package_id}")
                    log_info(f"  Place the APK at: {self.targets_dir / f'{self.company_name}.apk'}")
                    return {"endpoints": list(), "secrets": list()}
            else:
                log_warning("Could not find the app on Google Play.")
                log_info(f"Place the APK manually at: {self.targets_dir / f'{self.company_name}.apk'}")
                return {"endpoints": list(), "secrets": list()}

        # Step 2: Decompile or extract
        log_info(f"Processing {self.apk_path.name} ({self.apk_path.stat().st_size // 1024}KB)...")
        
        if self._check_apktool():
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
