#!/usr/bin/env python3
"""
Module: Mobile App APK Extractor
Decompiles Android APKs (if present in the targets directory) and extracts
hardcoded API endpoints, secrets, and staging domains that lack WAF protection.
"""

import argparse
import asyncio
import os
import re
import sys
import subprocess
from pathlib import Path
from typing import List, Dict

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import log_info, log_success, log_warning, log_error, banner, write_lines

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
        self.endpoints = set()
        self.secrets = []

    def _check_dependencies(self) -> bool:
        try:
            subprocess.run(["apktool", "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    async def extract(self) -> Dict:
        banner("Mobile APK API Extractor")
        
        if not self.apk_path.exists():
            log_warning(f"No APK found at {self.apk_path}")
            log_info("To use Mobile API extraction, download the target's APK from APKPure/PlayStore and place it in the targets/ directory.")
            return {"endpoints": list(), "secrets": list()}
            
        if not self._check_dependencies():
            log_error("apktool is not installed or not in PATH. Please install apktool.")
            return {"endpoints": list(), "secrets": list()}

        log_info(f"Decompiling {self.apk_path.name} using apktool...")
        
        # Run apktool
        cmd = ["apktool", "d", "-f", "-o", str(self.output_dir), str(self.apk_path)]
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if process.returncode != 0:
                log_error(f"apktool failed: {stderr.decode(errors='ignore')}")
                return {"endpoints": list(), "secrets": list()}
        except Exception as e:
            log_error(f"Error running apktool: {e}")
            return {"endpoints": list(), "secrets": list()}

        log_success("Decompilation complete. Extracting strings...")
        
        # Extract Endpoints
        url_pattern = re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[a-zA-Z0-9_.-]+)*')
        
        # Walk the decompiled directory
        for root, dirs, files in os.walk(self.output_dir):
            for file in files:
                if file.endswith((".xml", ".smali")):
                    filepath = Path(root) / file
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            
                            # Find URLs
                            urls = url_pattern.findall(content)
                            for u in urls:
                                # Only keep URLs related to the target or generic APIs
                                if self.company_name in u or "api" in u:
                                    self.endpoints.add(u)
                                    
                            # Very basic secret regex (Firebase, AWS, etc)
                            if "AIza" in content:
                                match = re.search(r'AIza[0-9A-Za-z-_]{35}', content)
                                if match:
                                    self.secrets.append({"type": "Firebase_API_Key", "value": match.group(0), "file": file})
                                    
                    except Exception:
                        pass
                        
        log_success(f"Extracted {len(self.endpoints)} API endpoints and {len(self.secrets)} hardcoded secrets from APK.")
        
        return {
            "endpoints": list(self.endpoints),
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
        for ep in results["endpoints"][:20]:
            print(f"  {ep}")

if __name__ == "__main__":
    main()
