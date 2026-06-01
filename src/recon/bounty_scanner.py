#!/usr/bin/env python3
"""
Module: Bounty Scanner (URL Heuristics)
Passively analyzes massive URL collections for high-value bug bounty endpoints.
"""

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.utils import log_info, log_success, banner, elapsed_str, read_lines, RICH_AVAILABLE

# High-Value Vulnerability Heuristics
HEURISTICS = {
    # ── PII & Token Leaks (HIGH) ──
    "PII_Leak_Params": {
        "severity": "HIGH",
        "description": "Sensitive PII parameters that might leak data.",
        "regex": re.compile(r"(?i)(?:email|ssn|dob|passport|phone|mobile|address)=", re.IGNORECASE)
    },
    "Token_Leak_Params": {
        "severity": "HIGH",
        "description": "Tokens, Auth Keys, and Passwords in URLs.",
        "regex": re.compile(r"(?i)(?:token|auth|key|password|secret|api_key|reset_token|session)=", re.IGNORECASE)
    },
    
    # ── Unsubscribe Logic (HIGH) ──
    "Unsubscribe_ATO": {
        "severity": "HIGH",
        "description": "Unsubscribe endpoint without token verification.",
        "regex": re.compile(r"(?i)/unsubscribe\?email=[^&]+$", re.IGNORECASE)
    },

    # ── Sensitive Endpoints (CRITICAL) ──
    "Exposed_Dashboards": {
        "severity": "CRITICAL",
        "description": "Exposed admin or dev dashboards.",
        "regex": re.compile(r"(?i)/(?:admin/?$|grafana|kibana|phpmyadmin|wp-admin|jenkins|swagger-ui|actuator/env)", re.IGNORECASE)
    },
    "Juicy_Files": {
        "severity": "HIGH",
        "description": "Highly sensitive file extensions.",
        "regex": re.compile(r"(?i)\.(?:env|sql|bak|log|git/config|svn/entries|yml|sqlite|db)$", re.IGNORECASE)
    },
    
    # ── IDOR / BOLA (MEDIUM) ──
    "IDOR_Endpoints": {
        "severity": "MEDIUM",
        "description": "Endpoints exposing raw user data or sequential IDs.",
        "regex": re.compile(r"(?i)/(?:api/v[0-9]+/users/[0-9]+|invoice[s]?/[0-9]+|receipt[s]?/[0-9]+|order[s]?/[0-9]+)", re.IGNORECASE)
    },
    
    # ── Open Redirects (MEDIUM) ──
    "Open_Redirect": {
        "severity": "MEDIUM",
        "description": "Parameters often vulnerable to Open Redirects.",
        "regex": re.compile(r"(?i)(?:url|return|next|redirect|go|uri|path)=https?://", re.IGNORECASE)
    }
}

class BountyScanner:
    def __init__(self, urls: List[str]):
        self.urls = urls
        self.findings = []
        self.stats = {k: 0 for k in HEURISTICS.keys()}

    def scan(self) -> Dict:
        start = time.time()
        banner("Passive Bounty Scanner")
        log_info(f"Scanning {len(self.urls)} unique URLs against {len(HEURISTICS)} heuristics...")

        for url in self.urls:
            url = url.strip()
            if not url:
                continue

            for vuln_id, config in HEURISTICS.items():
                if config["regex"].search(url):
                    finding = {
                        "type": vuln_id,
                        "severity": config["severity"],
                        "description": config["description"],
                        "url": url
                    }
                    self.findings.append(finding)
                    self.stats[vuln_id] += 1

        log_success(f"Bounty Scan complete in {elapsed_str(start)}")
        log_success(f"Total flags raised: {len(self.findings)}")
        
        return {
            "findings": self.findings,
            "stats": self.stats,
            "total_urls": len(self.urls)
        }

def main():
    parser = argparse.ArgumentParser(description="Passive Bounty URL Scanner")
    parser.add_argument("-l", "--list", required=True, help="File containing URLs to scan (e.g., unique_urls.txt)")
    parser.add_argument("-o", "--output", help="Output JSON file for findings")
    
    args = parser.parse_args()
    urls = read_lines(args.list)
    
    if not urls:
        print("No URLs to scan.")
        return

    scanner = BountyScanner(urls)
    results = scanner.scan()
    
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        log_success(f"Findings saved to {args.output}")

if __name__ == "__main__":
    main()
