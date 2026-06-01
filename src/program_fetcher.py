#!/usr/bin/env python3
"""
Module: Bug Bounty Program Scope Fetcher
Fetches in-scope, bounty-eligible assets for a given program from HackerOne & Bugcrowd.
Data powered by bounty-targets-data (Arkadiyt).
"""

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.recon.utils import log_info, log_success, log_error, log_warning, banner, RICH_AVAILABLE

if RICH_AVAILABLE:
    from rich.console import Console
    from rich.table import Table
    console = Console()

H1_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json"
BC_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json"

def fetch_json(url: str):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            return json.loads(response.read().decode())
    except Exception as e:
        log_error(f"Failed to fetch {url}: {e}")
        return []

def clean_target(target: str) -> str:
    """Removes wildcards and protocols to get the root domain."""
    t = target.strip().lower()
    t = re.sub(r"^https?://", "", t)
    t = re.sub(r"^\*\.", "", t)
    t = t.split("/")[0]
    return t

def is_valid_domain(target: str) -> bool:
    """Basic check to ignore CIDRs, IPs, or executable names if mislabeled."""
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", target):
        return False
    return True

def search_hackerone(data, query: str):
    query = query.lower()
    results = []
    for program in data:
        name = program.get("name", "").lower()
        handle = program.get("handle", "").lower()
        
        if query in name or query in handle:
            targets = set()
            in_scope = program.get("targets", {}).get("in_scope", [])
            for asset in in_scope:
                # We only want Web URLs that are bounty eligible
                if asset.get("asset_type") == "URL" and asset.get("eligible_for_bounty", False):
                    identifier = asset.get("asset_identifier", "")
                    cleaned = clean_target(identifier)
                    if is_valid_domain(cleaned):
                        targets.add(cleaned)
            
            if targets:
                results.append({
                    "platform": "HackerOne",
                    "name": program.get("name"),
                    "url": program.get("url"),
                    "targets": list(targets)
                })
    return results

def search_bugcrowd(data, query: str):
    query = query.lower()
    results = []
    for program in data:
        name = program.get("name", "").lower()
        
        if query in name:
            targets = set()
            in_scope = program.get("targets", {}).get("in_scope", [])
            for asset in in_scope:
                # Bugcrowd types: website, api
                if asset.get("type") in ["website", "api"]:
                    identifier = asset.get("target", "")
                    cleaned = clean_target(identifier)
                    if is_valid_domain(cleaned):
                        targets.add(cleaned)
            
            if targets:
                results.append({
                    "platform": "Bugcrowd",
                    "name": program.get("name"),
                    "url": program.get("url"),
                    "targets": list(targets)
                })
    return results

def main():
    banner("Program Scope Fetcher")
    parser = argparse.ArgumentParser(description="Fetch Bug Bounty Program Scopes")
    parser.add_argument("program", help="Program name to search for (e.g., tesla, yahoo)")
    parser.add_argument("-o", "--output", default="targets.txt", help="Output file for domains")
    
    args = parser.parse_args()
    query = args.program
    
    log_info(f"Fetching latest scopes for '{query}'...")
    
    h1_data = fetch_json(H1_URL)
    bc_data = fetch_json(BC_URL)
    
    matches = search_hackerone(h1_data, query) + search_bugcrowd(bc_data, query)
    
    if not matches:
        log_error(f"No programs found matching '{query}' that offer bounties for Web/API assets.")
        return
        
    # If multiple matches, we just aggregate them (or we could prompt, but let's aggregate for automation)
    all_targets = set()
    for match in matches:
        log_success(f"Found {len(match['targets'])} targets for {match['name']} on {match['platform']}!")
        all_targets.update(match['targets'])
        
    final_targets = sorted(list(all_targets))
    
    with open(args.output, "w") as f:
        for t in final_targets:
            f.write(t + "\n")
            
    log_success(f"Total unique domains extracted: {len(final_targets)}")
    log_success(f"Saved targets to {args.output}")
    log_info("You can now run: ./run_bulk.sh targets.txt")

if __name__ == "__main__":
    main()
