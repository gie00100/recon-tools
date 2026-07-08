"""
H1 Scope Importer — bounty_scope_updater.py

Usage:
  1. Public programs (from URL or Handle):
     python bounty_scope_updater.py --url https://hackerone.com/PROGRAM/policy_scopes
     python bounty_scope_updater.py --urls https://hackerone.com/A/policy_scopes https://hackerone.com/B/policy_scopes

  2. Private programs — download the scope CSV from HackerOne and drop it in:
     tools/targets/h1_csvs/PROGRAM_NAME.csv
     Then run:
     python bounty_scope_updater.py --csv targets/h1_csvs/PROGRAM_NAME.csv

Output:
  Appends new program blocks to targets/targets.txt (with # STATUS: PENDING comment)
  If the program is already in the list, it will note that it's already done/added.
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

TARGETS_FILE = Path(__file__).parent.parent / 'targets' / 'targets.txt'
H1_CSV_DIR   = Path(__file__).parent.parent / 'targets' / 'h1_csvs'

# Public bug bounty targets data repository
BOUNTY_TARGETS_URL = 'https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json'


def extract_handle(url: str) -> str:
    """Extract program handle from HackerOne URL."""
    m = re.search(r'hackerone\.com/([^/]+)', url)
    return m.group(1) if m else url


def is_web_domain(asset_type: str, identifier: str) -> bool:
    """Return True for web URL/domain assets, skip mobile/source code."""
    asset_type = asset_type.lower()
    if asset_type in ('url', 'domain', 'cidr', 'website', 'web'):
        return True
    if asset_type in ('google_play_id', 'apple_store_id', 'testflight', 'other',
                      'hardware', 'source_code', 'executable'):
        return False
    # Fallback: check if identifier looks like a domain/URL
    if re.match(r'^[\*\w][\w\.\-]*\.[a-z]{2,}', identifier):
        return True
    return False


def clean_domain(identifier: str) -> str:
    """Strip scheme and wildcards, return bare domain."""
    identifier = identifier.strip()
    if '://' in identifier:
        parsed = urlparse(identifier if '://' in identifier else 'https://' + identifier)
        identifier = parsed.netloc or parsed.path
    identifier = re.sub(r'^\*\.', '', identifier)
    identifier = re.sub(r':\d+$', '', identifier)
    return identifier.lower().strip('/')


def fetch_h1_data() -> list:
    if not HAS_REQUESTS:
        print('[!] requests not installed. Run: pip install requests')
        return []
    print('[*] Fetching latest public HackerOne scopes from bounty-targets-data...')
    try:
        r = requests.get(BOUNTY_TARGETS_URL, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f'[!] Failed to fetch public H1 data: {e}')
        return []


def fetch_scope_public(handle: str, h1_data: list) -> dict:
    """Fetch scope using arkadiyt's bounty-targets-data JSON."""
    for prog in h1_data:
        if prog.get('handle', '').lower() == handle.lower():
            domains = []
            for target in prog.get('targets', {}).get('in_scope', []):
                asset_type = target.get('asset_type', '')
                identifier = target.get('asset_identifier', '')
                eligible = target.get('eligible_for_bounty', False)
                
                if not is_web_domain(asset_type, identifier):
                    continue
                
                domain = clean_domain(identifier)
                if domain and '.' in domain and ' ' not in domain:
                    domains.append({
                        'domain': domain,
                        'eligible_for_bounty': eligible,
                        'raw': identifier,
                    })
            
            return {
                'name': prog.get('name', handle),
                'handle': handle,
                'url': f'https://hackerone.com/{handle}/policy_scopes',
                'domains': domains,
            }
    
    print(f'[!] Program "{handle}" not found in public H1 data. If this is a private program, please download the scope CSV and use --csv targets/h1_csvs/PROGRAM_NAME.csv')
    return {}


def parse_csv_scope(csv_path: Path) -> dict:
    """Parse a HackerOne scope export CSV."""
    domains = []
    program_name = csv_path.stem.replace('_', ' ').title()

    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            asset_type  = row.get('Type', row.get('Asset Type', row.get('asset_type', '')))
            identifier  = row.get('Identifier', row.get('Asset', row.get('URL', row.get('identifier', ''))))
            eligible    = str(row.get('Eligible for bounty', row.get('Bounty', row.get('eligible_for_bounty', 'true')))).lower() in ('true', 'yes', '1')

            if not identifier:
                continue
            if not is_web_domain(asset_type, identifier):
                continue

            domain = clean_domain(identifier)
            if domain and '.' in domain and ' ' not in domain:
                domains.append({
                    'domain': domain,
                    'eligible_for_bounty': eligible,
                    'raw': identifier,
                })

    return {
        'name': program_name,
        'handle': csv_path.stem,
        'url': f'(CSV import: {csv_path.name})',
        'domains': domains,
    }


def load_existing_targets() -> str:
    """Load current targets.txt content."""
    if TARGETS_FILE.exists():
        return TARGETS_FILE.read_text(encoding='utf-8')
    return ''


def program_already_exists(content: str, handle: str, name: str) -> bool:
    """Check if program is already in targets.txt."""
    handle_lower = handle.lower()
    name_lower   = name.lower()
    content_lower = content.lower()
    return (
        handle_lower in content_lower or
        name_lower.replace(' ', '') in content_lower.replace(' ', '')
    )


def build_targets_block(program: dict) -> str:
    """Build a formatted targets.txt block for a program."""
    lines = []
    name   = program['name']
    handle = program['handle']
    url    = program['url']
    domains = program['domains']

    # Remove duplicates while preserving order
    seen = set()
    unique_domains = []
    for d in domains:
        if d['domain'] not in seen:
            seen.add(d['domain'])
            unique_domains.append(d)

    bounty_count = sum(1 for d in unique_domains if d['eligible_for_bounty'])
    total_count  = len(unique_domains)

    lines.append(f'# === {name} (HackerOne) ===')
    lines.append(f'# Program: {url}')
    lines.append(f'# Scope: {total_count} domains ({bounty_count} bounty-eligible)')
    lines.append(f'# STATUS: PENDING')

    for d in unique_domains:
        bounty_tag = '' if d['eligible_for_bounty'] else '  # (no bounty)'
        lines.append(f'{d["domain"]}{bounty_tag}')

    lines.append('')
    return '\n'.join(lines)


def append_to_targets(blocks: list[str], programs_meta: list[dict]):
    """Append new program blocks to targets.txt, return count added."""
    existing = load_existing_targets()
    added = 0
    new_content = existing.rstrip('\n') + '\n\n'

    for i, block in enumerate(blocks):
        prog = programs_meta[i]
        
        # Check if already in file
        if program_already_exists(existing, prog['handle'], prog['name']):
            print(f'[skip] {prog["name"]} is already done / present in targets.txt')
            continue

        new_content += block + '\n'
        added += 1
        print(f'[+] Added: {prog["name"]} ({len(prog["domains"])} domains)')

    if added:
        TARGETS_FILE.write_text(new_content, encoding='utf-8')
        print(f'\n[+] Updated targets.txt — added {added} new program(s)')
    else:
        print('\n[=] No new programs added (all already present)')

    return added


def main():
    parser = argparse.ArgumentParser(description='HackerOne Scope Importer')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--url',       help='Single HackerOne policy_scopes URL')
    group.add_argument('--csv',       help='Path to H1 scope CSV export')
    group.add_argument('--urls',      nargs='+', help='Multiple H1 policy_scopes URLs')
    group.add_argument('--urls-file', help='File containing H1 policy_scopes URLs (one per line)')
    parser.add_argument('--dry-run',  action='store_true', help='Print what would be added without writing')

    args = parser.parse_args()

    programs = []
    
    # Pre-fetch H1 data if any public URLs are requested
    h1_data = []
    if args.url or args.urls or args.urls_file:
        h1_data = fetch_h1_data()

    if args.url:
        handle = extract_handle(args.url)
        print(f'[*] Fetching scope for: {handle}')
        prog = fetch_scope_public(handle, h1_data)
        if prog: programs.append(prog)

    elif args.csv:
        csv_path = Path(args.csv)
        print(f'[*] Parsing CSV: {csv_path.name}')
        prog = parse_csv_scope(csv_path)
        if prog: programs.append(prog)

    elif args.urls:
        for url in args.urls:
            handle = extract_handle(url)
            print(f'[*] Fetching: {handle}')
            prog = fetch_scope_public(handle, h1_data)
            if prog: programs.append(prog)

    elif args.urls_file:
        with open(args.urls_file) as f:
            urls = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        for url in urls:
            handle = extract_handle(url)
            print(f'[*] Fetching: {handle}')
            prog = fetch_scope_public(handle, h1_data)
            if prog: programs.append(prog)

    if not programs:
        print('[!] No programs fetched. Ensure handles are public or provide a --csv.')
        sys.exit(1)

    blocks = [build_targets_block(p) for p in programs]

    if args.dry_run:
        print('\n--- DRY RUN: Would add the following ---\n')
        for block in blocks:
            print(block)
        return

    append_to_targets(blocks, programs)


if __name__ == '__main__':
    main()
