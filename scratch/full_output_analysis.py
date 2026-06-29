"""
Deep analysis of all URLs in all_output folder.
Re-run the bounty scanner against ALL URLs (not just existing findings) 
to find what we're missing and identify false positives.
"""
import json, glob, sys, os
from collections import defaultdict
from urllib.parse import urlparse

sys.path.insert(0, os.path.abspath('.'))
from src.recon.bounty_scanner import BountyScanner

def load_all_urls():
    all_urls = set()
    sources = defaultdict(int)
    
    # Load from master_unique_urls.txt (most comprehensive)
    for fpath in glob.glob('all_output/**/master_unique_urls.txt', recursive=True):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('http'):
                        all_urls.add(line)
                        sources['master_unique_urls'] += 1
        except Exception as e:
            print(f'Error: {fpath}: {e}')

    # Load from virustotal_urls.txt
    for fpath in glob.glob('all_output/**/virustotal_urls.txt', recursive=True):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('http'):
                        all_urls.add(line)
                        sources['virustotal_urls'] += 1
        except: pass

    # Load from js_endpoints.txt
    for fpath in glob.glob('all_output/**/js_endpoints.txt', recursive=True):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('http'):
                        all_urls.add(line)
                        sources['js_endpoints'] += 1
        except: pass

    print(f"Total unique URLs collected: {len(all_urls)}")
    for src, cnt in sources.items():
        print(f"  {src}: {cnt} lines (many duplicates)")
    return list(all_urls)


def analyze_noise(findings):
    """Group findings to identify FP patterns."""
    type_groups = defaultdict(list)
    for f in findings:
        type_groups[f['type']].append(f)
    
    with open('scratch/full_scan_results.txt', 'w', encoding='utf-8') as out:
        out.write(f"=== FULL SCAN RESULTS ===\n")
        out.write(f"Total findings: {len(findings)}\n\n")
        out.write("By Type:\n")
        for t, items in sorted(type_groups.items(), key=lambda x: -len(x[1])):
            out.write(f"  {t}: {len(items)}\n")
        
        out.write("\n\n=== DETAILS PER TYPE ===\n")
        for t, items in sorted(type_groups.items(), key=lambda x: -len(x[1])):
            out.write(f"\n\n[{t}] - {len(items)} findings\n")
            out.write("-" * 80 + "\n")
            for i, f in enumerate(items[:30]):  # show up to 30 per type
                out.write(f"  {i+1}. [{f.get('severity','?')}] {f.get('url','')[:150]}\n")
                out.write(f"     Evidence: {f.get('evidence','')[:200]}\n")

    print(f"\nTotal findings: {len(findings)}")
    print("\nBy Type:")
    for t, items in sorted(type_groups.items(), key=lambda x: -len(x[1])):
        print(f"  {t}: {len(items)}")
    print("\nFull details written to scratch/full_scan_results.txt")


if __name__ == '__main__':
    urls = load_all_urls()
    if not urls:
        print("No URLs found! Check that all_output has data.")
        sys.exit(1)
    
    print(f"\nScanning {len(urls)} URLs...")
    scanner = BountyScanner(urls)
    result = scanner.scan()
    findings = result.get('findings', [])
    analyze_noise(findings)
