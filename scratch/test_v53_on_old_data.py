import json
import glob
from collections import defaultdict
import sys
import os

sys.path.insert(0, os.path.abspath('.'))
from src.recon.bounty_scanner import BountyScanner

def test_v53():
    print("Testing v5.3 scanner on URLs from all_output...")
    json_files = glob.glob("all_output/**/bounty_targets.json", recursive=True)
    
    all_urls = set()
    for fpath in json_files:
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
                for finding in data.get("findings", []):
                    if "url" in finding:
                        all_urls.add(finding["url"])
        except:
            pass
            
    print(f"Extracted {len(all_urls)} unique URLs from old findings.")
    
    scanner = BountyScanner(list(all_urls))
    findings = scanner.scan().get('findings', [])
    
    type_counts = defaultdict(int)
    fp_candidates = defaultdict(list)
    
    for finding in findings:
        vuln_type = finding["type"]
        type_counts[vuln_type] += finding.get('count', 1)
        if len(fp_candidates[vuln_type]) < 20:
            fp_candidates[vuln_type].append(finding)
            
    total_findings = sum(type_counts.values())
    print(f"\nTotal Findings (v5.3): {total_findings}")
    
    with open("scratch/v53_results.txt", "w", encoding="utf-8") as out_f:
        out_f.write(f"Total Findings: {total_findings}\n")
        out_f.write("\nFindings by Type:\n")
        for v_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            out_f.write(f"  {v_type}: {count}\n")
            
        out_f.write("\n\n--- Sample Evidence per Type ---\n")
        for v_type, samples in fp_candidates.items():
            out_f.write(f"\n[{v_type}]\n")
            for i, s in enumerate(samples):
                out_f.write(f"  {i+1}. URL: {s['url'][:150]}...\n")
                out_f.write(f"     Evidence: {s['evidence']}\n")


if __name__ == "__main__":
    test_v53()
