import json
import glob
from collections import defaultdict
from urllib.parse import urlparse

def analyze_findings():
    print("Analyzing findings in all_output directory...")
    # Find all bounty_targets.json files
    json_files = glob.glob("all_output/**/bounty_targets.json", recursive=True)
    
    type_counts = defaultdict(int)
    fp_candidates = defaultdict(list)
    
    total_findings = 0
    
    for fpath in json_files:
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
                findings = data.get("findings", [])
                
                for finding in findings:
                    vuln_type = finding.get("type", "UNKNOWN")
                    url = finding.get("url", "")
                    evidence = finding.get("evidence", "")
                    
                    type_counts[vuln_type] += 1
                    total_findings += 1
                    
                    # Store a few examples for each type to identify patterns of FPs
                    if len(fp_candidates[vuln_type]) < 20:
                        fp_candidates[vuln_type].append({"url": url, "evidence": evidence})
        except Exception as e:
            pass
            
    with open("scratch/current_findings_summary.txt", "w", encoding="utf-8") as out_f:
        out_f.write(f"Total Findings: {total_findings}\n")
        out_f.write("\nFindings by Type:\n")
        for v_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            out_f.write(f"  {v_type}: {count}\n")
            
        out_f.write("\n\n--- Sample Evidence per Type ---\n")
        for v_type, samples in fp_candidates.items():
            out_f.write(f"\n[{v_type}]\n")
            for i, s in enumerate(samples):
                out_f.write(f"  {i+1}. URL: {s['url'][:100]}...\n")
                out_f.write(f"     Evidence: {s['evidence']}\n")
            
if __name__ == "__main__":
    analyze_findings()
