import json, glob

all_findings = []
for fpath in glob.glob('all_output/**/master_bounty_findings.json', recursive=True):
    try:
        with open(fpath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for finding in data.get('findings', []):
                finding['_source_file'] = fpath
            all_findings.extend(data.get('findings', []))
    except Exception as e:
        print(f'Error reading {fpath}: {e}')

print(f"Total findings: {len(all_findings)}\n")
for f in all_findings:
    sev = f.get("severity", "?")
    ftype = f.get("type", "?")
    url = f.get("url", "")[:130]
    ev = f.get("evidence", "")[:130]
    print(f"[{sev}] {ftype}")
    print(f"  URL: {url}")
    print(f"  Evidence: {ev}")
    print()
