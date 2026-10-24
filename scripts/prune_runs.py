#!/usr/bin/env python3
"""Keep only the newest KEEP runs per domain under output/ (monitor diffs need 2).
Deletes older <domain>_<ts> dirs. Preserves *_state.json and _monitor/."""
import glob, os, re, shutil, sys, collections
OUT = os.environ.get("RECON_OUTPUT", "/root/recon-tools/output")
KEEP = int(os.environ.get("RECON_KEEP", "2"))
bydom = collections.defaultdict(list)
for d in glob.glob(os.path.join(OUT, "*_*")):
    if not os.path.isdir(d):
        continue
    m = re.match(r"(.+)_(\d{8}_\d{6})$", os.path.basename(d))
    if m:
        bydom[m.group(1)].append(d)
def dsize(p):
    t = 0
    for r,_,fs in os.walk(p):
        for f in fs:
            try: t += os.path.getsize(os.path.join(r,f))
            except OSError: pass
    return t
freed = 0; removed = 0
for dom, dirs in bydom.items():
    dirs.sort(key=lambda p: os.path.basename(p), reverse=True)  # newest first
    for old in dirs[KEEP:]:
        freed += dsize(old)
        shutil.rmtree(old, ignore_errors=True)
        removed += 1
print(f"pruned {removed} old run dirs, freed {freed/1e6:.0f} MB (kept newest {KEEP}/domain)")
