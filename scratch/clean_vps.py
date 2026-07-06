"""
1. Connect to VPS via Paramiko
2. List all output dirs
3. Delete dirs already fetched locally
4. Report disk freed
"""
import os, re, paramiko, time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCAL_OUT    = os.path.join(PROJECT_ROOT, 'output')

IP   = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"
REMOTE_OUT = "/root/recon-tools/output"

# Build local domain set
local_domains = set()
for name in os.listdir(LOCAL_OUT):
    if os.path.isdir(os.path.join(LOCAL_OUT, name)):
        local_domains.add(name.lower().strip())

print(f"[*] Local output: {len(local_domains)} domains")

# Connect
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
print(f"[*] Connecting to {IP}...")
ssh.connect(IP, username=USER, password=PASS, timeout=30, look_for_keys=False, allow_agent=False)
ssh.get_transport().set_keepalive(30)
print("[+] Connected!")

# Get VPS output dirs
_, stdout, _ = ssh.exec_command(f'ls {REMOTE_OUT}/ 2>/dev/null')
vps_dirs = [d.strip() for d in stdout.read().decode().split('\n') if d.strip()]
print(f"[*] VPS has {len(vps_dirs)} output dir(s)")

# Get disk usage before
_, stdout, _ = ssh.exec_command(f'du -sh {REMOTE_OUT}/')
before_size = stdout.read().decode().strip()
print(f"[*] VPS output size before: {before_size}")

# Delete dirs already fetched locally
deleted = []
kept = []
for vdir in vps_dirs:
    # Extract domain from "domain_YYYYMMDD_HHMMSS" or just "domain"
    m = re.match(r'^(.+?)_\d{8}_\d{6}$', vdir)
    domain = m.group(1).lower() if m else vdir.lower()

    if domain in local_domains:
        remote_path = f"{REMOTE_OUT}/{vdir}"
        print(f"  [~] Deleting: {vdir}")
        _, _, serr = ssh.exec_command(f'rm -rf "{remote_path}"')
        serr.read()
        deleted.append(vdir)
    else:
        print(f"  [=] Keeping (not local yet): {vdir}")
        kept.append(vdir)

# Disk usage after
_, stdout, _ = ssh.exec_command(f'du -sh {REMOTE_OUT}/ 2>/dev/null || echo "0"')
after_size = stdout.read().decode().strip()

ssh.close()

print(f"\n[+] Cleanup done!")
print(f"    Deleted: {len(deleted)} dirs")
print(f"    Kept:    {len(kept)} dirs")
print(f"    Before:  {before_size}")
print(f"    After:   {after_size}")
if kept:
    print(f"\n[*] Dirs kept on VPS (not yet local):")
    for d in kept:
        print(f"    {d}")
