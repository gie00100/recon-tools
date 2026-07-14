"""
VPS Scan Dashboard — shows how many scans are done, in progress, and remaining.
Called from recon.bat option [9].
"""
import paramiko
import sys
import re

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

IP   = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"

print("[*] Connecting to VPS...")
try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(IP, username=USER, password=PASS, timeout=15,
                look_for_keys=False, allow_agent=False)
except Exception as e:
    print(f"[!] Could not connect to VPS: {e}")
    sys.exit(1)

# 1. Total targets (uncommented, non-blank lines in targets.txt)
_, stdout, _ = ssh.exec_command(
    r"grep -v '^#' /root/recon-tools/targets/targets.txt | grep -v '^$' | sort -u"
)
all_targets = [l.strip() for l in stdout.read().decode('utf-8', errors='replace').split('\n') if l.strip()]
total = len(all_targets)

# 2. Completed scans (directories in output/)
_, stdout, _ = ssh.exec_command(
    "ls -1 /root/recon-tools/output/ 2>/dev/null | grep -v state.json"
)
output_dirs = [d.strip() for d in stdout.read().decode('utf-8', errors='replace').split('\n') if d.strip()]

# Extract domain names from output dir names (format: domain_YYYYMMDD_HHMMSS)
scanned_domains = set()
for d in output_dirs:
    m = re.match(r'^(.+?)_\d{8}_\d{6}$', d)
    if m:
        scanned_domains.add(m.group(1).lower())

done = len(scanned_domains)
remaining = total - done

# 3. Currently running scan (check screen session + scan.log tail)
_, stdout, _ = ssh.exec_command("screen -ls 2>/dev/null | grep -i recon")
screens = stdout.read().decode('utf-8', errors='replace').strip()
is_running = bool(screens)

currently_scanning = "N/A"
if is_running:
    _, stdout, _ = ssh.exec_command(
        "tail -n 30 /root/recon-tools/scan.log 2>/dev/null | grep -oP 'Scanning: \\K.*' | tail -1"
    )
    currently_scanning = stdout.read().decode('utf-8', errors='replace').strip() or "Unknown"

# 4. Disk space
_, stdout, _ = ssh.exec_command("df -h / | tail -1")
disk = stdout.read().decode('utf-8', errors='replace').strip()
disk_parts = disk.split()
disk_used  = disk_parts[2] if len(disk_parts) > 2 else "?"
disk_avail = disk_parts[3] if len(disk_parts) > 3 else "?"
disk_pct   = disk_parts[4] if len(disk_parts) > 4 else "?"

# 5. Bot status
_, stdout, _ = ssh.exec_command("systemctl is-active recon-bot 2>/dev/null")
bot_status = stdout.read().decode('utf-8', errors='replace').strip()

ssh.close()

# ── Display ──────────────────────────────────────────────────────────
pct_done = (done / total * 100) if total > 0 else 0
bar_len = 40
filled = int(bar_len * done / total) if total > 0 else 0
bar = "#" * filled + "-" * (bar_len - filled)

print()
print("  ================================================================")
print("    VPS SCAN DASHBOARD")
print("  ================================================================")
print()
print(f"    Total Targets  : {total}")
print(f"    Scans Done     : {done}")
print(f"    Remaining      : {remaining}")
print(f"    Progress       : [{bar}] {pct_done:.1f}%")
print()
print(f"    Scanner Active : {'YES' if is_running else 'NO'}")
print(f"    Currently On   : {currently_scanning}")
print(f"    Discord Bot    : {bot_status}")
print()
print(f"    Disk Used      : {disk_used} / Available: {disk_avail} ({disk_pct})")
print()
print("  ================================================================")

# Show last 5 completed scans
if scanned_domains:
    print()
    print("    Last completed scans (by dir order):")
    for d in output_dirs[-5:]:
        m = re.match(r'^(.+?)_(\d{8})_(\d{6})$', d)
        if m:
            domain = m.group(1)
            date = f"{m.group(2)[:4]}-{m.group(2)[4:6]}-{m.group(2)[6:]}"
            time_str = f"{m.group(3)[:2]}:{m.group(3)[2:4]}:{m.group(3)[4:]}"
            print(f"      - {domain:40s}  {date} {time_str}")
    print()
