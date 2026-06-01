import paramiko
import os

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"

print("[*] Connecting to VPS...")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(IP, username=USER, password=PASS, timeout=10, look_for_keys=False, allow_agent=False)

# Dump screen buffer to file to check stdout progress
print("[*] Dumping recon_main screen session buffer...")
ssh.exec_command("screen -S recon_main -X hardcopy /tmp/screen_recon.log")
import time; time.sleep(1)

# Read the screen log
stdin, stdout, stderr = ssh.exec_command("tail -n 25 /tmp/screen_recon.log 2>/dev/null || echo 'No active screen buffer dump found.'")
screen_log = stdout.read().decode('utf-8', errors='ignore')
safe_log = screen_log.encode('ascii', errors='ignore').decode('ascii')

# Get completed targets vs total targets
stdin, stdout, stderr = ssh.exec_command("cat /root/recon-tools/ui_targets.txt")
targets = [line.strip() for line in stdout.read().decode('utf-8', errors='ignore').split('\n') if line.strip()]

stdin, stdout, stderr = ssh.exec_command("ls -d /root/recon-tools/output/*/")
output_dirs = stdout.read().decode('utf-8', errors='ignore').split('\n')

completed = []
for target in targets:
    # Check if a completed report.json exists for this target
    stdin, stdout, stderr = ssh.exec_command(f"find /root/recon-tools/output/ -name 'report.json' -path '*/{target}_*'")
    found = stdout.read().decode('utf-8', errors='ignore').strip()
    if found:
        completed.append(target)

print("\n=== RECON PIPELINE PROGRESS ===")
print(f"Total Targets: {len(targets)}")
print(f"Completed    : {len(completed)} / {len(targets)}")
for target in targets:
    status_icon = "Done" if target in completed else "Scanning"
    print(f"  - {target:25s} -> {status_icon}")

print("\n=== LATEST LOG OUTPUT ===")
print(safe_log)

ssh.close()
