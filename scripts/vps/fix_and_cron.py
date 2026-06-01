import paramiko
import time

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(IP, username=USER, password=PASS, timeout=10, look_for_keys=False, allow_agent=False)

def run(cmd, label=None):
    if label:
        print(f"[*] {label}")
    stdin, stdout, stderr = ssh.exec_command(cmd)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode(errors='ignore').strip()
    err = stderr.read().decode(errors='ignore').strip()
    if out:
        print(f"    {out[:800]}")
    if err and exit_code != 0:
        print(f"    ERR: {err[:300]}")
    return out

# Upload fixed run_recon.sh
print("[*] Uploading fixed run_recon.sh (no brute-force)...")
sftp = ssh.open_sftp()
sftp.put("run_recon.sh", "/root/recon-tools/run_recon.sh")
sftp.close()
run("chmod +x /root/recon-tools/run_recon.sh")

# Kill any leftover screen sessions
run("for s in $(screen -ls 2>/dev/null | grep -oP '\\d+\\.recon' || true); do screen -S $s -X quit 2>/dev/null; done")
run("pkill -f recon_master.py 2>/dev/null || true")
time.sleep(2)

# Set up daily cron: run bulk recon every day at 2 AM UTC
print("[*] Setting up daily cron job...")
cron_cmd = '0 2 * * * cd /root/recon-tools && ./run_bulk.sh ui_targets.txt >> /root/recon-tools/cron_recon.log 2>&1'
run(f'(crontab -l 2>/dev/null | grep -v run_bulk; echo "{cron_cmd}") | crontab -', "Installing crontab...")

# Verify cron
run("crontab -l", "Current crontab:")

# Restart recon with 1 worker (sequential, memory-safe)
print("\n[*] Restarting recon (sequential, 1 worker)...")
run('cd /root/recon-tools && rm -f /tmp/recon_chunk_*.txt')
run('cd /root/recon-tools && screen -dmS recon_main bash -c "./run_bulk.sh ui_targets.txt; echo DONE; sleep 3600"')
time.sleep(2)

# Verify
run("screen -ls", "Active sessions:")
run("free -h", "Memory:")

ssh.close()
print("\n[+] Done! Recon restarted (memory-safe) + daily cron at 2 AM UTC.")
