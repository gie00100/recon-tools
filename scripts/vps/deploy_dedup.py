import paramiko
import time

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"

print("[*] Connecting to VPS...")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(IP, username=USER, password=PASS, timeout=10, look_for_keys=False, allow_agent=False)

# Step 1: Upload fixed url_dedup.py
print("[*] Uploading optimized url_dedup.py to VPS...")
sftp = ssh.open_sftp()
sftp.put("src/recon/url_dedup.py", "/root/recon-tools/src/recon/url_dedup.py")
sftp.close()
print("[+] Optimized url_dedup.py uploaded successfully!")

# Step 2: Kill old locked-up recon processes
print("[*] Killing old hung scan sessions (stuck in O(N^2) comparison loop)...")
ssh.exec_command("pkill -f run_recon.sh || true")
ssh.exec_command("pkill -f run_bulk.sh || true")
ssh.exec_command("pkill -f recon_master.py || true")
ssh.exec_command("for s in $(screen -ls | grep -oP '\\d+\\.recon\\S+'); do screen -S $s -X quit; done || true")
time.sleep(2)

# Step 3: Relaunch sequentially under fresh screen session
print("[*] Restarting clean sequential bulk recon...")
ssh.exec_command("cd /root/recon-tools && rm -f /tmp/recon_chunk_*.txt")
ssh.exec_command('cd /root/recon-tools && screen -dmS recon_main bash -c "./run_bulk.sh ui_targets.txt; echo DONE; sleep 3600"')
time.sleep(3)

# Step 4: Verify processes
print("\n[*] Active process priorities (NI column):")
stdin, stdout, stderr = ssh.exec_command("ps -eo pid,ni,args | grep -E 'python|run_' | grep -v grep")
print(stdout.read().decode('utf-8', errors='ignore'))

# Automatically prioritize the bot vs scanner again!
print("[*] Reprioritizing Bot and Scanner nice levels...")
ssh.exec_command("renice -n 19 -p $(pgrep -f recon_master.py) 2>/dev/null || true")
ssh.exec_command("renice -n -5 -p $(pgrep -f discord_bot.py) 2>/dev/null || true")

ssh.close()
print("[+] Deploy and restart complete! The pipeline will now fly through deduplication.")
