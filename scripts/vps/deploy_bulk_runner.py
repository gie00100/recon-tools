import paramiko
import time

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"

print("[*] Connecting to VPS...")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(IP, username=USER, password=PASS, timeout=10)

print("[*] Uploading optimized run_bulk.sh to VPS...")
sftp = ssh.open_sftp()
sftp.put("run_bulk.sh", "/root/recon-tools/run_bulk.sh")
sftp.close()

# Ensure execution permissions are clean
ssh.exec_command("chmod +x /root/recon-tools/run_bulk.sh")
print("[+] run_bulk.sh uploaded and permissions set successfully!")

print("[*] Terminating old sessions to restart bulk scan cleanly...")
ssh.exec_command("pkill -f run_recon.sh || true")
ssh.exec_command("pkill -f run_bulk.sh || true")
ssh.exec_command("pkill -f recon_master.py || true")
ssh.exec_command("for s in $(screen -ls | grep -oP '\\d+\\.recon\\S+'); do screen -S $s -X quit; done || true")
time.sleep(2)

print("[*] Restarting sequential bulk recon runner...")
ssh.exec_command("cd /root/recon-tools && rm -f /tmp/recon_chunk_*.txt")
ssh.exec_command('cd /root/recon-tools && screen -dmS recon_main bash -c "./run_bulk.sh ui_targets.txt; echo DONE; sleep 3600"')
time.sleep(3)

print("\n[*] Verifying active screen sessions and priorities:")
stdin, stdout, stderr = ssh.exec_command("ps -eo pid,ni,args | grep -E 'python|run_' | grep -v grep")
print(stdout.read().decode('utf-8', errors='ignore'))

# Automatically adjust bot/scanner priorities
print("[*] Aligning execution nice values...")
ssh.exec_command("renice -n 19 -p $(pgrep -f recon_master.py) 2>/dev/null || true")
ssh.exec_command("renice -n -5 -p $(pgrep -f discord_bot.py) 2>/dev/null || true")

ssh.close()
print("[+] Deploy complete! The pipeline will now skip finished targets and process pending domains sequentially.")
