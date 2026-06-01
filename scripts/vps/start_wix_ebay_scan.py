import paramiko
import time

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"

print("[*] Connecting to VPS...")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(IP, username=USER, password=PASS, timeout=10, look_for_keys=False, allow_agent=False)

# Step 1: Upload the new targets file
print("[*] Uploading wix_ebay_targets.txt to VPS...")
sftp = ssh.open_sftp()
sftp.put("targets/wix_ebay_targets.txt", "/root/recon-tools/wix_ebay_targets.txt")
sftp.close()
print("[+] Targets file uploaded successfully!")

# Step 2: Kill any old running scan sessions
print("[*] Cleaning up old scan sessions...")
ssh.exec_command("pkill -f run_recon.sh || true")
ssh.exec_command("pkill -f run_bulk.sh || true")
ssh.exec_command("pkill -f recon_master.py || true")
ssh.exec_command("pkill -f waymore || true")
ssh.exec_command("for s in $(screen -ls | grep -oP '\\d+\\.recon\\S+'); do screen -S $s -X quit; done || true")
time.sleep(2)

# Step 3: Launch fresh sequential bulk recon
print("[*] Launching bulk recon for Wix + eBay targets...")
ssh.exec_command('cd /root/recon-tools && screen -dmS recon_main bash -c "./run_bulk.sh wix_ebay_targets.txt; echo DONE; sleep 3600"')
time.sleep(4)

# Step 4: Verify processes started
print("\n[*] Verifying active processes:")
stdin, stdout, stderr = ssh.exec_command("ps -eo pid,ni,args | grep -E 'python|run_' | grep -v grep")
print(stdout.read().decode('utf-8', errors='ignore'))

# Step 5: Adjust nice priorities
print("[*] Setting CPU priorities (bot=-5, scanner=19)...")
ssh.exec_command("renice -n 19 -p $(pgrep -f recon_master.py) 2>/dev/null || true")
ssh.exec_command("renice -n -5 -p $(pgrep -f discord_bot.py) 2>/dev/null || true")

# Step 6: Count targets
stdin, stdout, stderr = ssh.exec_command("grep -v '^#' /root/recon-tools/wix_ebay_targets.txt | grep -v '^$' | wc -l")
target_count = stdout.read().decode().strip()
print(f"\n[+] Scan launched! Total targets to process: {target_count}")

ssh.close()
print("[+] Deploy and start complete! The pipeline is now scanning Wix + eBay targets sequentially.")
