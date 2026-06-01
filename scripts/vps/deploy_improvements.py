import paramiko
import time

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"

print("[*] Connecting to VPS...")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(IP, username=USER, password=PASS, timeout=10)

print("[*] Uploading improved files to VPS...")
sftp = ssh.open_sftp()
sftp.put("src/recon/backup_gen.py", "/root/recon-tools/src/recon/backup_gen.py")
sftp.put("src/recon/cred_hunter.py", "/root/recon-tools/src/recon/cred_hunter.py")
sftp.put("src/recon_master.py", "/root/recon-tools/src/recon_master.py")
sftp.close()
print("[+] Improved files uploaded successfully!")

print("[*] Killing existing active scan session to reload new code...")
ssh.exec_command("pkill -f run_recon.sh || true")
ssh.exec_command("pkill -f run_bulk.sh || true")
ssh.exec_command("pkill -f recon_master.py || true")
ssh.exec_command("pkill -f waymore || true")
ssh.exec_command("for s in $(screen -ls | grep -oP '\\d+\\.recon\\S+'); do screen -S $s -X quit; done || true")
time.sleep(2)

print("[*] Restarting clean sequential bulk recon with improvements active...")
ssh.exec_command("cd /root/recon-tools && rm -f /tmp/recon_chunk_*.txt")
ssh.exec_command('cd /root/recon-tools && screen -dmS recon_main bash -c "./run_bulk.sh ui_targets.txt; echo DONE; sleep 3600"')
time.sleep(3)

print("\n[*] Verifying restarted processes and CPU priorities:")
stdin, stdout, stderr = ssh.exec_command("ps -eo pid,ni,args | grep -E 'python|run_' | grep -v grep")
print(stdout.read().decode('utf-8', errors='ignore'))

# Automatically prioritize the bot vs scanner nice levels
print("[*] Adjusting nice priorities...")
ssh.exec_command("renice -n 19 -p $(pgrep -f recon_master.py) 2>/dev/null || true")
ssh.exec_command("renice -n -5 -p $(pgrep -f discord_bot.py) 2>/dev/null || true")

ssh.close()
print("[+] Deploy and restart complete! The pipeline is now fully active with false-positive filtering.")
