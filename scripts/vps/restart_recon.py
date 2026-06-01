import paramiko
import time

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"

print("[*] Connecting to VPS...")
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
        print(f"    {out[:500]}")
    if err and exit_code != 0:
        print(f"    ERR: {err[:300]}")
    return out

# Step 1: Kill old processes and screen sessions
print("[*] Cleaning up old processes...")
run("pkill -f run_recon.sh || true")
run("pkill -f run_bulk.sh || true")
run("pkill -f recon_master.py || true")
run("for s in $(screen -ls | grep -oP '\\d+\\.recon\\S+'); do screen -S $s -X quit; done || true")
time.sleep(2)

# Step 2: Relaunch sequentially under fresh screen session
print("[*] Launching fresh memory-safe sequential bulk recon...")
run("cd /root/recon-tools && rm -f /tmp/recon_chunk_*.txt")
run('cd /root/recon-tools && screen -dmS recon_main bash -c "./run_bulk.sh ui_targets.txt; echo DONE; sleep 3600"')
time.sleep(3)

# Step 3: Verify execution
print("\n[*] Verifying active screens and processes:")
run("screen -ls")
run("ps aux | grep recon | grep -v grep")

ssh.close()
print("[+] Recon restarted successfully under fresh environment!")
