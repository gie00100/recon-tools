import paramiko
import time

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(IP, username=USER, password=PASS, timeout=10, look_for_keys=False, allow_agent=False)

# Step 1: Add 2GB swap
print("[*] Creating 2GB swap file...")
commands = [
    "fallocate -l 2G /swapfile",
    "chmod 600 /swapfile",
    "mkswap /swapfile",
    "swapon /swapfile",
    "echo '/swapfile none swap sw 0 0' >> /etc/fstab",
    "sysctl vm.swappiness=60",
]

for cmd in commands:
    print(f"  -> {cmd}")
    stdin, stdout, stderr = ssh.exec_command(cmd)
    exit_code = stdout.channel.recv_exit_status()
    err = stderr.read().decode(errors='ignore').strip()
    if exit_code != 0 and err:
        print(f"     WARN: {err}")

# Verify
print("\n[*] Verifying swap...")
stdin, stdout, stderr = ssh.exec_command("free -h")
print(stdout.read().decode(errors='ignore'))

# Step 2: Clean up old failed output dirs and chunk files
print("[*] Cleaning up failed output dirs...")
ssh.exec_command("rm -f /tmp/recon_chunk_*.txt")

# Step 3: Re-launch with 2 workers instead of 5
print("[*] Re-launching parallel recon with 2 workers...")
cmd = 'cd /root/recon-tools && chmod +x run_parallel.sh && ./run_parallel.sh ui_targets.txt 2'
stdin, stdout, stderr = ssh.exec_command(cmd)
output = stdout.read().decode(errors='ignore')
print(output)

# Verify screen sessions
print("[*] Verifying screen sessions...")
stdin, stdout, stderr = ssh.exec_command("screen -ls")
print(stdout.read().decode(errors='ignore'))

ssh.close()
print("[+] Done! Workers relaunched with swap protection.")
