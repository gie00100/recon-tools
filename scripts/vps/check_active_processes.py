import paramiko

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"

print("[*] Connecting to VPS...")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(IP, username=USER, password=PASS, timeout=10, look_for_keys=False, allow_agent=False)

print("=== Active Screen Sessions ===")
stdin, stdout, stderr = ssh.exec_command("screen -ls")
print(stdout.read().decode('utf-8', errors='ignore'))

print("=== Active Recon Processes ===")
stdin, stdout, stderr = ssh.exec_command("ps aux | grep -E 'python|recon|run' | grep -v grep")
print(stdout.read().decode('utf-8', errors='ignore'))

print("=== Free Memory ===")
stdin, stdout, stderr = ssh.exec_command("free -h")
print(stdout.read().decode('utf-8', errors='ignore'))

print("=== CPU Usage ===")
stdin, stdout, stderr = ssh.exec_command("top -b -n 1 | head -n 20")
print(stdout.read().decode('utf-8', errors='ignore'))

ssh.close()
