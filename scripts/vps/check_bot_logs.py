import paramiko

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"

print("[*] Connecting to VPS...")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(IP, username=USER, password=PASS, timeout=10, look_for_keys=False, allow_agent=False)

print("[*] Checking systemd journal for recon-bot service logs...")
stdin, stdout, stderr = ssh.exec_command("journalctl -u recon-bot -n 50 --no-pager 2>&1")
logs = stdout.read().decode(errors='ignore')
print("=== LOGS ===")
print(logs)

ssh.close()
