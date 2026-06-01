import paramiko

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"

print("[*] Connecting to VPS...")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(IP, username=USER, password=PASS, timeout=10, look_for_keys=False, allow_agent=False)

print("[*] Checking /root/recon-tools/src/.env contents on VPS...")
stdin, stdout, stderr = ssh.exec_command("cat /root/recon-tools/src/.env")
print("=== VPS .env ===")
text = stdout.read().decode('utf-8', errors='ignore')
safe_text = text.encode('ascii', errors='ignore').decode('ascii')
print(safe_text)

ssh.close()
