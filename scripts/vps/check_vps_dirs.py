import paramiko

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"

print("[*] Connecting to VPS...")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(IP, username=USER, password=PASS, timeout=10, look_for_keys=False, allow_agent=False)

print("[*] Checking output directories on VPS...")
stdin, stdout, stderr = ssh.exec_command("ls -lat /root/recon-tools/output/")
print(stdout.read().decode('utf-8', errors='ignore'))

ssh.close()
