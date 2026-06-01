import paramiko
import os

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"
LOCAL_ENV = r"src\.env"
REMOTE_ENV = "/root/recon-tools/src/.env"

print("[*] Connecting to VPS...")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(IP, username=USER, password=PASS, timeout=10, look_for_keys=False, allow_agent=False)

print("[*] Uploading local .env to VPS...")
sftp = ssh.open_sftp()
sftp.put(LOCAL_ENV, REMOTE_ENV)
sftp.close()
print("[+] .env synced successfully!")

# Restart bot service
print("[*] Restarting recon-bot service...")
stdin, stdout, stderr = ssh.exec_command("systemctl restart recon-bot")
stdout.channel.recv_exit_status()

# Check bot status
stdin, stdout, stderr = ssh.exec_command("systemctl is-active recon-bot")
print(f"[+] Bot status: {stdout.read().decode().strip()}")

ssh.close()
print("[+] Sync complete!")
