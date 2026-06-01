import paramiko
import time

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"

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
        safe_out = out.encode('ascii', errors='ignore').decode('ascii')
        print(f"    {safe_out[:500]}")
    if err and exit_code != 0:
        safe_err = err.encode('ascii', errors='ignore').decode('ascii')
        print(f"    ERR: {safe_err[:300]}")
    return out

# Upload files
print("[*] Uploading files...")
sftp = ssh.open_sftp()
sftp.put("src/discord_bot.py", "/root/recon-tools/src/discord_bot.py")
sftp.put("src/recon_master.py", "/root/recon-tools/src/recon_master.py")
sftp.put("src/recon/config.py", "/root/recon-tools/src/recon/config.py")
sftp.put("src/recon/live_probe.py", "/root/recon-tools/src/recon/live_probe.py")
sftp.put("src/recon/bounty_scanner.py", "/root/recon-tools/src/recon/bounty_scanner.py")
sftp.put("src/requirements.txt", "/root/recon-tools/src/requirements.txt")
sftp.put("recon-bot.service", "/etc/systemd/system/recon-bot.service")
sftp.close()
print("[+] Files uploaded!")

# Install requirements including discord.py and dnspython
run("cd /root/recon-tools && ./venv/bin/pip install -r src/requirements.txt", "Installing dependencies...")

# Enable and start the bot service
run("systemctl daemon-reload", "Reloading systemd...")
run("systemctl enable recon-bot", "Enabling bot service...")
run("systemctl restart recon-bot", "Starting bot service...")
time.sleep(3)

# Check status
status = run("systemctl status recon-bot --no-pager -l", "Checking bot status...")

ssh.close()
print("\n[+] Discord Bot deployed and running!")
