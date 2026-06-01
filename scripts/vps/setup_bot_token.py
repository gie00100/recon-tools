import paramiko

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"
BOT_TOKEN = "MTUxMDUzODAzMTQ0NTE4MDQ4Ng.GaS8sI.uLjhxXNNO30In483tR0ez4Z4N6rFyWCNxCAN8w"

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(IP, username=USER, password=PASS, timeout=10, look_for_keys=False, allow_agent=False)

# Add DISCORD_BOT_TOKEN to .env
print("[*] Adding DISCORD_BOT_TOKEN to .env...")
stdin, stdout, stderr = ssh.exec_command(f'grep -q "DISCORD_BOT_TOKEN" /root/recon-tools/src/.env && sed -i "s|^DISCORD_BOT_TOKEN=.*|DISCORD_BOT_TOKEN={BOT_TOKEN}|" /root/recon-tools/src/.env || echo "DISCORD_BOT_TOKEN={BOT_TOKEN}" >> /root/recon-tools/src/.env')
stdout.channel.recv_exit_status()

# Verify it's in the file
stdin, stdout, stderr = ssh.exec_command('grep DISCORD_BOT_TOKEN /root/recon-tools/src/.env')
print(f"[+] .env entry: {stdout.read().decode(errors='ignore').strip()[:30]}...")

# Restart the bot service
print("[*] Restarting recon-bot service...")
stdin, stdout, stderr = ssh.exec_command('systemctl restart recon-bot')
stdout.channel.recv_exit_status()

import time
time.sleep(5)

# Check status
stdin, stdout, stderr = ssh.exec_command('systemctl is-active recon-bot')
status = stdout.read().decode(errors='ignore').strip()
print(f"[+] Bot status: {status}")

# Check logs
stdin, stdout, stderr = ssh.exec_command('journalctl -u recon-bot -n 15 --no-pager 2>&1')
logs = stdout.read().decode(errors='ignore')
# Filter for relevant lines
for line in logs.split('\n'):
    if 'python' in line or 'Bot' in line or 'logged' in line or 'error' in line.lower() or 'token' in line.lower() or 'DISCORD' in line:
        print(f"    {line.strip()}")

# Also check screen sessions
stdin, stdout, stderr = ssh.exec_command('screen -ls 2>&1')
print(f"\n[*] Screen sessions:\n{stdout.read().decode(errors='ignore')}")

ssh.close()
print("[+] Done!")
