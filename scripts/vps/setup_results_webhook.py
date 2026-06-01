import paramiko
import time

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"
RESULTS_WEBHOOK = "https://discord.com/api/webhooks/1510547434994925729/cktwmqCpTHBuaiWEdRzhSiQ-01cKo8owCNScIqVDucx1UPy-fggchK2nmlQIsyQatFKV"

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(IP, username=USER, password=PASS, timeout=10, look_for_keys=False, allow_agent=False)

# Add/Update DISCORD_RESULTS_WEBHOOK_URL in .env
print("[*] Adding DISCORD_RESULTS_WEBHOOK_URL to VPS .env...")
cmd = f'grep -q "DISCORD_RESULTS_WEBHOOK_URL" /root/recon-tools/src/.env && sed -i "s|\\(^DISCORD_RESULTS_WEBHOOK_URL=\\).*|\\1{RESULTS_WEBHOOK}|" /root/recon-tools/src/.env || echo "DISCORD_RESULTS_WEBHOOK_URL={RESULTS_WEBHOOK}" >> /root/recon-tools/src/.env'
stdin, stdout, stderr = ssh.exec_command(cmd)
stdout.channel.recv_exit_status()

# Verify it's in the file
stdin, stdout, stderr = ssh.exec_command('grep DISCORD_RESULTS_WEBHOOK_URL /root/recon-tools/src/.env')
print(f"[+] .env entry: {stdout.read().decode(errors='ignore').strip()}")

# Restart the bot service
print("[*] Restarting recon-bot service...")
stdin, stdout, stderr = ssh.exec_command('systemctl restart recon-bot')
stdout.channel.recv_exit_status()

time.sleep(3)

# Check status
stdin, stdout, stderr = ssh.exec_command('systemctl is-active recon-bot')
status = stdout.read().decode(errors='ignore').strip()
print(f"[+] Bot status: {status}")

ssh.close()
print("[+] Done!")
