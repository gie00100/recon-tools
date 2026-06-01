import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('134.209.72.156', username='root', password='Kingo@123Kingo', timeout=10, look_for_keys=False, allow_agent=False)

# Check screen sessions
stdin, stdout, stderr = ssh.exec_command('screen -ls')
print("=== Screen Sessions ===")
print(stdout.read().decode(errors='ignore'))

# Check recon processes  
stdin, stdout, stderr = ssh.exec_command('ps aux | grep recon | grep -v grep')
print("=== Recon Processes ===")
out = stdout.read().decode(errors='ignore')
print(out if out.strip() else "None running")

# Check bot is alive
stdin, stdout, stderr = ssh.exec_command('systemctl is-active recon-bot')
print(f"\n=== Bot Status: {stdout.read().decode(errors='ignore').strip()} ===")

# Check output dirs with completed scans
stdin, stdout, stderr = ssh.exec_command('for d in /root/recon-tools/output/*/; do f=$(ls "$d" | wc -l); echo "$d -> $f files"; done')
print("\n=== Output Dirs ===")
print(stdout.read().decode(errors='ignore'))

ssh.close()
