import paramiko

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"

print("[*] Connecting to VPS...")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(IP, username=USER, password=PASS, timeout=10, look_for_keys=False, allow_agent=False)

print("[*] Reprioritizing all running recon processes with renice...")
commands = [
    "renice -n 19 -p $(pgrep -f recon_master.py) 2>/dev/null || true",
    "renice -n 19 -p $(pgrep -f run_recon.sh) 2>/dev/null || true",
    "renice -n 19 -p $(pgrep -f run_bulk.sh) 2>/dev/null || true",
    "renice -n -5 -p $(pgrep -f discord_bot.py) 2>/dev/null || true"
]

for cmd in commands:
    stdin, stdout, stderr = ssh.exec_command(cmd)
    stdout.channel.recv_exit_status()

# Verify priorities
print("\n[*] Active process priorities (NI column, higher = lower priority):")
stdin, stdout, stderr = ssh.exec_command("ps -eo pid,ni,args | grep -E 'python|run_' | grep -v grep")
print(stdout.read().decode('utf-8', errors='ignore'))

ssh.close()
print("[+] Done! Process execution priorities adjusted dynamically.")
