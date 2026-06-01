import paramiko

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"

print("[*] Connecting to VPS...")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(IP, username=USER, password=PASS, timeout=10, look_for_keys=False, allow_agent=False)

print("[*] Uploading fixed run_recon.sh and run_bulk.sh...")
sftp = ssh.open_sftp()
sftp.put("run_recon.sh", "/root/recon-tools/run_recon.sh")
sftp.put("run_bulk.sh", "/root/recon-tools/run_bulk.sh")
sftp.close()

# Fix permissions and clean up CRLF in targets on the VPS
commands = [
    "chmod +x /root/recon-tools/run_recon.sh /root/recon-tools/run_bulk.sh",
    "sed -i 's/\\r$//' /root/recon-tools/ui_targets.txt /root/recon-tools/targets.txt 2>/dev/null || true",
    "sed -i 's/\\r$//' /root/recon-tools/targets/*.txt 2>/dev/null || true"
]

print("[*] Running post-deploy script cleaning commands...")
for cmd in commands:
    stdin, stdout, stderr = ssh.exec_command(cmd)
    stdout.channel.recv_exit_status()

ssh.close()
print("[+] Sync and post-cleaning complete!")
