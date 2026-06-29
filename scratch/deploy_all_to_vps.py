import paramiko
import os
import sys

def deploy():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print("Connecting to VPS...")
    ssh.connect('134.209.72.156', username='root', password='Kingo@123Kingo', timeout=10)
    
    sftp = ssh.open_sftp()
    
    files_to_upload = [
        'src/discord_bot.py',
        'src/recon/bounty_scanner.py',
        'src/recon_master.py',
        'scripts/vps/run_watchlist.py',
        'targets/targets.txt',
        'targets/watchlist.txt'
    ]
    
    for f in files_to_upload:
        local_path = f
        remote_path = f'/root/recon-tools/{f}'
        print(f"Uploading {local_path} -> {remote_path}")
        try:
            sftp.put(local_path, remote_path)
        except Exception as e:
            print(f"Failed to upload {local_path}: {e}")
            
    sftp.close()
    
    # Restart the discord bot if it's running
    print("Restarting discord_bot screen session...")
    ssh.exec_command("screen -S discord_bot -X quit")
    ssh.exec_command("cd /root/recon-tools && screen -dmS discord_bot bash -c 'source venv/bin/activate && python3 src/discord_bot.py 2>&1 | tee discord_bot.log'")
    
    ssh.close()
    print("Deploy complete!")

if __name__ == "__main__":
    deploy()
