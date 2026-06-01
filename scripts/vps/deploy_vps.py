import os
import zipfile
import paramiko
from scp import SCPClient
from pathlib import Path

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"
LOCAL_DIR = r"c:\Users\pg001\OneDrive\Desktop\tools"
ZIP_NAME = "recon-tools.zip"

def create_zip():
    print("[*] Creating zip archive, excluding venv, __pycache__, and output...")
    with zipfile.ZipFile(ZIP_NAME, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(LOCAL_DIR):
            # Exclude unwanted directories
            dirs[:] = [d for d in dirs if d not in ('venv', '__pycache__', 'output', '.git')]
            for file in files:
                if file == ZIP_NAME: continue
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, LOCAL_DIR)
                zipf.write(full_path, rel_path)
    print(f"[+] Created {ZIP_NAME} ({os.path.getsize(ZIP_NAME) // 1024} KB)")

def progress(filename, size, sent):
    print(f"\r[*] Uploading {filename.decode()}... {sent}/{size} bytes", end="")

def deploy():
    create_zip()
    
    print(f"\n[*] Connecting to {IP} via SSH...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(IP, username=USER, password=PASS, timeout=10)
        print("[+] Connected successfully!")
        
        # Upload
        print("[*] Uploading toolkit archive...")
        with SCPClient(ssh.get_transport(), progress=progress) as scp:
            scp.put(ZIP_NAME, remote_path="/root/")
        print("\n[+] Upload complete.")
        
        # Unzip and run setup
        print("[*] Executing remote setup (this may take a few minutes)...")
        commands = [
            "apt-get update && apt-get install -y unzip",
            "mkdir -p /root/recon-tools",
            "unzip -o /root/recon-tools.zip -d /root/recon-tools",
            "cd /root/recon-tools && chmod +x setup_vps.sh run_recon.sh run_bulk.sh",
            "cd /root/recon-tools && ./setup_vps.sh"
        ]
        
        command_str = " && ".join(commands)
        stdin, stdout, stderr = ssh.exec_command(command_str)
        
        # Read lines one by one to show progress
        stdout.channel.set_combine_stderr(True)
        for line in stdout:
            safe_line = line.encode('ascii', errors='ignore').decode('ascii')
            print(safe_line, end="")
            
        print("\n[+] VPS Setup completed!")
        print("\n[!] The toolkit is now installed on your Droplet!")
        print("[!] You can SSH into your Droplet, navigate to /root/recon-tools, and run:")
        print("    tmux new -s recon")
        print("    ./run_recon.sh <target.com>")
        
    except Exception as e:
        print(f"\n[!] Error during deployment: {e}")
    finally:
        ssh.close()
        if os.path.exists(ZIP_NAME):
            os.remove(ZIP_NAME)

if __name__ == "__main__":
    deploy()
