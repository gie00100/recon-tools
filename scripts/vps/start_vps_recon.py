import paramiko
import sys
import os

# Resolve project root (two levels up from scripts/vps/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"

def start_parallel(targets_file="ui_targets.txt", max_workers=5):
    print(f"[*] Connecting to {IP} via SSH...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(IP, username=USER, password=PASS, timeout=10, look_for_keys=False, allow_agent=False)
        print("[+] Connected successfully!")
        
        # Kill existing recon sessions (tmux + screen)
        print("[*] Cleaning up old sessions...")
        ssh.exec_command('tmux kill-session -t bulk_recon 2>/dev/null')
        ssh.exec_command('pkill -f run_bulk.sh 2>/dev/null')
        ssh.exec_command('pkill -f run_recon.sh 2>/dev/null')
        # Clean old chunk files
        ssh.exec_command('rm -f /tmp/recon_chunk_*.txt')
        import time; time.sleep(2)
        
        # Upload targets file
        sftp = ssh.open_sftp()
        local_path = os.path.join(PROJECT_ROOT, "targets", targets_file)
        print(f"[*] Uploading {local_path}...")
        sftp.put(local_path, f"/root/recon-tools/{targets_file}")
        sftp.close()
        
        # Make sure screen is installed
        stdin, stdout, stderr = ssh.exec_command('which screen || apt-get install -y screen')
        stdout.channel.recv_exit_status()
        
        # Launch parallel runner
        cmd = f'cd /root/recon-tools && chmod +x run_parallel.sh && ./run_parallel.sh {targets_file} {max_workers}'
        print(f"[*] Launching: {cmd}")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        
        output = stdout.read().decode(errors='ignore')
        errors = stderr.read().decode(errors='ignore')
        
        print(output)
        if errors:
            print(f"[!] Stderr: {errors}")
            
        # Verify screen sessions
        stdin, stdout, stderr = ssh.exec_command('screen -ls')
        print("\n[*] Active screen sessions:")
        print(stdout.read().decode(errors='ignore'))
            
    except Exception as e:
        print(f"\n[!] Error: {e}")
    finally:
        ssh.close()

if __name__ == "__main__":
    targets = sys.argv[1] if len(sys.argv) > 1 else "ui_targets.txt"
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    start_parallel(targets, workers)
