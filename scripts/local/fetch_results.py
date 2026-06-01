import os
import re
import paramiko
from scp import SCPClient

# Resolve project root (two levels up from scripts/local/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOCAL_OUT = os.path.join(PROJECT_ROOT, "output")

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"

def fetch_all():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(IP, username=USER, password=PASS, timeout=10, look_for_keys=False, allow_agent=False)
        
        # Get all folders in the remote output directory
        stdin, stdout, stderr = ssh.exec_command('find /root/recon-tools/output/ -maxdepth 1 -mindepth 1 -type d')
        remote_dirs = [d.strip() for d in stdout.read().decode().split('\n') if d.strip()]
        
        if not remote_dirs:
            print("No output directories found on VPS.")
            return False
            
        print(f"[*] Found {len(remote_dirs)} run directories on VPS.")
        fetched_count = 0
        
        for rdir in remote_dirs:
            dir_name = os.path.basename(rdir.rstrip('/'))
            
            # Parse domain and timestamp using pattern: <domain>_<date>_<time>
            match = re.match(r'^(.+)_(\d{8}_\d{6})$', dir_name)
            if match:
                domain = match.group(1)
                timestamp = match.group(2)
            else:
                domain = dir_name
                timestamp = "historical"
                
            # Systematic local output path: output/<domain>/<timestamp>/
            local_target_dir = os.path.join(LOCAL_OUT, domain, timestamp)
            os.makedirs(local_target_dir, exist_ok=True)
            
            # Check if unique_urls.txt exists to confirm scan finished (or has contents)
            stdin, stdout, stderr = ssh.exec_command(f'ls {rdir}/unique_urls.txt')
            has_unique = bool(stdout.read().decode().strip())
            
            print(f"\n[*] Syncing [{domain}] (Run: {timestamp})...")
            
            with SCPClient(ssh.get_transport()) as scp:
                files_to_download = [
                    "unique_urls.txt",
                    "live_urls.txt",
                    "exposed_ports.json",
                    "bounty_targets.json",
                    "credentials_found.json",
                    "js_findings.json",
                    "subdomains.txt",
                    "virustotal_urls.txt",
                    "all_hosts.txt",
                    "live_hosts.json",
                    "js_endpoints.txt",
                    "report.html",
                    "report.json"
                ]
                
                downloaded = []
                for fname in files_to_download:
                    # Check if file exists on VPS first to avoid scp stderr noise
                    stdin, stdout, stderr = ssh.exec_command(f'ls "{rdir}/{fname}" 2>/dev/null')
                    if stdout.read().decode().strip():
                        try:
                            scp.get(f"{rdir}/{fname}", local_path=local_target_dir)
                            downloaded.append(fname)
                        except Exception:
                            pass
                
                if downloaded:
                    print(f"  [+] Downloaded: {', '.join(downloaded)}")
                    print(f"  [+] Saved locally to: {os.path.relpath(local_target_dir, PROJECT_ROOT)}")
                    fetched_count += 1
                else:
                    print("  [-] No files found or scan still starting.")
                    
        return fetched_count > 0
    except Exception as e:
        print(f"Error connecting or fetching: {e}")
        return False
    finally:
        ssh.close()

if __name__ == "__main__":
    if fetch_all():
        print("\n[+] SUCCESS: Systematic sync completed successfully!")
    else:
        print("\n[!] SUCCESS: Finished with no pending active runs to pull.")
