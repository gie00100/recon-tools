#!/usr/bin/env python3
"""
VPS Deploy via SFTP — uploads code directly, no git needed.
"""

import paramiko
import configparser
import os
import time

def run_cmd(ssh, cmd, timeout=120):
    """Execute command on remote and print output."""
    print(f"\n  $ {cmd}")
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode(errors='ignore').strip()
    err = stderr.read().decode(errors='ignore').strip()
    if out:
        for line in out.split('\n')[:20]:
            print(f"    {line}")
    if err and 'WARNING' not in err:
        for line in err.split('\n')[:10]:
            print(f"    [stderr] {line}")
    return out


def sftp_upload_dir(sftp, local_dir, remote_dir, skip_dirs=None):
    """Recursively upload a directory via SFTP."""
    skip_dirs = skip_dirs or set()
    uploaded = 0

    for item in os.listdir(local_dir):
        local_path = os.path.join(local_dir, item)
        remote_path = f"{remote_dir}/{item}"

        if item in skip_dirs or item.startswith('.'):
            continue

        if os.path.isdir(local_path):
            try:
                sftp.mkdir(remote_path)
            except IOError:
                pass  # Already exists
            uploaded += sftp_upload_dir(sftp, local_path, remote_path, skip_dirs)
        else:
            try:
                sftp.put(local_path, remote_path)
                uploaded += 1
            except Exception as e:
                print(f"    [!] Failed: {remote_path}: {e}")

    return uploaded


def main():
    # Load config
    config = configparser.ConfigParser()
    config.read('vps_config.ini')
    host = config['vps']['host']
    user = config['vps']['user']
    password = config['vps']['password']
    port = int(config['vps']['port'])
    remote_path = config['vps']['remote_path']

    print(f"[*] Connecting to {user}@{host}:{port}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port=port, username=user, password=password, timeout=30)
    print("[+] Connected!")

    # Step 1: Check current state
    print("\n=== STEP 1: Check VPS State ===")
    run_cmd(ssh, "df -h / | tail -1")
    run_cmd(ssh, f"ls {remote_path}/src/recon/bounty_scanner.py 2>/dev/null || echo 'No source code found'")

    # Step 2: Create remote directory structure
    print("\n=== STEP 2: Upload Source Code via SFTP ===")
    sftp = ssh.open_sftp()

    # Create dirs
    for d in ['src', 'src/recon', 'scripts', 'targets']:
        try:
            sftp.mkdir(f"{remote_path}/{d}")
        except IOError:
            pass

    # Upload src/
    print("  Uploading src/...")
    count = sftp_upload_dir(sftp, 'd:/recon-tool/src', f'{remote_path}/src',
                            skip_dirs={'output', '__pycache__', '.pyc'})
    print(f"    Uploaded {count} files to src/")

    # Upload scripts/
    print("  Uploading scripts/...")
    count = sftp_upload_dir(sftp, 'd:/recon-tool/scripts', f'{remote_path}/scripts',
                            skip_dirs={'__pycache__'})
    print(f"    Uploaded {count} files to scripts/")

    # Upload key root files
    print("  Uploading root files...")
    for f in ['requirements.txt', 'run_recon.sh', 'run_bulk.sh']:
        local = f'd:/recon-tool/{f}'
        if os.path.exists(local):
            sftp.put(local, f'{remote_path}/{f}')
            print(f"    {f}")

    # Upload targets (merge, don't overwrite)
    print("  Uploading targets/...")
    count = sftp_upload_dir(sftp, 'd:/recon-tool/targets', f'{remote_path}/targets')
    print(f"    Uploaded {count} files to targets/")

    sftp.close()

    # Step 3: Setup venv if missing
    print("\n=== STEP 3: Setup Python Environment ===")
    venv_check = run_cmd(ssh, f"test -f {remote_path}/venv/bin/activate && echo 'exists' || echo 'missing'")
    if 'missing' in venv_check:
        print("  Creating venv...")
        run_cmd(ssh, f"python3 -m venv {remote_path}/venv", timeout=60)

    run_cmd(ssh, f"cd {remote_path} && source venv/bin/activate && pip install -r requirements.txt -q 2>&1 | tail -5", timeout=120)

    # Step 4: Verify
    print("\n=== STEP 4: Verify ===")
    run_cmd(ssh, f"cd {remote_path} && source venv/bin/activate && python -c 'from recon.bounty_scanner import BountyScanner; print(\"Scanner loaded: \" + str(len(BountyScanner._heuristics_count()) if hasattr(BountyScanner, \"_heuristics_count\") else \"OK\"))'")
    run_cmd(ssh, f"head -8 {remote_path}/src/recon/bounty_scanner.py")
    run_cmd(ssh, f"chmod +x {remote_path}/run_recon.sh 2>/dev/null; echo done")
    run_cmd(ssh, "df -h / | tail -1")

    # Step 5: Kill old, start new scans
    print("\n=== STEP 5: Start Scans ===")
    run_cmd(ssh, "pkill -f recon_master.py 2>/dev/null; sleep 1; echo 'Old processes killed'")

    run_cmd(ssh, f"screen -dmS recon_wix bash -c 'cd {remote_path} && source venv/bin/activate && python src/recon_master.py -d wix.com -o {remote_path}/output --full --active 2>&1 | tee /root/recon_wix.log'")
    time.sleep(3)
    run_cmd(ssh, f"screen -dmS recon_ebay bash -c 'cd {remote_path} && source venv/bin/activate && python src/recon_master.py -d ebay.com -o {remote_path}/output --full --active 2>&1 | tee /root/recon_ebay.log'")
    time.sleep(3)

    run_cmd(ssh, "screen -ls")
    run_cmd(ssh, "pgrep -af recon_master || echo 'No recon processes found'")

    print("\n" + "=" * 50)
    print("  DEPLOYMENT COMPLETE")
    print("  wix.com + ebay.com scans launched")
    print("  Monitor: !status on Discord")
    print("=" * 50)

    ssh.close()


if __name__ == "__main__":
    main()
