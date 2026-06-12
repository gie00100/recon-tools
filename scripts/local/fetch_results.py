import os
import re
import sys
import paramiko
from scp import SCPClient

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Resolve project root (two levels up from scripts/local/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOCAL_OUT = os.path.join(PROJECT_ROOT, "output")

IP = "134.209.72.156"
USER = "root"
PASS = "Kingo@123Kingo"

# Files to always fetch (small — direct SCP)
SMALL_FILES = [
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
    "report.json",
]

# Large files that may need chunked transfer (> SIZE_THRESHOLD bytes)
# Fetched via SSH cat + chunked read rather than SCP to avoid timeouts
LARGE_FILES = [
    "unique_urls.txt",
    "waymore_urls.txt",
]

# If a file is larger than this (50 MB), use chunked SSH streaming instead of SCP
SIZE_THRESHOLD = 50 * 1024 * 1024  # 50 MB

# Chunk size for reading large files over SSH (4 MB per read)
CHUNK_SIZE = 4 * 1024 * 1024


def _remote_file_size(ssh, remote_path: str) -> int:
    """Return file size in bytes, or -1 if file doesn't exist."""
    stdin, stdout, stderr = ssh.exec_command(
        f'stat -c%s "{remote_path}" 2>/dev/null || echo -1'
    )
    result = stdout.read().decode().strip()
    try:
        return int(result)
    except ValueError:
        return -1


def _fetch_small(scp, remote_path: str, local_dir: str, fname: str) -> bool:
    """Download a file via SCP. Returns True on success."""
    try:
        scp.get(remote_path, local_path=local_dir)
        return True
    except Exception as e:
        print(f"    [!] SCP failed for {fname}: {e}")
        return False


def _fetch_large_chunked(ssh, remote_path: str, local_path: str, fname: str, file_size: int) -> bool:
    """
    Stream a large file from the VPS in chunks using SSH 'dd' commands.
    This avoids SCP timeouts on very large files (100MB+) by reading
    fixed-size blocks and writing them locally one at a time.
    """
    mb = file_size / (1024 * 1024)
    print(f"    [~] Large file ({mb:.1f} MB) — using chunked SSH transfer...")

    local_tmp = local_path + ".part"
    try:
        written = 0
        chunk_num = 0
        with open(local_tmp, 'wb') as f:
            while written < file_size:
                skip_bytes = written
                count = min(CHUNK_SIZE, file_size - written)
                # Use dd to extract exactly 'count' bytes starting at 'skip_bytes'
                cmd = (
                    f'dd if="{remote_path}" bs=1 skip={skip_bytes} count={count} 2>/dev/null'
                )
                stdin, stdout, stderr = ssh.exec_command(cmd)
                chunk_data = stdout.read()
                if not chunk_data:
                    print(f"    [!] Empty chunk at offset {skip_bytes} — stopping.")
                    break
                f.write(chunk_data)
                written += len(chunk_data)
                chunk_num += 1
                pct = (written / file_size) * 100
                print(f"    [~] Chunk {chunk_num}: {written/(1024*1024):.1f}/{mb:.1f} MB ({pct:.0f}%)")

        if written >= file_size * 0.99:  # Allow 1% tolerance for rounding
            os.replace(local_tmp, local_path)
            print(f"    [+] Chunked transfer complete: {fname} ({written/(1024*1024):.1f} MB)")
            return True
        else:
            print(f"    [!] Incomplete transfer: got {written} / {file_size} bytes")
            if os.path.exists(local_tmp):
                os.remove(local_tmp)
            return False
    except Exception as e:
        print(f"    [!] Chunked transfer failed for {fname}: {e}")
        if os.path.exists(local_tmp):
            os.remove(local_tmp)
        return False


def _fetch_file(ssh, scp, remote_dir: str, local_dir: str, fname: str) -> bool:
    """
    Fetch a single file from the VPS.
    - Checks if file exists remotely
    - Checks if already downloaded locally (skips if same size)
    - Routes to SCP (small) or chunked SSH (large)
    """
    remote_path = f"{remote_dir}/{fname}"
    local_path = os.path.join(local_dir, fname)

    # Check file exists on VPS
    remote_size = _remote_file_size(ssh, remote_path)
    if remote_size < 0:
        return False  # File doesn't exist

    # Skip if already fully downloaded (same size)
    if os.path.exists(local_path):
        local_size = os.path.getsize(local_path)
        if local_size == remote_size:
            return True  # Already have it, skip silently

    # Route based on size
    if remote_size > SIZE_THRESHOLD:
        return _fetch_large_chunked(ssh, remote_path, local_path, fname, remote_size)
    else:
        return _fetch_small(scp, remote_path, local_dir, fname)


def fetch_all():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print(f"[*] Connecting to VPS ({IP})...")
        ssh.connect(IP, username=USER, password=PASS, timeout=30,
                    look_for_keys=False, allow_agent=False)

        # Get all folders in the remote output directory
        stdin, stdout, stderr = ssh.exec_command(
            'find /root/recon-tools/output/ -maxdepth 1 -mindepth 1 -type d | sort'
        )
        remote_dirs = [d.strip() for d in stdout.read().decode().split('\n') if d.strip()]

        if not remote_dirs:
            print("No output directories found on VPS.")
            return False

        print(f"[*] Found {len(remote_dirs)} scan dir(s) on VPS.")
        fetched_count = 0

        with SCPClient(ssh.get_transport()) as scp:
            for rdir in remote_dirs:
                dir_name = os.path.basename(rdir.rstrip('/'))

                # Parse domain_YYYYMMDD_HHMMSS pattern
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

                print(f"\n[*] Syncing [{domain}] (Run: {timestamp})...")

                downloaded = []
                skipped = []

                # --- Small files (SCP) ---
                for fname in SMALL_FILES:
                    result = _fetch_file(ssh, scp, rdir, local_target_dir, fname)
                    if result:
                        local_path = os.path.join(local_target_dir, fname)
                        # Check if it was skipped (already existed with same size)
                        remote_size = _remote_file_size(ssh, f"{rdir}/{fname}")
                        if os.path.exists(local_path) and os.path.getsize(local_path) == remote_size:
                            # Could be a skip or fresh download - just count as downloaded
                            downloaded.append(fname)

                # --- Large files (chunked SSH) ---
                for fname in LARGE_FILES:
                    remote_path = f"{rdir}/{fname}"
                    remote_size = _remote_file_size(ssh, remote_path)
                    if remote_size < 0:
                        continue  # File doesn't exist on VPS

                    local_path = os.path.join(local_target_dir, fname)
                    mb = remote_size / (1024 * 1024)

                    # Skip if already fully downloaded
                    if os.path.exists(local_path):
                        local_size = os.path.getsize(local_path)
                        if local_size == remote_size:
                            skipped.append(f"{fname} ({mb:.1f}MB, already local)")
                            continue

                    print(f"  [>] Fetching {fname} ({mb:.1f} MB)...")
                    if remote_size > SIZE_THRESHOLD:
                        success = _fetch_large_chunked(ssh, remote_path, local_path, fname, remote_size)
                    else:
                        success = _fetch_small(scp, remote_path, local_target_dir, fname)

                    if success:
                        downloaded.append(f"{fname} ({mb:.1f}MB)")

                if downloaded:
                    print(f"  [+] Downloaded: {', '.join(downloaded)}")
                    if skipped:
                        print(f"  [=] Already local: {', '.join(skipped)}")
                    print(f"  [+] Path: {os.path.relpath(local_target_dir, PROJECT_ROOT)}")
                    fetched_count += 1
                else:
                    if skipped:
                        print(f"  [=] All files already local: {', '.join(skipped)}")
                        fetched_count += 1
                    else:
                        print("  [-] No files found or scan still starting.")

        return fetched_count > 0

    except Exception as e:
        print(f"[!] Error connecting or fetching: {e}")
        return False
    finally:
        ssh.close()
        print("\n[*] Connection closed.")


if __name__ == "__main__":
    if fetch_all():
        print("\n[+] SUCCESS: Sync completed successfully!")
    else:
        print("\n[!] No active runs to pull or VPS unreachable.")
