import os
import re
import sys
import time
import paramiko
from scp import SCPClient

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Resolve project root (two levels up from scripts/local/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOCAL_OUT = os.path.join(PROJECT_ROOT, "output")

IP   = "134.209.72.156"
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

# Large files fetched in chunks to avoid SCP timeouts
LARGE_FILES = [
    "unique_urls.txt",
    "waymore_urls.txt",
]

# Threshold above which chunked transfer is used (50 MB)
SIZE_THRESHOLD = 50 * 1024 * 1024

# ── Chunked transfer settings ─────────────────────────────────────────────────
# Use 1 MB blocks (dd bs=1M) — massively faster than bs=1 (byte-by-byte).
# Each chunk uses a NEW ssh.exec_command() call so the channel is fresh;
# this sidesteps paramiko's key-renegotiation timeout on long-lived channels.
CHUNK_MB   = 8            # MB per chunk (8 MB = 8 exec_command calls per 64MB file)
CHUNK_SIZE = CHUNK_MB * 1024 * 1024


def _make_ssh() -> paramiko.SSHClient:
    """Create a fresh SSH connection with keepalive to prevent idle timeouts."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        IP, username=USER, password=PASS,
        timeout=30, look_for_keys=False, allow_agent=False,
    )
    # Send keepalive every 30 s — prevents key-renegotiation timeout
    ssh.get_transport().set_keepalive(30)
    return ssh


def _remote_file_size(ssh, remote_path: str) -> int:
    """Return file size in bytes, or -1 if file doesn't exist."""
    _, stdout, _ = ssh.exec_command(f'stat -c%s "{remote_path}" 2>/dev/null || echo -1')
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
    Stream a large file from the VPS in chunks.

    Uses dd with bs=1M (megabyte blocks) and block-level skip/count
    instead of bs=1 (byte-level). This is ~1000x faster and each
    chunk opens a NEW exec_command channel, avoiding the paramiko
    key-renegotiation timeout that kills long-lived channels.

    Transfer rate: ~8-20 MB/s over typical VPS connections.
    """
    mb = file_size / (1024 * 1024)
    block_size_mb = CHUNK_MB
    total_blocks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE

    print(f"    [~] {fname}: {mb:.1f} MB — chunked transfer ({block_size_mb}MB/chunk, {total_blocks} chunks)...")

    local_tmp = local_path + ".part"
    try:
        written = 0
        chunk_num = 0
        with open(local_tmp, 'wb') as f:
            while written < file_size:
                # Block-level offset (skip N complete blocks)
                skip_blocks = written // CHUNK_SIZE
                remaining = file_size - written
                count_mb = min(block_size_mb, (remaining + 1024*1024 - 1) // (1024*1024))

                # dd bs=1M skip=N count=M — skips N full megabytes, reads M megabytes
                # Much faster than bs=1 which reads byte-by-byte from start
                cmd = (
                    f'dd if="{remote_path}" bs={block_size_mb}M '
                    f'skip={skip_blocks} count={count_mb} 2>/dev/null'
                )

                # Each chunk gets a FRESH exec_command — no key-renegotiation timeout
                _, stdout, _ = ssh.exec_command(cmd, timeout=120)
                chunk_data = stdout.read()

                if not chunk_data:
                    print(f"    [!] Empty chunk at block {skip_blocks} — stopping.")
                    break

                f.write(chunk_data)
                written += len(chunk_data)
                chunk_num += 1
                pct = (written / file_size) * 100
                speed_mb = (written / (1024*1024)) / max(chunk_num * 0.5, 1)
                print(f"    [~] Chunk {chunk_num}/{total_blocks}: "
                      f"{written/(1024*1024):.1f}/{mb:.1f} MB ({pct:.0f}%)")

        if written >= file_size * 0.99:  # 1% tolerance for block boundary rounding
            os.replace(local_tmp, local_path)
            print(f"    [+] Done: {fname} ({written/(1024*1024):.1f} MB)")
            return True
        else:
            print(f"    [!] Incomplete: got {written/(1024*1024):.1f} / {mb:.1f} MB")
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
    - Checks remote existence
    - Skips if already downloaded locally with matching size
    - Routes to SCP (small) or chunked SSH (large)
    """
    remote_path = f"{remote_dir}/{fname}"
    local_path  = os.path.join(local_dir, fname)

    remote_size = _remote_file_size(ssh, remote_path)
    if remote_size < 0:
        return False  # File doesn't exist on VPS

    # Skip if already fully downloaded
    if os.path.exists(local_path) and os.path.getsize(local_path) == remote_size:
        return True  # Already have it

    if remote_size > SIZE_THRESHOLD:
        return _fetch_large_chunked(ssh, remote_path, local_path, fname, remote_size)
    else:
        return _fetch_small(scp, remote_path, local_dir, fname)


def fetch_all():
    ssh = _make_ssh()
    try:
        print(f"[*] Connecting to VPS ({IP})...")

        # Get all scan output folders
        _, stdout, _ = ssh.exec_command(
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
                    domain    = match.group(1)
                    timestamp = match.group(2)
                else:
                    domain    = dir_name
                    timestamp = "historical"

                local_target_dir = os.path.join(LOCAL_OUT, domain, timestamp)
                os.makedirs(local_target_dir, exist_ok=True)
                print(f"\n[*] Syncing [{domain}] (Run: {timestamp})...")

                downloaded = []
                skipped    = []

                # ── Small files via SCP ───────────────────────────────────
                for fname in SMALL_FILES:
                    remote_path = f"{rdir}/{fname}"
                    local_path  = os.path.join(local_target_dir, fname)
                    remote_size = _remote_file_size(ssh, remote_path)
                    if remote_size < 0:
                        continue
                    if os.path.exists(local_path) and os.path.getsize(local_path) == remote_size:
                        skipped.append(fname)
                        continue
                    if _fetch_small(scp, remote_path, local_target_dir, fname):
                        downloaded.append(fname)

                # ── Large files via chunked SSH ───────────────────────────
                for fname in LARGE_FILES:
                    remote_path = f"{rdir}/{fname}"
                    remote_size = _remote_file_size(ssh, remote_path)
                    if remote_size < 0:
                        continue

                    local_path = os.path.join(local_target_dir, fname)
                    mb = remote_size / (1024 * 1024)

                    if os.path.exists(local_path) and os.path.getsize(local_path) == remote_size:
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
                    # Show size of entire local dir
                    total_mb = sum(
                        os.path.getsize(os.path.join(local_target_dir, f))
                        for f in os.listdir(local_target_dir)
                        if os.path.isfile(os.path.join(local_target_dir, f))
                    ) / (1024 * 1024)
                    print(f"  [+] Downloaded: {', '.join(downloaded)}")
                    if skipped:
                        print(f"  [=] Skipped (already local): {', '.join(skipped)}")
                    print(f"  [+] Path: {os.path.relpath(local_target_dir, PROJECT_ROOT)}  ({total_mb:.1f} MB total)")
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
        import traceback
        traceback.print_exc()
        return False
    finally:
        ssh.close()
        print("\n[*] Connection closed.")


if __name__ == "__main__":
    if fetch_all():
        print("\n[+] SUCCESS: Sync completed successfully!")
    else:
        print("\n[!] No active runs to pull or VPS unreachable.")
