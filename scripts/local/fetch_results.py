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
    "staging_environments.json",
    "js_url_credentials.json",
    "api_intel.json",
    "confirmed_access.json",
    "credentials_found.json",
    "schema_findings.json",
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

# Files considered "complete" when checking if a dir is already local.
# If ALL of these exist locally and are non-empty, we skip the whole dir.
COMPLETE_MARKERS = [
    "subdomains.txt",
    "live_urls.txt",
    "report.json",
]

# ── Chunked transfer settings ───────────────────────────────────────────────
CHUNK_MB   = 8            # MB per chunk
CHUNK_SIZE = CHUNK_MB * 1024 * 1024

MAX_RETRIES   = 4   # retry attempts on connection drop
RETRY_DELAY   = 5   # seconds between reconnect attempts


def _local_dir_complete(local_dir: str) -> bool:
    """
    Fast local-only check: returns True if the directory already has all
    COMPLETE_MARKERS present and non-empty — meaning this run is already
    fully downloaded. No SSH calls made.
    """
    if not os.path.isdir(local_dir):
        return False
    local_files = {f.lower() for f in os.listdir(local_dir)
                   if os.path.isfile(os.path.join(local_dir, f))}
    for marker in COMPLETE_MARKERS:
        fpath = os.path.join(local_dir, marker)
        if marker.lower() not in local_files:
            return False
        if os.path.getsize(fpath) == 0:
            return False
    return True

# ── Connection helpers ───────────────────────────────────────────────────

def _make_ssh() -> paramiko.SSHClient:
    """Create a fresh SSH connection with keepalive to prevent idle timeouts."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        IP, username=USER, password=PASS,
        timeout=30, look_for_keys=False, allow_agent=False,
    )
    ssh.get_transport().set_keepalive(30)
    return ssh


def _make_ssh_with_retry() -> paramiko.SSHClient:
    """Connect with up to MAX_RETRIES attempts on failure."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return _make_ssh()
        except Exception as e:
            if attempt < MAX_RETRIES:
                print(f"    [!] Connect failed (attempt {attempt}/{MAX_RETRIES}): {e} — retrying in {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)
            else:
                raise


def _is_connection_error(e: Exception) -> bool:
    """Return True if e is a network/transport error that warrants a reconnect."""
    msg = str(e).lower()
    return any(kw in msg for kw in [
        'connection reset', 'connection forcibly closed', 'broken pipe',
        'eof', 'transport', 'socket', 'winError 10054', '10054', '10053',
        'connection refused', 'timed out', 'no existing session',
    ])


def _remote_file_size(ssh, remote_path: str) -> int:
    """Return file size in bytes, or -1 if file doesn't exist. Retries on connection error."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            _, stdout, _ = ssh.exec_command(f'stat -c%s "{remote_path}" 2>/dev/null || echo -1')
            result = stdout.read().decode().strip()
            try:
                return int(result)
            except ValueError:
                return -1
        except Exception as e:
            if attempt < MAX_RETRIES and _is_connection_error(e):
                print(f"    [!] stat failed (attempt {attempt}), reconnecting...")
                time.sleep(RETRY_DELAY)
                try: ssh.close()
                except: pass
                ssh = _make_ssh_with_retry()
            else:
                return -1
    return -1


def _fetch_small(ssh, remote_path: str, local_dir: str, fname: str) -> bool:
    """Download a file via SCP with reconnect-retry. Returns True on success."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with SCPClient(ssh.get_transport()) as scp:
                scp.get(remote_path, local_path=local_dir)
            return True
        except Exception as e:
            if attempt < MAX_RETRIES and _is_connection_error(e):
                print(f"    [!] SCP failed for {fname} (attempt {attempt}), reconnecting: {e}")
                time.sleep(RETRY_DELAY)
                try: ssh.close()
                except: pass
                ssh = _make_ssh_with_retry()
            else:
                print(f"    [!] SCP failed for {fname}: {e}")
                return False
    return False


def _fetch_large_chunked(ssh, remote_path: str, local_path: str, fname: str, file_size: int) -> bool:
    """Stream a large file from the VPS in chunks with full reconnect-and-resume."""
    mb = file_size / (1024 * 1024)
    total_blocks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
    local_tmp = local_path + ".part"
    written = os.path.getsize(local_tmp) if os.path.exists(local_tmp) else 0
    if written > 0:
        print(f"    [~] Resuming from {written/(1024*1024):.1f} MB (partial download found)")

    chunk_num = written // CHUNK_SIZE
    consecutive_errors = 0

    try:
        with open(local_tmp, 'ab') as f:
            while written < file_size:
                skip_blocks = written // CHUNK_SIZE
                remaining = file_size - written
                count_mb = min(CHUNK_MB, (remaining + 1024*1024 - 1) // (1024*1024))
                cmd = f'dd if="{remote_path}" bs=1M skip={skip_blocks} count={count_mb} 2>/dev/null'

                try:
                    _, stdout, _ = ssh.exec_command(cmd, timeout=120)
                    chunk_data = stdout.read()
                    consecutive_errors = 0
                except Exception as e:
                    consecutive_errors += 1
                    if consecutive_errors <= MAX_RETRIES and _is_connection_error(e):
                        print(f"    [!] Connection dropped at {written/(1024*1024):.1f} MB — reconnecting...")
                        time.sleep(RETRY_DELAY)
                        try: ssh.close()
                        except: pass
                        ssh = _make_ssh_with_retry()
                        continue
                    else: raise

                if not chunk_data: break
                f.write(chunk_data)
                f.flush()
                written += len(chunk_data)
                chunk_num += 1
                print(f"    [~] Chunk {chunk_num}/{total_blocks}: {written/(1024*1024):.1f}/{mb:.1f} MB")

        if written >= file_size * 0.99:
            os.replace(local_tmp, local_path)
            print(f"    [+] Done: {fname} ({written/(1024*1024):.1f} MB)")
            return True
        return False
    except Exception as e:
        print(f"    [!] Chunked transfer failed for {fname}: {e}")
        return False


def _print_intel_summary(local_dir: str, domain: str):
    """Print a quick summary of key intel files after fetch."""
    import json as _json

    has_intel = False

    # Bounty targets
    bt_path = os.path.join(local_dir, "bounty_targets.json")
    if os.path.exists(bt_path) and os.path.getsize(bt_path) > 2:
        try:
            data = _json.loads(open(bt_path, 'r', encoding='utf-8', errors='replace').read())
            findings = data.get("findings", [])
            if findings:
                has_intel = True
                types = {}
                for f in findings:
                    t = f["type"]
                    types[t] = types.get(t, 0) + 1
                crits = sum(1 for f in findings if f.get("severity") == "CRITICAL")
                highs = sum(1 for f in findings if f.get("severity") == "HIGH")
                print(f"  🎯 Bounty: {len(findings)} findings ({crits} CRITICAL, {highs} HIGH)")
                for t, c in sorted(types.items(), key=lambda x: -x[1])[:5]:
                    print(f"     {t}: {c}")
        except Exception:
            pass

    # Staging environments
    se_path = os.path.join(local_dir, "staging_environments.json")
    if os.path.exists(se_path) and os.path.getsize(se_path) > 2:
        try:
            data = _json.loads(open(se_path, 'r', encoding='utf-8', errors='replace').read())
            envs = data.get("environments", [])
            if envs:
                has_intel = True
                print(f"  🏗️  Staging: {len(envs)} live environments")
                for e in envs[:3]:
                    print(f"     → {e['url'][:80]}")
                if len(envs) > 3:
                    print(f"     ... and {len(envs) - 3} more")
        except Exception:
            pass

    # API intelligence
    ai_path = os.path.join(local_dir, "api_intel.json")
    if os.path.exists(ai_path) and os.path.getsize(ai_path) > 2:
        try:
            data = _json.loads(open(ai_path, 'r', encoding='utf-8', errors='replace').read())
            interesting = data.get("interesting_endpoints", [])
            secrets = data.get("all_js_secrets", [])
            specs = data.get("exposed_specs_and_metrics", [])
            schema = data.get("schema_findings", {})
            has_intel = True

            parts = []
            if interesting:
                parts.append(f"{len(interesting)} API endpoints")
            if secrets:
                parts.append(f"{len(secrets)} JS secrets")
            if specs:
                parts.append(f"{len(specs)} exposed specs")
            print(f"  🔍 API Intel: {', '.join(parts)}")

            # Show exposed specs/metrics (most actionable)
            for s in specs:
                print(f"     [{s['type']}] {s['url'][:80]}")

            # Show GraphQL/Swagger schema hits
            if isinstance(schema, dict):
                for cat in ['graphql', 'swagger', 'openapi']:
                    hits = schema.get(cat, [])
                    if hits:
                        for h in hits[:3]:
                            url = h if isinstance(h, str) else h.get('url', str(h))
                            print(f"     [SCHEMA:{cat.upper()}] {url[:80]}")
        except Exception:
            pass

    # JS URL credentials
    jc_path = os.path.join(local_dir, "js_url_credentials.json")
    if os.path.exists(jc_path) and os.path.getsize(jc_path) > 2:
        try:
            data = _json.loads(open(jc_path, 'r', encoding='utf-8', errors='replace').read())
            c_findings = data.get("findings", [])
            if c_findings:
                has_intel = True
                print(f"  🔐 JS URL Credentials: {len(c_findings)} unverified findings (saved to js_url_credentials.json)")
        except Exception:
            pass

    if not has_intel:
        print(f"  [~] No actionable findings for {domain}")


def fetch_all():
    print(f"[*] Connecting to VPS ({IP})...")
    try:
        ssh = _make_ssh_with_retry()
    except Exception as e:
        print(f"[!] Could not connect to VPS: {e}")
        return False

    try:
        _, stdout, _ = ssh.exec_command('find /root/recon-tools/output/ -maxdepth 1 -mindepth 1 -type d | sort')
        remote_dirs = [d.strip() for d in stdout.read().decode().split('\n') if d.strip()]

        if not remote_dirs:
            print("No output directories found on VPS.")
            return False

        print(f"[*] Found {len(remote_dirs)} scan dir(s) on VPS.")
        fetched_count = 0

        for rdir in remote_dirs:
            dir_name = os.path.basename(rdir.rstrip('/'))
            match = re.match(r'^(.+)_(\d{8}_\d{6})$', dir_name)
            domain, timestamp = (match.group(1), match.group(2)) if match else (dir_name, "historical")

            # Sanitize domain for Windows filesystem (strip *, ?, <, >, |, etc.)
            safe_domain = re.sub(r'[*?<>|"\\:]', '', domain).strip('.')
            if not safe_domain:
                print(f"[!] Skipping dir with invalid name: {dir_name}")
                continue
            if safe_domain != domain:
                print(f"[~] Sanitized domain: {domain} -> {safe_domain}")

            local_target_dir = os.path.join(LOCAL_OUT, safe_domain, timestamp)
            os.makedirs(local_target_dir, exist_ok=True)

            # ── Fast local pre-check: skip entire dir if already complete ──
            if _local_dir_complete(local_target_dir):
                local_files = os.listdir(local_target_dir)
                print(f"[=] Already local [{domain}] ({len(local_files)} files) — skipping.")
                fetched_count += 1
                continue

            print(f"\n[*] Syncing [{domain}] (Run: {timestamp})...")


            downloaded, skipped = [], []

            # ── Small files via SCP ──────────────────────────────────────
            for fname in SMALL_FILES:
                remote_path = f"{rdir}/{fname}"
                local_path  = os.path.join(local_target_dir, fname)
                remote_size = _remote_file_size(ssh, remote_path)
                if remote_size < 0: continue
                if os.path.exists(local_path) and os.path.getsize(local_path) == remote_size:
                    skipped.append(fname)
                    continue
                if _fetch_small(ssh, remote_path, local_target_dir, fname):
                    downloaded.append(fname)

            # ── Large files via chunked SSH ────────────────────────────────
            SORT_BEFORE_FETCH = {'waymore_urls.txt', 'unique_urls.txt'}
            for fname in LARGE_FILES:
                remote_path = f"{rdir}/{fname}"
                remote_size = _remote_file_size(ssh, remote_path)
                if remote_size < 0: continue

                if fname in SORT_BEFORE_FETCH:
                    sorted_marker = remote_path + '.sorted'
                    if _remote_file_size(ssh, sorted_marker) < 0:
                        print(f"    [~] Sorting {fname} on VPS (sort -u)...")
                        sort_cmd = f'sort -u "{remote_path}" -o "{remote_path}" && touch "{sorted_marker}"'
                        _, _sout, _serr = ssh.exec_command(sort_cmd, timeout=300)
                        _serr.read()  # wait for sort to finish
                        print(f'    [~] Sorted. New size: {_remote_file_size(ssh, remote_path)/(1024*1024):.1f} MB')
                        remote_size = _remote_file_size(ssh, remote_path)

                local_path = os.path.join(local_target_dir, fname)
                mb = remote_size / (1024 * 1024)

                if os.path.exists(local_path) and os.path.getsize(local_path) == remote_size:
                    skipped.append(f"{fname} ({mb:.1f}MB, already local)")
                    continue

                print(f"  [>] Fetching {fname} ({mb:.1f} MB)...")
                if _fetch_large_chunked(ssh, remote_path, local_path, fname, remote_size):
                    downloaded.append(f"{fname} ({mb:.1f}MB)")

            if downloaded or skipped:
                fetched_count += 1
                print(f"  [+] Status: {len(downloaded)} new, {len(skipped)} skipped.")

            # ── Quick intel summary from fetched files ───────────────────
            _print_intel_summary(local_target_dir, domain)

        return fetched_count > 0

    except Exception as e:
        print(f"[!] Error connecting or fetching: {e}")
        return False
    finally:
        try: ssh.close()
        except: pass
        print("\n[*] Connection closed.")


if __name__ == "__main__":
    if fetch_all():
        print("\n[+] SUCCESS: Sync completed successfully!")
    else:
        print("\n[!] No active runs to pull or VPS unreachable.")
