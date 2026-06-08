"""
Clean VPS Data — Safely remove old recon output from the VPS.

Usage:
  python scripts/vps/clean_vps_data.py                  # Interactive mode
  python scripts/vps/clean_vps_data.py --all             # Clean everything (with confirmation)
  python scripts/vps/clean_vps_data.py --fetched         # Clean only scans already fetched locally
  python scripts/vps/clean_vps_data.py --older-than 7    # Clean scans older than 7 days
  python scripts/vps/clean_vps_data.py --domain ebay.com # Clean specific domain only
  python scripts/vps/clean_vps_data.py --dry-run --all   # Preview what would be deleted
"""

import argparse
import os
import re
import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add parent dirs so we can import vps_helper
sys.path.insert(0, str(Path(__file__).parent))
from vps_helper import connect_vps, run_remote


# ── Constants ────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).parent.parent.parent
LOCAL_OUTPUT = PROJECT_ROOT / "output"
REMOTE_OUTPUT = "/root/recon-tools/output"
REMOTE_ROOT = "/root/recon-tools"

# Common cache/temp paths that pile up on the VPS
CACHE_PATHS = [
    "~/.config/waymore/results",        # Waymore cached results
    "~/.config/waymore/waymore.db",     # Waymore SQLite DB
    "/tmp/recon_chunk_*.txt",           # Bulk runner temp files
    "/tmp/subfinder*",                  # Subfinder temp
    "/tmp/amass*",                      # Amass temp
]


def print_header(title):
    width = 60
    print(f"\n{'=' * width}")
    print(f"  {title}")
    print(f"{'=' * width}")


def print_section(title):
    print(f"\n  ── {title} {'─' * (45 - len(title))}")


def get_disk_usage(ssh):
    """Get VPS disk usage stats."""
    disk = run_remote(ssh, "df -h / | tail -1", silent=True)
    output_size = run_remote(ssh, f"du -sh {REMOTE_OUTPUT} 2>/dev/null | cut -f1", silent=True)
    cache_size = run_remote(ssh, "du -sh ~/.config/waymore 2>/dev/null | cut -f1", silent=True)
    return disk, output_size or "0", cache_size or "0"


def get_remote_scan_dirs(ssh):
    """List all scan output directories on the VPS with metadata."""
    raw = run_remote(
        ssh,
        f"find {REMOTE_OUTPUT} -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort",
        silent=True,
    )
    if not raw:
        return []

    dirs = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        dirname = os.path.basename(line.rstrip("/"))

        # Parse domain_YYYYMMDD_HHMMSS pattern
        match = re.match(r"^(.+)_(\d{8})_(\d{6})$", dirname)
        if match:
            domain = match.group(1)
            date_str = match.group(2)
            time_str = match.group(3)
            try:
                scan_date = datetime.strptime(f"{date_str}_{time_str}", "%Y%m%d_%H%M%S")
            except ValueError:
                scan_date = None
        else:
            domain = dirname
            scan_date = None

        dirs.append({
            "path": line.rstrip("/"),
            "dirname": dirname,
            "domain": domain,
            "date": scan_date,
        })

    # Enrich with size and completion status
    for d in dirs:
        size = run_remote(ssh, f"du -sh \"{d['path']}\" 2>/dev/null | cut -f1", silent=True)
        has_report = run_remote(ssh, f"test -f \"{d['path']}/report.html\" && echo yes || echo no", silent=True)
        d["size"] = size or "?"
        d["completed"] = has_report.strip() == "yes"

    return dirs


def get_local_fetched_domains():
    """Get the set of domain directories that exist locally (already fetched)."""
    fetched = set()
    if LOCAL_OUTPUT.exists():
        for entry in LOCAL_OUTPUT.iterdir():
            if entry.is_dir():
                fetched.add(entry.name)
    return fetched


def display_scan_table(dirs, fetched_domains):
    """Display scan directories in a readable table."""
    if not dirs:
        print("  No scan directories found on VPS.")
        return

    print(f"\n  {'#':<4} {'Domain':<35} {'Date':<12} {'Size':<8} {'Status':<12} {'Fetched'}")
    print(f"  {'─'*4} {'─'*35} {'─'*12} {'─'*8} {'─'*12} {'─'*7}")

    for i, d in enumerate(dirs, 1):
        date_str = d["date"].strftime("%Y-%m-%d") if d["date"] else "unknown"
        status = "✓ Complete" if d["completed"] else "⚠ Partial"
        is_fetched = "✓ Yes" if d["domain"] in fetched_domains else "✗ No"
        domain_display = d["domain"][:34]
        print(f"  {i:<4} {domain_display:<35} {date_str:<12} {d['size']:<8} {status:<12} {is_fetched}")


def filter_dirs(dirs, args, fetched_domains):
    """Apply filters to determine which directories to clean."""
    to_clean = []

    for d in dirs:
        # Domain filter
        if args.domain and d["domain"] != args.domain.lower():
            continue

        # Age filter
        if args.older_than and d["date"]:
            cutoff = datetime.now() - timedelta(days=args.older_than)
            if d["date"] > cutoff:
                continue

        # Fetched-only filter
        if args.fetched and d["domain"] not in fetched_domains:
            continue

        # If --all, include everything
        if args.all or args.domain or args.older_than or args.fetched:
            to_clean.append(d)

    return to_clean


def clean_scan_dirs(ssh, dirs, dry_run=False):
    """Delete the specified scan directories from the VPS."""
    if not dirs:
        print("  Nothing to clean.")
        return 0

    total_cleaned = 0
    for d in dirs:
        label = f"  [{'DRY-RUN' if dry_run else 'DELETE'}] {d['dirname']} ({d['size']})"
        print(label)
        if not dry_run:
            run_remote(ssh, f"rm -rf \"{d['path']}\"", silent=True)
            # Also remove matching state file
            state_file = f"{REMOTE_OUTPUT}/{d['domain']}_state.json"
            run_remote(ssh, f"rm -f \"{state_file}\" 2>/dev/null", silent=True)
            total_cleaned += 1

    return total_cleaned


def clean_caches(ssh, dry_run=False):
    """Clean temp files and tool caches on the VPS."""
    print_section("Cache & Temp Cleanup")
    cleaned = False

    for pattern in CACHE_PATHS:
        # Check if path exists
        exists = run_remote(ssh, f"ls -d {pattern} 2>/dev/null | head -5", silent=True)
        if exists:
            size = run_remote(ssh, f"du -sh {pattern} 2>/dev/null | cut -f1", silent=True)
            label = f"  [{'DRY-RUN' if dry_run else 'DELETE'}] {pattern} ({size or '?'})"
            print(label)
            if not dry_run:
                run_remote(ssh, f"rm -rf {pattern}", silent=True)
            cleaned = True

    # Clean Python __pycache__ dirs in the project
    pycache = run_remote(
        ssh,
        f"find {REMOTE_ROOT}/src -type d -name __pycache__ 2>/dev/null | head -20",
        silent=True,
    )
    if pycache:
        pycache_size = run_remote(
            ssh,
            f"find {REMOTE_ROOT}/src -type d -name __pycache__ -exec du -shc {{}} + 2>/dev/null | tail -1 | cut -f1",
            silent=True,
        )
        label = f"  [{'DRY-RUN' if dry_run else 'DELETE'}] __pycache__ dirs ({pycache_size or '?'})"
        print(label)
        if not dry_run:
            run_remote(ssh, f"find {REMOTE_ROOT}/src -type d -name __pycache__ -exec rm -rf {{}} + 2>/dev/null", silent=True)
        cleaned = True

    # Clean old log files
    old_logs = run_remote(
        ssh,
        f"find {REMOTE_ROOT} -maxdepth 2 -name '*.log' -mtime +3 2>/dev/null | head -20",
        silent=True,
    )
    if old_logs:
        log_count = len(old_logs.strip().split("\n"))
        label = f"  [{'DRY-RUN' if dry_run else 'DELETE'}] {log_count} old log file(s) (>3 days)"
        print(label)
        if not dry_run:
            run_remote(ssh, f"find {REMOTE_ROOT} -maxdepth 2 -name '*.log' -mtime +3 -delete 2>/dev/null", silent=True)
        cleaned = True

    if not cleaned:
        print("  No caches or temp files to clean.")


def clean_dead_state_files(ssh, dirs, dry_run=False):
    """Remove orphaned state files that have no matching output directory."""
    print_section("Orphaned State Files")

    state_files = run_remote(
        ssh,
        f"find {REMOTE_OUTPUT} -maxdepth 1 -name '*_state.json' 2>/dev/null",
        silent=True,
    )
    if not state_files:
        print("  No orphaned state files found.")
        return

    existing_domains = {d["domain"] for d in dirs}
    cleaned = False

    for sf in state_files.strip().split("\n"):
        sf = sf.strip()
        if not sf:
            continue
        basename = os.path.basename(sf)
        # State file pattern: <domain>_state.json
        state_domain = basename.replace("_state.json", "")

        # Check if any output dir still exists for this domain
        if state_domain not in existing_domains:
            size = run_remote(ssh, f"du -sh \"{sf}\" 2>/dev/null | cut -f1", silent=True)
            label = f"  [{'DRY-RUN' if dry_run else 'DELETE'}] {basename} ({size or '?'})"
            print(label)
            if not dry_run:
                run_remote(ssh, f"rm -f \"{sf}\"", silent=True)
            cleaned = True

    if not cleaned:
        print("  No orphaned state files found.")


def interactive_mode(ssh, dirs, fetched_domains):
    """Interactive menu for choosing what to clean."""
    while True:
        print("\n  Select cleanup action:")
        print("    1) Clean all completed & fetched scans (safest)")
        print("    2) Clean scans older than N days")
        print("    3) Clean a specific domain's data")
        print("    4) Clean ALL scan data (nuclear option)")
        print("    5) Clean caches & temp files only")
        print("    6) Clean orphaned state files only")
        print("    7) Exit")
        print()

        try:
            choice = input("  Choice [1-7]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n  Aborted.")
            return

        if choice == "1":
            to_clean = [d for d in dirs if d["domain"] in fetched_domains and d["completed"]]
            if not to_clean:
                print("\n  No completed & fetched scans to clean.")
                continue
            print(f"\n  Will clean {len(to_clean)} completed & fetched scan(s):")
            for d in to_clean:
                print(f"    - {d['dirname']} ({d['size']})")
            confirm = input(f"\n  Proceed? (y/n): ").strip().lower()
            if confirm == "y":
                clean_scan_dirs(ssh, to_clean)
                clean_dead_state_files(ssh, [d for d in dirs if d not in to_clean])
                print("  ✓ Done.")

        elif choice == "2":
            try:
                days = int(input("  Clean scans older than how many days? ").strip())
            except (ValueError, KeyboardInterrupt, EOFError):
                continue
            cutoff = datetime.now() - timedelta(days=days)
            to_clean = [d for d in dirs if d["date"] and d["date"] < cutoff]
            if not to_clean:
                print(f"\n  No scans older than {days} days.")
                continue
            print(f"\n  Will clean {len(to_clean)} scan(s) older than {days} days:")
            for d in to_clean:
                date_str = d["date"].strftime("%Y-%m-%d") if d["date"] else "?"
                fetched = " (fetched)" if d["domain"] in fetched_domains else " (NOT fetched!)"
                print(f"    - {d['dirname']} ({d['size']}) — {date_str}{fetched}")
            confirm = input(f"\n  Proceed? (y/n): ").strip().lower()
            if confirm == "y":
                clean_scan_dirs(ssh, to_clean)
                print("  ✓ Done.")

        elif choice == "3":
            domain = input("  Enter domain name: ").strip().lower()
            to_clean = [d for d in dirs if d["domain"] == domain]
            if not to_clean:
                print(f"\n  No scan data found for '{domain}'.")
                continue
            print(f"\n  Will clean {len(to_clean)} scan(s) for {domain}:")
            for d in to_clean:
                print(f"    - {d['dirname']} ({d['size']})")
            confirm = input(f"\n  Proceed? (y/n): ").strip().lower()
            if confirm == "y":
                clean_scan_dirs(ssh, to_clean)
                print("  ✓ Done.")

        elif choice == "4":
            not_fetched = [d for d in dirs if d["domain"] not in fetched_domains]
            if not_fetched:
                print(f"\n  ⚠ WARNING: {len(not_fetched)} scan(s) have NOT been fetched locally:")
                for d in not_fetched:
                    print(f"    - {d['dirname']} ({d['size']})")
            confirm = input(f"\n  Delete ALL {len(dirs)} scan directories? Type 'DELETE ALL' to confirm: ").strip()
            if confirm == "DELETE ALL":
                clean_scan_dirs(ssh, dirs)
                clean_dead_state_files(ssh, [])
                print("  ✓ All scan data removed.")
            else:
                print("  Aborted.")

        elif choice == "5":
            clean_caches(ssh, dry_run=False)
            print("  ✓ Done.")

        elif choice == "6":
            clean_dead_state_files(ssh, dirs, dry_run=False)
            print("  ✓ Done.")

        elif choice == "7":
            return

        else:
            print("  Invalid choice.")


def main():
    parser = argparse.ArgumentParser(
        description="Clean recon data from the VPS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/vps/clean_vps_data.py                   # Interactive mode
  python scripts/vps/clean_vps_data.py --all              # Delete all output (asks confirmation)
  python scripts/vps/clean_vps_data.py --fetched          # Delete only locally-fetched scans
  python scripts/vps/clean_vps_data.py --older-than 7     # Delete scans >7 days old
  python scripts/vps/clean_vps_data.py --domain wix.com   # Delete wix.com scans only
  python scripts/vps/clean_vps_data.py --dry-run --all    # Preview what would be deleted
  python scripts/vps/clean_vps_data.py --caches-only      # Just clean temp/cache files
        """,
    )
    parser.add_argument("--all", action="store_true", help="Clean all scan output directories")
    parser.add_argument("--fetched", action="store_true", help="Clean only scans already fetched to local machine")
    parser.add_argument("--older-than", type=int, metavar="DAYS", help="Clean scans older than N days")
    parser.add_argument("--domain", type=str, help="Clean only a specific domain's data")
    parser.add_argument("--caches-only", action="store_true", help="Only clean caches and temp files, skip output dirs")
    parser.add_argument("--include-caches", action="store_true", help="Also clean caches/temp files along with output dirs")
    parser.add_argument("--dry-run", action="store_true", help="Preview what would be deleted without actually deleting")

    args = parser.parse_args()

    # Connect to VPS
    print_header("VPS Data Cleanup")
    try:
        ssh, cfg = connect_vps()
    except Exception as e:
        print(f"\n  [ERROR] Failed to connect to VPS: {e}")
        sys.exit(1)

    try:
        # Show current disk usage
        print_section("Current Disk Usage")
        disk, output_size, cache_size = get_disk_usage(ssh)
        print(f"  Disk:          {disk}")
        print(f"  Output dir:    {output_size}")
        print(f"  Waymore cache: {cache_size}")

        # Caches-only mode
        if args.caches_only:
            clean_caches(ssh, dry_run=args.dry_run)
            if not args.dry_run:
                print_section("Disk Usage After Cleanup")
                disk, output_size, cache_size = get_disk_usage(ssh)
                print(f"  Disk:          {disk}")
                print(f"  Output dir:    {output_size}")
                print(f"  Waymore cache: {cache_size}")
            return

        # Get scan directories and local state
        print_section("Scanning VPS Output Directories")
        dirs = get_remote_scan_dirs(ssh)
        fetched_domains = get_local_fetched_domains()

        display_scan_table(dirs, fetched_domains)
        print(f"\n  Total: {len(dirs)} scan dir(s) | {sum(1 for d in dirs if d['completed'])} completed | {sum(1 for d in dirs if d['domain'] in fetched_domains)} fetched locally")

        if not dirs:
            print("\n  Nothing to clean — VPS output is empty.")
            if args.include_caches:
                clean_caches(ssh, dry_run=args.dry_run)
            return

        # Non-interactive mode: apply filters
        is_filtered = args.all or args.fetched or args.older_than or args.domain
        if is_filtered:
            to_clean = filter_dirs(dirs, args, fetched_domains)
            if not to_clean:
                print("\n  No scan directories match the specified filters.")
                if args.include_caches:
                    clean_caches(ssh, dry_run=args.dry_run)
                return

            print_section(f"{'[DRY-RUN] ' if args.dry_run else ''}Directories to Clean")
            cleaned = clean_scan_dirs(ssh, to_clean, dry_run=args.dry_run)

            # Clean orphaned state files
            remaining = [d for d in dirs if d not in to_clean]
            clean_dead_state_files(ssh, remaining, dry_run=args.dry_run)

            if args.include_caches:
                clean_caches(ssh, dry_run=args.dry_run)

            if not args.dry_run and cleaned > 0:
                print(f"\n  ✓ Cleaned {cleaned} scan director{'y' if cleaned == 1 else 'ies'}.")
                print_section("Disk Usage After Cleanup")
                disk, output_size, cache_size = get_disk_usage(ssh)
                print(f"  Disk:          {disk}")
                print(f"  Output dir:    {output_size}")
                print(f"  Waymore cache: {cache_size}")
            elif args.dry_run:
                print(f"\n  [DRY-RUN] Would clean {len(to_clean)} scan director{'y' if len(to_clean) == 1 else 'ies'}.")

        else:
            # Interactive mode
            interactive_mode(ssh, dirs, fetched_domains)

            # Show final disk usage
            print_section("Disk Usage After Cleanup")
            disk, output_size, cache_size = get_disk_usage(ssh)
            print(f"  Disk:          {disk}")
            print(f"  Output dir:    {output_size}")
            print(f"  Waymore cache: {cache_size}")

    finally:
        ssh.close()
        print(f"\n{'=' * 60}")
        print("  Connection closed.")
        print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
