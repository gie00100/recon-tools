#!/usr/bin/env python3
"""
Bulk Recon Runner — Automatically processes all targets from targets.txt
Runs scans sequentially, cleaning up after each to save disk space.
Sends Discord notifications on start/complete of each target.
"""

import asyncio
import subprocess
import sys
import time
import re
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from recon.config import Config

try:
    import aiohttp
except ImportError:
    aiohttp = None

TARGETS_FILE = Path(__file__).parent.parent / "targets" / "targets.txt"
OUTPUT_DIR = Path(__file__).parent.parent / "output"
WEBHOOK_URL = Config.DISCORD_WEBHOOK_URL


async def send_discord(title, description, color=0x00FF00):
    """Send a Discord webhook notification."""
    if not WEBHOOK_URL or not aiohttp:
        return
    embed = {
        "title": title,
        "description": description[:4000],
        "color": color,
        "timestamp": datetime.utcnow().isoformat(),
    }
    try:
        async with aiohttp.ClientSession() as session:
            await session.post(WEBHOOK_URL, json={"embeds": [embed]})
    except Exception as e:
        print(f"[!] Discord notification failed: {e}")


def get_targets():
    """Read targets from targets.txt, skip comments and blanks."""
    targets = []
    if TARGETS_FILE.exists():
        for line in TARGETS_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def get_completed():
    """Get set of domains that have completed output directories."""
    completed = set()
    if OUTPUT_DIR.exists():
        for item in OUTPUT_DIR.iterdir():
            if item.is_dir():
                m = re.match(r'^(.+?)_\d{8}_\d{6}$', item.name)
                if m:
                    completed.add(m.group(1))
                else:
                    completed.add(item.name)
    return completed


def cleanup_large_files(domain):
    """Remove large temp files (waymore_urls, unique_urls) to save disk."""
    if not OUTPUT_DIR.exists():
        return
    for item in OUTPUT_DIR.iterdir():
        if item.is_dir() and item.name.startswith(domain):
            for large_file in ["waymore_urls.txt", "unique_urls.txt"]:
                f = item / large_file
                if f.exists() and f.stat().st_size > 5_000_000:  # >5MB
                    size_mb = f.stat().st_size / 1_000_000
                    print(f"  [cleanup] Removing {f.name} ({size_mb:.1f}MB)")
                    f.unlink()


def run_recon(domain):
    """Run recon_master.py for a single domain. Returns True on success."""
    cmd = [
        sys.executable, str(Path(__file__).parent / "recon_master.py"),
        "-d", domain,
        "-o", str(OUTPUT_DIR),
        "--full", "--active"
    ]
    print(f"\n{'='*60}")
    print(f"  Starting: {domain}")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    start = time.time()
    try:
        result = subprocess.run(cmd, timeout=7200)  # 2hr timeout per domain
        elapsed = time.time() - start
        mins = int(elapsed // 60)
        if result.returncode == 0:
            print(f"\n  ✅ {domain} completed in {mins}m")
            return True
        else:
            print(f"\n  ❌ {domain} failed (exit {result.returncode}) after {mins}m")
            return False
    except subprocess.TimeoutExpired:
        print(f"\n  ⏰ {domain} timed out after 2 hours")
        return False
    except Exception as e:
        print(f"\n  ❌ {domain} error: {e}")
        return False


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="Bulk Recon Runner")
    parser.add_argument("--filter", type=str, default=None,
                        help="Only process targets containing this string (e.g. 'whatnot', 'twilio', 'anduril')")
    parser.add_argument("--worker", type=str, default="",
                        help="Worker name for Discord notifications")
    args = parser.parse_args()

    all_targets = get_targets()
    if not all_targets:
        print("[!] No targets found in targets.txt")
        return

    # Filter targets if --filter is specified
    if args.filter:
        targets = [t for t in all_targets if args.filter.lower() in t.lower()]
        worker_name = args.worker or args.filter
    else:
        targets = all_targets
        worker_name = args.worker or "all"

    completed = get_completed()
    pending = [t for t in targets if t not in completed]

    print(f"\n📋 Bulk Recon Runner [{worker_name}]")
    print(f"   Total targets: {len(targets)}")
    print(f"   Already done:  {len(completed & set(targets))}")
    print(f"   Pending:       {len(pending)}")
    print()

    if not pending:
        print("[✅] All targets already completed!")
        await send_discord(
            f"✅ Worker [{worker_name}] — All Done",
            f"All {len(targets)} targets have been scanned.",
            0x00FF00
        )
        return

    await send_discord(
        f"🚀 Worker [{worker_name}] Started",
        f"Processing {len(pending)} targets.\n"
        f"Targets: {', '.join(pending[:10])}{'...' if len(pending) > 10 else ''}",
        0x3498DB
    )

    results = {"success": [], "failed": []}
    total_start = time.time()

    for i, domain in enumerate(pending, 1):
        print(f"\n[{i}/{len(pending)}] Processing: {domain}")

        await send_discord(
            f"🔄 [{worker_name}] Scanning [{i}/{len(pending)}]",
            f"**Target:** `{domain}`\n"
            f"**Progress:** {len(results['success'])} done, {len(results['failed'])} failed",
            0xF39C12
        )

        success = run_recon(domain)

        if success:
            results["success"].append(domain)
            cleanup_large_files(domain)
            await send_discord(
                f"✅ [{worker_name}] Completed [{i}/{len(pending)}]",
                f"**Target:** `{domain}`\n"
                f"**Progress:** {len(results['success'])}/{len(pending)} completed",
                0x2ECC71
            )
        else:
            results["failed"].append(domain)
            await send_discord(
                f"❌ [{worker_name}] Failed [{i}/{len(pending)}]",
                f"**Target:** `{domain}`\n"
                f"Moving to next target...",
                0xE74C3C
            )

    total_elapsed = int((time.time() - total_start) / 60)

    summary = (
        f"**Worker:** {worker_name}\n"
        f"**Total Time:** {total_elapsed}m\n"
        f"**Successful:** {len(results['success'])}\n"
        f"**Failed:** {len(results['failed'])}\n\n"
    )
    if results['success']:
        summary += f"✅ {', '.join(results['success'][:20])}\n"
    if results['failed']:
        summary += f"❌ {', '.join(results['failed'][:20])}\n"

    await send_discord(f"🏁 Worker [{worker_name}] Complete", summary, 0x9B59B6)
    print(f"\n🏁 All done! {len(results['success'])} succeeded, {len(results['failed'])} failed in {total_elapsed}m")


if __name__ == "__main__":
    asyncio.run(main())
