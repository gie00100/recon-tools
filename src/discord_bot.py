#!/usr/bin/env python3
"""
Discord Command Bot for Recon Pipeline
Runs 24/7 on the VPS and accepts commands from Discord to control recon.

Commands:
  !recon <domain>       - Start recon on a domain
  !status               - Show running screen sessions
  !results [domain]     - Show latest results for a domain (or all)
  !stop                 - Stop all running recon sessions
  !help                 - Show available commands
"""

import asyncio
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import aiohttp

# Load config
sys.path.insert(0, str(Path(__file__).parent))
from recon.config import Config

WEBHOOK_URL = Config.DISCORD_WEBHOOK_URL
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "")
DISCORD_CHANNEL_ID = os.getenv("DISCORD_CHANNEL_ID", "")
RECON_DIR = Path(__file__).parent.parent
OUTPUT_DIR = RECON_DIR / "output"
POLL_INTERVAL = 2  # seconds

# When set, send_embed replies directly in this Discord channel
_reply_channel = None


# ── Webhook Helpers ──────────────────────────────────────────

async def send_embed(title, description, color=0x00FF00, fields=None):
    """Send a rich embed — replies in channel if Gateway mode, else webhook."""
    global _reply_channel
    import discord as _discord

    embed_obj = _discord.Embed(
        title=title,
        description=description[:4000],
        color=color,
        timestamp=datetime.now(timezone.utc),
    )
    if fields:
        for f in fields[:25]:
            embed_obj.add_field(
                name=f.get("name", ""),
                value=f.get("value", ""),
                inline=f.get("inline", False),
            )

    # Gateway mode: reply directly in the channel
    if _reply_channel is not None:
        try:
            await _reply_channel.send(embed=embed_obj)
            return
        except Exception as e:
            print(f"[!] Channel send failed: {e}, falling back to webhook")

    # Fallback: send via webhook
    if not WEBHOOK_URL:
        return
    embed_dict = {
        "title": title,
        "description": description[:4000],
        "color": color,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if fields:
        embed_dict["fields"] = fields[:25]
    async with aiohttp.ClientSession() as session:
        await session.post(WEBHOOK_URL, json={"embeds": [embed_dict]})


async def send_message(content):
    """Send a plain text message to the webhook."""
    if not WEBHOOK_URL:
        return
    async with aiohttp.ClientSession() as session:
        await session.post(WEBHOOK_URL, json={"content": content})


# ── Command Handlers ─────────────────────────────────────────

async def cmd_recon(domain):
    """Start recon on a domain via a new screen session."""
    domain = domain.strip().lower()
    if not domain or "." not in domain:
        await send_embed("❌ Invalid Domain", f"`{domain}` is not a valid domain.", 0xFF0000)
        return

    # Check if already running
    result = subprocess.run(["screen", "-ls"], capture_output=True, text=True)
    if f"recon_{domain}" in result.stdout:
        await send_embed("⚠️ Already Running", f"Recon for `{domain}` is already in progress.", 0xFFA500)
        return

    # Sanitize session name (screen doesn't like dots)
    session_name = f"recon_{domain.replace('.', '_')}"

    # Launch in a detached screen session
    cmd = f'cd {RECON_DIR} && ./run_recon.sh {domain}'
    subprocess.Popen(
        ["screen", "-dmS", session_name, "bash", "-c", cmd],
        cwd=str(RECON_DIR)
    )

    await send_embed(
        "🚀 Recon Started",
        f"**Domain:** `{domain}`\n**Session:** `{session_name}`\n\nMonitor with `!status`\nResults with `!results {domain}`",
        0x00FF00
    )


async def cmd_status():
    """Show full pipeline status: completed, running, pending domains."""
    targets_file = RECON_DIR / "targets" / "targets.txt"

    # 1. Read target list
    targets = []
    if targets_file.exists():
        for line in targets_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)

    # 2. Get completed scans from output directory
    completed = set()
    if OUTPUT_DIR.exists():
        for item in OUTPUT_DIR.iterdir():
            if item.is_dir():
                name = item.name
                import re
                m = re.match(r'^(.+?)_\d{8}_\d{6}$', name)
                if m:
                    completed.add(m.group(1))
                else:
                    completed.add(name)

    # 3. Get ALL currently running domains from recon_master processes
    running_domains = set()
    try:
        process = await asyncio.create_subprocess_exec(
            "pgrep", "-af", "recon_master",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate()
        output = stdout.decode(errors="ignore").strip()
        if output:
            import re as _re
            for line in output.splitlines():
                match = _re.search(r'-d\s+(\S+)', line)
                if match:
                    running_domains.add(match.group(1))
    except Exception:
        pass

    # Also check screen sessions for running scans
    try:
        process = await asyncio.create_subprocess_exec(
            "screen", "-ls",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate()
        output = stdout.decode(errors="ignore").strip()
        import re as _re2
        for match in _re2.finditer(r'recon_(\S+)', output):
            screen_domain = match.group(1).replace('_', '.')
            # Only add if it looks like a domain
            if '.' in screen_domain or screen_domain in [t.replace('.', '') for t in targets]:
                running_domains.add(screen_domain)
    except Exception:
        pass

    # 4. Classify each target
    done_list = []
    running_list = []
    pending_list = []

    for domain in targets:
        if domain in running_domains:
            running_list.append(domain)
        elif domain in completed:
            state_file = OUTPUT_DIR / f"{domain}_state.json"
            if state_file.exists():
                done_list.append(f"✅ `{domain}`")
            else:
                done_list.append(f"✅ `{domain}` *(partial)*")
        else:
            pending_list.append(f"⏳ `{domain}`")

    # 5. Find extra scans not in target list (running or completed)
    target_set = set(targets)
    extra_running = [d for d in sorted(running_domains) if d not in target_set]
    extra_completed = [d for d in sorted(completed) if d not in target_set and d not in running_domains]

    # 6. Disk usage
    disk_info = ""
    try:
        process = await asyncio.create_subprocess_exec(
            "df", "-h", "/",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate()
        lines = stdout.decode().strip().split("\n")
        if len(lines) > 1:
            parts = lines[1].split()
            disk_info = f"💾 Disk: {parts[2]}/{parts[1]} ({parts[4]})"
    except Exception:
        pass

    output_size = ""
    try:
        process = await asyncio.create_subprocess_exec(
            "du", "-sh", str(OUTPUT_DIR),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate()
        size = stdout.decode().strip().split("\t")[0]
        output_size = f"📂 Output: {size}"
    except Exception:
        pass

    # 7. Build the embed
    fields = []

    if done_list:
        done_text = "\n".join(done_list)
        fields.append({"name": f"✅ Completed ({len(done_list)})", "value": done_text[:1024], "inline": False})

    if running_list or extra_running:
        all_running = [f"🔄 `{d}`" for d in running_list] + [f"🔄 `{d}` *(extra)*" for d in extra_running]
        fields.append({"name": f"🔄 Running ({len(all_running)})", "value": "\n".join(all_running)[:1024], "inline": False})

    if pending_list:
        fields.append({"name": f"⏳ Pending ({len(pending_list)})", "value": "\n".join(pending_list)[:1024], "inline": False})

    if extra_completed:
        extra_text = "\n".join(f"➕ `{d}`" for d in extra_completed)
        fields.append({"name": f"➕ Extra Completed ({len(extra_completed)})", "value": extra_text[:1024], "inline": False})

    total_running = len(running_list) + len(extra_running)
    summary = (
        f"**Total Targets:** {len(targets)}\n"
        f"**Completed:** {len(done_list)}\n"
        f"**Running:** {total_running}\n"
        f"**Pending:** {len(pending_list)}\n"
    )
    if disk_info:
        summary += f"\n{disk_info}"
    if output_size:
        summary += f"\n{output_size}"

    await send_embed("📊 Recon Pipeline Status", summary, 0x00BFFF, fields)


async def cmd_results(domain=None):
    """Show results for a domain or all domains, sorted by richness."""
    if not OUTPUT_DIR.exists():
        await send_embed("📁 No Results", "Output directory is empty.", 0x808080)
        return

    dirs = [d for d in OUTPUT_DIR.iterdir() if d.is_dir()]

    if domain:
        dirs = [d for d in dirs if domain.lower() in d.name.lower()]
        if not dirs:
            await send_embed("📁 No Results", f"No results found for `{domain}`.", 0xFFA500)
            return

    # Build rich info per scan dir
    scan_data = []
    for d in dirs:
        info = {"dir": d, "score": 0, "stats": []}

        def _count(fname):
            f = d / fname
            if f.exists():
                try:
                    return sum(1 for line in open(f, encoding="utf-8", errors="ignore") if line.strip())
                except Exception:
                    return 0
            return 0

        def _json_count(fname, key="findings"):
            f = d / fname
            if f.exists() and f.stat().st_size > 5:
                try:
                    data = json.loads(f.read_text(encoding="utf-8", errors="ignore"))
                    return len(data.get(key, data) if isinstance(data, dict) else data)
                except Exception:
                    return 0
            return 0

        # Subdomains
        n = _count("subdomains.txt")
        if n:
            info["stats"].append(f"🔍 {n} subdomains")
            info["score"] += n

        # Live hosts
        n = _count("live_urls.txt")
        if n:
            info["stats"].append(f"🟢 {n} live hosts")
            info["score"] += n * 2

        # Waymore URLs
        n = _count("waymore_urls.txt")
        if n:
            info["stats"].append(f"🌐 {n:,} waymore URLs")
            info["score"] += n // 10

        # VT URLs
        n = _count("virustotal_urls.txt")
        if n:
            info["stats"].append(f"🦠 {n:,} VT URLs")
            info["score"] += n // 10

        # Unique URLs (deduplicated)
        n = _count("unique_urls.txt")
        if n:
            info["stats"].append(f"🔗 {n:,} unique URLs")
            info["score"] += n // 5

        # Bounty findings — high weight
        n = _json_count("bounty_targets.json", "findings")
        if n:
            info["stats"].append(f"🎯 **{n} bounty flags**")
            info["score"] += n * 50

        # Credentials — highest weight
        n = _json_count("credentials_found.json")
        if n:
            info["stats"].append(f"🔑 **{n} CREDENTIALS FOUND**")
            info["score"] += n * 200

        # Exposed ports
        n = _json_count("exposed_ports.json")
        if n:
            info["stats"].append(f"🚪 {n} exposed ports")
            info["score"] += n * 10

        info["completed"] = "✅" if (d / "report.json").exists() else "⏳"
        scan_data.append(info)

    # Sort: bounty/creds richest first, then by recency
    scan_data.sort(key=lambda x: (x["score"], x["dir"].stat().st_mtime), reverse=True)

    fields = []
    for info in scan_data[:10]:
        d = info["dir"]
        value = "\n".join(info["stats"]) if info["stats"] else "No data yet"
        fields.append({
            "name": f"{info['completed']} {d.name}",
            "value": value,
            "inline": False,
        })

    total = len(scan_data)
    await send_embed(
        "📊 Recon Results",
        f"Showing top {len(fields)} of {total} scan(s) — sorted by richness:",
        0x00BFFF,
        fields,
    )


async def cmd_stop():
    """Stop all running recon sessions asynchronously."""
    # Kill recon processes in non-blocking background
    try:
        p1 = await asyncio.create_subprocess_exec("pkill", "-f", "run_recon.sh")
        p2 = await asyncio.create_subprocess_exec("pkill", "-f", "run_bulk.sh")
        p3 = await asyncio.create_subprocess_exec("pkill", "-f", "recon_master.py")
        await asyncio.gather(p1.wait(), p2.wait(), p3.wait())

        # List screen sessions
        process = await asyncio.create_subprocess_exec(
            "screen", "-ls",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate()
        output = stdout.decode(errors="ignore").strip()
    except Exception as e:
        await send_embed("❌ Error", f"Failed to stop processes cleanly: {e}", 0xFF0000)
        return

    # Kill screen sessions
    killed = 0
    kill_tasks = []
    for line in output.split("\n"):
        if "recon_" in line or "recon_main" in line:
            session_id = line.strip().split("\t")[0]
            # Launch async kill command
            kill_tasks.append(
                asyncio.create_subprocess_exec("screen", "-S", session_id, "-X", "quit")
            )
            killed += 1

    if kill_tasks:
        processes = await asyncio.gather(*kill_tasks)
        await asyncio.gather(*(p.wait() for p in processes))

    await send_embed("🛑 All Stopped", f"Killed {killed} active recon session(s).", 0xFF0000)


async def cmd_help():
    """Show available commands."""
    help_text = (
        "**Available Commands:**\n\n"
        "🚀 `!recon <domain>` — Start recon on a target domain\n"
        "📊 `!status` — Show active recon sessions\n"
        "📁 `!results [domain]` — View results (optional: filter by domain)\n"
        "🛑 `!stop` — Kill all running recon sessions\n"
        "❓ `!help` — Show this help message\n\n"
        "**Examples:**\n"
        "```\n"
        "!recon hackerone.com\n"
        "!results ui.com\n"
        "!status\n"
        "```"
    )
    await send_embed("🤖 Recon Bot Help", help_text, 0x7289DA)


# ── Webhook Polling Bot (No Bot Token Needed!) ───────────────
# Uses a simple webhook-based approach: polls a Discord channel via
# the webhook's "wait" parameter to read messages.
#
# For a proper bot with real-time responses, set DISCORD_BOT_TOKEN.

COMMAND_MAP = {
    "!recon": cmd_recon,
    "!status": cmd_status,
    "!results": cmd_results,
    "!stop": cmd_stop,
    "!help": cmd_help,
}


async def run_gateway_bot():
    """Run a real Discord bot using the Gateway API (requires DISCORD_BOT_TOKEN)."""
    try:
        import discord
        from discord import Intents
    except ImportError:
        print("[!] discord.py not installed. Run: pip install discord.py")
        print("[!] Falling back to webhook polling mode.")
        await run_webhook_poll()
        return

    intents = Intents.default()
    intents.message_content = True
    intents.guilds = True
    client = discord.Client(intents=intents)

    @client.event
    async def on_ready():
        print(f"[+] Bot logged in as {client.user}")
        print(f"[+] Guilds: {[g.name for g in client.guilds]}")
        for guild in client.guilds:
            for ch in guild.text_channels:
                perms = ch.permissions_for(guild.me)
                can_read = perms.read_messages
                can_send = perms.send_messages
                print(f"    #{ch.name}: read={can_read} send={can_send}")
        await send_embed("🤖 Recon Bot Online", "Ready to accept commands! Type `!help` to get started.", 0x00FF00)

    # Track processed message IDs to prevent duplicate responses
    _processed_msgs = set()

    @client.event
    async def on_message(message):
        # Skip bots, self, webhooks
        if message.author == client.user or message.author.bot or message.webhook_id:
            return

        # Deduplicate — skip if already processed this message
        if message.id in _processed_msgs:
            print(f"[DUP] Skipping duplicate message {message.id}")
            return
        _processed_msgs.add(message.id)
        # Keep set small — only track last 100
        if len(_processed_msgs) > 100:
            _processed_msgs.clear()

        content = message.content.strip()
        print(f"[MSG] #{message.channel.name} @{message.author}: {content} (id={message.id})")

        if not content.startswith("!"):
            return

        parts = content.split(maxsplit=1)
        command = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else None

        print(f"[CMD] {command} (arg={arg})")

        if command in COMMAND_MAP:
            global _reply_channel
            _reply_channel = message.channel
            handler = COMMAND_MAP[command]
            try:
                if arg and command in ("!recon", "!results"):
                    await handler(arg)
                elif command in ("!status", "!stop", "!help"):
                    await handler()
                elif command == "!results" and not arg:
                    await handler()
                else:
                    await send_embed("❌ Usage Error", f"Usage: `{command} <argument>`", 0xFF0000)
            finally:
                _reply_channel = None
        else:
            print(f"[CMD] Unknown command: {command}")

    await client.start(DISCORD_BOT_TOKEN)


async def run_webhook_poll():
    """
    Fallback: Poll-based command reader.
    Reads a command file that can be written to via a simple webhook integration.
    """
    cmd_file = RECON_DIR / ".discord_commands"
    print("[*] Running in webhook-poll mode.")
    print(f"[*] Write commands to: {cmd_file}")
    await send_embed("🤖 Recon Bot Online (Webhook Mode)",
                     "Ready! Type `!help` in the command file to get started.", 0x00FF00)

    while True:
        if cmd_file.exists():
            content = cmd_file.read_text().strip()
            if content:
                cmd_file.write_text("")  # Clear

                parts = content.split(maxsplit=1)
                command = parts[0].lower()
                arg = parts[1].strip() if len(parts) > 1 else None

                if command in COMMAND_MAP:
                    handler = COMMAND_MAP[command]
                    if arg and command in ("!recon", "!results"):
                        await handler(arg)
                    elif command in ("!status", "!stop", "!help"):
                        await handler()
                    elif command == "!results" and not arg:
                        await handler()

        await asyncio.sleep(POLL_INTERVAL)


async def main():
    if DISCORD_BOT_TOKEN:
        print("[*] DISCORD_BOT_TOKEN found. Starting Gateway bot...")
        await run_gateway_bot()
    else:
        print("[!] No DISCORD_BOT_TOKEN set. Starting webhook-poll mode.")
        print("[!] To enable real Discord commands, add DISCORD_BOT_TOKEN to .env")
        await run_webhook_poll()


if __name__ == "__main__":
    asyncio.run(main())
