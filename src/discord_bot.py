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


# ── Webhook Helpers ──────────────────────────────────────────

async def send_embed(title, description, color=0x00FF00, fields=None):
    """Send a rich embed to the Discord webhook."""
    if not WEBHOOK_URL:
        return
    embed = {
        "title": title,
        "description": description[:4000],
        "color": color,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if fields:
        embed["fields"] = fields[:25]  # Discord max 25 fields
    payload = {"embeds": [embed]}
    async with aiohttp.ClientSession() as session:
        await session.post(WEBHOOK_URL, json=payload)


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
    targets_file = RECON_DIR / "targets" / "wix_ebay_targets.txt"

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
                # Strip timestamp suffix: ebay.com_20260601_155104 → ebay.com
                name = item.name
                # Find the pattern _YYYYMMDD_ and strip from there
                import re
                m = re.match(r'^(.+?)_\d{8}_\d{6}$', name)
                if m:
                    completed.add(m.group(1))
                else:
                    completed.add(name)

    # 3. Get currently running domain
    running_domain = None
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
            match = _re.search(r'-d\s+(\S+)', output)
            if match:
                running_domain = match.group(1)
    except Exception:
        pass

    # 4. Classify each target
    done_list = []
    running_list = []
    pending_list = []

    for domain in targets:
        if running_domain and domain == running_domain:
            running_list.append(domain)
        elif domain in completed:
            # Check for state file (full completion)
            state_file = OUTPUT_DIR / f"{domain}_state.json"
            if state_file.exists():
                done_list.append(f"✅ `{domain}`")
            else:
                done_list.append(f"✅ `{domain}` *(partial)*")
        else:
            pending_list.append(f"⏳ `{domain}`")

    # 5. Find extra scans not in target list
    target_set = set(targets)
    extra_list = [f"➕ `{d}`" for d in sorted(completed) if d not in target_set]

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
        # Split into chunks of 20 to avoid Discord field length limit
        done_text = "\n".join(done_list)
        fields.append({"name": f"✅ Completed ({len(done_list)})", "value": done_text[:1024], "inline": False})

    if running_list:
        fields.append({"name": "🔄 Running", "value": "\n".join(f"🔄 `{d}`" for d in running_list), "inline": False})

    if pending_list:
        fields.append({"name": f"⏳ Pending ({len(pending_list)})", "value": "\n".join(pending_list)[:1024], "inline": False})

    if extra_list:
        fields.append({"name": f"➕ Extra Scans ({len(extra_list)})", "value": "\n".join(extra_list)[:1024], "inline": False})

    summary = (
        f"**Total Targets:** {len(targets)}\n"
        f"**Completed:** {len(done_list)}\n"
        f"**Running:** {len(running_list)}\n"
        f"**Pending:** {len(pending_list)}\n"
    )
    if disk_info:
        summary += f"\n{disk_info}"
    if output_size:
        summary += f"\n{output_size}"

    await send_embed("📊 Recon Pipeline Status", summary, 0x00BFFF, fields)


async def cmd_results(domain=None):
    """Show results for a domain or all domains."""
    if not OUTPUT_DIR.exists():
        await send_embed("📁 No Results", "Output directory is empty.", 0x808080)
        return

    dirs = sorted(OUTPUT_DIR.iterdir(), key=lambda d: d.stat().st_mtime, reverse=True)
    dirs = [d for d in dirs if d.is_dir()]

    if domain:
        # Filter to matching domain
        dirs = [d for d in dirs if domain.lower() in d.name.lower()]
        if not dirs:
            await send_embed("📁 No Results", f"No results found for `{domain}`.", 0xFFA500)
            return

    # Show latest 5 results
    fields = []
    for d in dirs[:5]:
        files = list(d.iterdir())
        file_count = len(files)

        # Try to read key stats
        stats_parts = []
        
        # Count subdomains
        sub_file = d / "subdomains.txt"
        if sub_file.exists():
            count = sum(1 for _ in open(sub_file))
            stats_parts.append(f"🔍 {count} subdomains")

        # Count live hosts
        live_file = d / "live_urls.txt"
        if live_file.exists():
            count = sum(1 for _ in open(live_file))
            stats_parts.append(f"🟢 {count} live hosts")

        # Count unique URLs
        url_file = d / "unique_urls.txt"
        if url_file.exists():
            count = sum(1 for _ in open(url_file))
            stats_parts.append(f"🔗 {count} unique URLs")

        # Check for credentials
        cred_file = d / "credentials_found.json"
        if cred_file.exists() and cred_file.stat().st_size > 5:
            try:
                creds = json.loads(cred_file.read_text())
                if creds:
                    stats_parts.append(f"🔑 **{len(creds)} CREDENTIALS FOUND**")
            except Exception:
                pass

        # Check for exposed ports
        port_file = d / "exposed_ports.json"
        if port_file.exists() and port_file.stat().st_size > 5:
            try:
                ports = json.loads(port_file.read_text())
                if ports:
                    stats_parts.append(f"🚪 {len(ports)} exposed ports")
            except Exception:
                pass

        # Check for bounty findings
        bounty_file = d / "bounty_targets.json"
        if bounty_file.exists() and bounty_file.stat().st_size > 5:
            try:
                bounty = json.loads(bounty_file.read_text())
                count = len(bounty.get("findings", []))
                if count:
                    stats_parts.append(f"🎯 {count} bounty flags")
            except Exception:
                pass

        value = "\n".join(stats_parts) if stats_parts else f"{file_count} files"
        completed = "✅" if (d / "report.json").exists() else "⏳"

        fields.append({
            "name": f"{completed} {d.name}",
            "value": value,
            "inline": False
        })

    await send_embed("📊 Recon Results", f"Showing latest {len(fields)} scans:", 0x00BFFF, fields)


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

    @client.event
    async def on_message(message):
        if message.author == client.user or message.author.bot or message.webhook_id:
            return

        content = message.content.strip()
        print(f"[MSG] #{message.channel.name} @{message.author}: {content}")

        if not content.startswith("!"):
            return

        parts = content.split(maxsplit=1)
        command = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else None

        print(f"[CMD] {command} (arg={arg})")

        if command in COMMAND_MAP:
            handler = COMMAND_MAP[command]
            if arg and command in ("!recon", "!results"):
                await handler(arg)
            elif command in ("!status", "!stop", "!help"):
                await handler()
            elif command == "!results" and not arg:
                await handler()
            else:
                await send_embed("❌ Usage Error", f"Usage: `{command} <argument>`", 0xFF0000)
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
