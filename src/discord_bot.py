#!/usr/bin/env python3
"""
Discord Command Bot for Recon Pipeline
Runs 24/7 on the VPS and accepts commands from Discord to control recon.

Commands:
  !recon <domain>       - Start recon on a domain
  !status               - Show running screen sessions
  !results [domain]     - Show latest results for a domain (or all)
  !stop                 - Stop all running recon sessions
  !dork <domain>        - Generate clickable dork URLs for Google/Bing/DDG/URLScan/Shodan/GitHub/VT
  !help                 - Show available commands
  [AUTO]                - Auto-dorks posted when scanner finds bounty_targets/credentials/js_findings
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
# Dedicated channel for all dork output (both !dork command and auto-dork watcher)
DORK_WEBHOOK_URL = "https://discord.com/api/webhooks/1522544980084916224/iisUny3tQ4dFYg3nE3PhulWz43cQnWLlG98pCEMgj9NTcPS6heNy3tI0V2vNlTqZE7N5"
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "")
DISCORD_CHANNEL_ID = os.getenv("DISCORD_CHANNEL_ID", "")
RECON_DIR = Path(__file__).parent.parent
OUTPUT_DIR = RECON_DIR / "output"
POLL_INTERVAL = 2  # seconds

# When set, send_embed replies directly in this Discord channel
_reply_channel = None


# ── Webhook Helpers ──────────────────────────────────────────

async def send_embed(title, description, color=0x00FF00, fields=None):
    """Send a rich embed — replies in channel if Gateway mode, else webhook.

    NOTE: Only ONE path fires per call — gateway OR webhook, never both.
    """
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
                value=f.get("value", "") or "\u200b",  # zero-width space if empty
                inline=f.get("inline", False),
            )

    # Gateway mode: reply directly in the channel
    if _reply_channel is not None:
        try:
            await _reply_channel.send(embed=embed_obj)
            return  # SUCCESS — do NOT also send via webhook
        except Exception as e:
            print(f"[!] Channel send failed: {e}, falling back to webhook")
            # Only falls through to webhook if gateway send actually fails

    # Webhook fallback (or primary path when no gateway)
    if not WEBHOOK_URL:
        return
    embed_dict = {
        "title": title,
        "description": description[:4000],
        "color": color,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if fields:
        embed_dict["fields"] = [
            {
                "name": f.get("name", ""),
                "value": (f.get("value") or "\u200b")[:1024],
                "inline": f.get("inline", False),
            }
            for f in fields[:25]
        ]
    async with aiohttp.ClientSession() as session:
        await session.post(WEBHOOK_URL, json={"embeds": [embed_dict]})


async def send_message(content):
    """Send a plain text message to the webhook."""
    if not WEBHOOK_URL:
        return
    async with aiohttp.ClientSession() as session:
        await session.post(WEBHOOK_URL, json={"content": content})


async def send_dork_embed(title, description, color=0x7289DA, fields=None):
    """
    Send a dork embed ALWAYS to the dedicated dork webhook channel.
    Never goes to the main channel — dork spam stays separate.
    """
    embed_dict = {
        "title": title,
        "description": description[:4000],
        "color": color,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if fields:
        embed_dict["fields"] = [
            {
                "name": f.get("name", ""),
                "value": (f.get("value") or "\u200b")[:1024],
                "inline": f.get("inline", False),
            }
            for f in fields[:25]
        ]
    async with aiohttp.ClientSession() as session:
        await session.post(DORK_WEBHOOK_URL, json={"embeds": [embed_dict]})


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

    # ── Helper: split a long domain list into ≤1024-char fields ──
    def _paginate_field(label, lines, emoji=""):
        """Split a list of lines into multiple embed fields of ≤1024 chars each."""
        result = []
        chunk, chunk_len = [], 0
        page = 1
        total_pages = 1
        # Pre-calculate pages
        temp, temp_len = [], 0
        for l in lines:
            entry = l + "\n"
            if temp_len + len(entry) > 1020:
                total_pages += 1
                temp, temp_len = [entry], len(entry)
            else:
                temp.append(entry)
                temp_len += len(entry)

        for l in lines:
            entry = l + "\n"
            if chunk_len + len(entry) > 1020:
                name = label if page == 1 else f"{label} (cont.)"
                result.append({"name": name, "value": "".join(chunk).strip(), "inline": False})
                chunk, chunk_len, page = [], 0, page + 1
            chunk.append(entry)
            chunk_len += len(entry)
        if chunk:
            name = label if page == 1 else f"{label} (cont.)"
            result.append({"name": name, "value": "".join(chunk).strip(), "inline": False})
        return result

    # 7. Build the embed
    fields = []

    if done_list:
        fields.extend(_paginate_field(f"✅ Completed ({len(done_list)})", done_list))

    if running_list or extra_running:
        all_running = [f"🔄 `{d}`" for d in running_list] + [f"🔄 `{d}` *(extra)*" for d in extra_running]
        fields.extend(_paginate_field(f"🔄 Running ({len(all_running)})", all_running))

    if pending_list:
        fields.extend(_paginate_field(f"⏳ Pending ({len(pending_list)})", pending_list))

    if extra_completed:
        extra_lines = [f"➕ `{d}`" for d in extra_completed]
        fields.extend(_paginate_field(f"➕ Extra Completed ({len(extra_completed)})", extra_lines))

    # Discord allows max 25 fields per embed — split into multiple embeds if needed
    FIELD_LIMIT = 25
    field_chunks = [fields[i:i+FIELD_LIMIT] for i in range(0, max(len(fields), 1), FIELD_LIMIT)]

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

    # Send first embed with summary + first batch of fields
    await send_embed("📊 Recon Pipeline Status", summary, 0x00BFFF, field_chunks[0] if field_chunks else None)

    # Send continuation embeds (if pending list was very long)
    for i, chunk in enumerate(field_chunks[1:], 2):
        await send_embed(f"📊 Status (cont. {i}/{len(field_chunks)})", "", 0x00BFFF, chunk)


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


async def cmd_dork(domain):
    """
    Generate clickable dork URLs for a domain across multiple search engines.
    The user clicks from their phone — no crawling, no captcha.
    Covers: Google, Bing, DuckDuckGo, URLScan.io, VirusTotal, Shodan, GitHub, Wayback.
    """
    import urllib.parse

    domain = domain.strip().lower()
    if not domain or '.' not in domain:
        await send_embed('❌ Invalid Domain', f'`{domain}` is not a valid domain.', 0xFF0000)
        return

    # Strip scheme if user passed a full URL
    if domain.startswith('http'):
        from urllib.parse import urlparse as _up
        domain = _up(domain).netloc or domain

    d = domain  # short alias

    def g(q):  # Google URL builder
        return f'https://www.google.com/search?q={urllib.parse.quote_plus(q)}'

    def bing(q):  # Bing URL builder
        return f'https://www.bing.com/search?q={urllib.parse.quote_plus(q)}'

    def ddg(q):   # DuckDuckGo URL builder
        return f'https://duckduckgo.com/?q={urllib.parse.quote_plus(q)}'

    # ── Dork categories ─────────────────────────────────────────────────────

    # 1. Exposed sensitive files
    exposed_files = [
        (f'Google: .env/.git/.bak files', g(f'site:{d} ext:env OR ext:bak OR ext:sql OR ext:json "password" OR "secret" OR "key"')),
        (f'Google: config/backup files',   g(f'site:{d} ("config.php" OR "wp-config.php" OR "settings.py" OR "database.yml" OR ".htpasswd")')),
        (f'Google: log files',             g(f'site:{d} ext:log ("error" OR "exception" OR "password" OR "token")')),
        (f'Bing: .env exposed',            bing(f'site:{d} ".env" OR "DB_PASSWORD" OR "APP_SECRET"')),
    ]

    # 2. Login/admin panels
    admin_panels = [
        (f'Google: Admin/login panels',    g(f'site:{d} inurl:(admin|login|dashboard|panel|manage|signin|console)')),
        (f'Google: phpMyAdmin',            g(f'site:{d} inurl:phpmyadmin OR inurl:pma')),
        (f'Bing: Admin endpoints',         bing(f'site:{d} inurl:admin OR inurl:cp OR inurl:dashboard')),
        (f'DDG: Login panels',             ddg(f'site:{d} (login OR signin OR admin OR dashboard)')),
    ]

    # 3. API keys / tokens in indexed pages
    secrets_in_pages = [
        (f'Google: API keys/tokens',       g(f'site:{d} ("api_key" OR "apikey" OR "access_token" OR "secret_key" OR "client_secret")')),
        (f'Google: AWS keys',              g(f'site:{d} ("AKIA" OR "aws_access_key" OR "aws_secret")')),
        (f'Google: Bearer tokens',         g(f'site:{d} "Authorization: Bearer" OR "bearer token" OR "jwt"')),
        (f'Bing: Internal tokens',         bing(f'site:{d} "password" OR "token" OR "secret" filetype:txt OR filetype:xml OR filetype:json')),
    ]

    # 4. Exposed documents / PII
    exposed_docs = [
        (f'Google: PDFs/invoices',         g(f'site:{d} ext:pdf ("invoice" OR "receipt" OR "statement" OR "contract")')),
        (f'Google: XLS/CSV data',          g(f'site:{d} ext:xlsx OR ext:csv OR ext:xls')),
        (f'Google: Internal docs',         g(f'site:{d} ("internal" OR "confidential" OR "private") ext:pdf OR ext:docx')),
    ]

    # 5. Error pages / debug info
    error_debug = [
        (f'Google: Error pages',           g(f'site:{d} ("stack trace" OR "exception" OR "Error 500" OR "debug" OR "traceback")')),
        (f'Google: DB errors',             g(f'site:{d} ("SQL syntax" OR "mysql_fetch" OR "ORA-" OR "PostgreSQL" OR "MongoDB")')),
        (f'Bing: Debug info',              bing(f'site:{d} "debug=true" OR "XDEBUG" OR "phpinfo()"')),
    ]

    # 6. Open redirect / SSRF params
    redirect_ssrf = [
        (f'Google: Open redirect params',  g(f'site:{d} inurl:(redirect|return|next|url|dest|destination|continue|goto)=')),
        (f'Google: SSRF params',           g(f'site:{d} inurl:(fetch|load|proxy|request|uri|src|path|service)=')),
    ]

    # 7. Subdomain/infra discovery
    infra = [
        (f'URLScan: Indexed URLs',         f'https://urlscan.io/search/#page.domain%3A{d}'),
        (f'URLScan: Subdomains',           f'https://urlscan.io/search/#domain%3A{d}'),
        (f'VirusTotal: Domain report',     f'https://www.virustotal.com/gui/domain/{d}/relations'),
        (f'VirusTotal: URLs indexed',      f'https://www.virustotal.com/gui/domain/{d}/urls'),
        (f'Shodan: Subdomains/services',   f'https://www.shodan.io/search?query=hostname%3A{d}'),
        (f'Wayback Machine',               f'https://web.archive.org/web/*/{d}/*'),
        (f'crt.sh: SSL certs (subdomains)',f'https://crt.sh/?q=%25.{d}&output=json'),
    ]

    # 8. GitHub code leaks
    github = [
        (f'GitHub: "{d}" code',           f'https://github.com/search?q=%22{urllib.parse.quote(d)}%22&type=code'),
        (f'GitHub: API keys for {d}',      f'https://github.com/search?q=%22{urllib.parse.quote(d)}%22+%22api_key%22+OR+%22secret%22&type=code'),
        (f'GitHub: Commits for {d}',       f'https://github.com/search?q=%22{urllib.parse.quote(d)}%22&type=commits'),
    ]

    # 9. Pastebin / leaks
    leaks = [
        (f'Google: Pastebin leaks',        g(f'site:pastebin.com OR site:paste.ee OR site:hastebin.com "{d}" password OR email OR token')),
        (f'DDG: Exposed data',             ddg(f'"{d}" ("password" OR "credentials" OR "token") site:pastebin.com')),
    ]

    # ── Build embed fields ───────────────────────────────────────────────────
    def make_field(name, dorks):
        # Each dork: [label](url) on its own line — all clickable in Discord
        lines = [f'[{label}]({url})' for label, url in dorks]
        return {'name': name, 'value': '\n'.join(lines), 'inline': False}

    fields = [
        make_field('📁 Exposed Sensitive Files',       exposed_files),
        make_field('🔐 Admin / Login Panels',           admin_panels),
        make_field('🔑 API Keys & Tokens in Pages',     secrets_in_pages),
        make_field('📄 Exposed Documents & PII',        exposed_docs),
        make_field('💥 Error Pages & Debug Info',       error_debug),
        make_field('↩️ Open Redirect & SSRF Params',    redirect_ssrf),
        make_field('🌐 Infra Discovery (URLScan/VT/Shodan)', infra),
        make_field('🐙 GitHub Code Leaks',              github),
        make_field('📋 Pastebin & Data Leaks',          leaks),
    ]

    total_dorks = sum(len(f) for f in [exposed_files, admin_panels, secrets_in_pages,
                                        exposed_docs, error_debug, redirect_ssrf,
                                        infra, github, leaks])

    await send_dork_embed(
        f'🔎 Dorks for `{d}`',
        f'**{total_dorks} clickable dork links** across Google, Bing, DuckDuckGo, URLScan, VirusTotal, Shodan, GitHub & Pastebin.\n'
        f'Click any link to open directly in your browser — no captcha on your phone.\n\u200b',
        0x7289DA,
        fields,
    )


async def cmd_help():
    """Show available commands."""
    help_text = (
        "**Available Commands:**\n\n"
        "🚀 `!recon <domain>` — Start recon on a target domain\n"
        "📊 `!status` — Show active recon sessions\n"
        "📁 `!results [domain]` — View results (optional: filter by domain)\n"
        "🛑 `!stop` — Kill all running recon sessions\n"
        "🔎 `!dork <domain>` — Generate 30+ clickable dork URLs for a domain\n"
        "  *Covers: Google, Bing, DuckDuckGo, URLScan, VirusTotal, Shodan, GitHub, Wayback, Pastebin*\n"
        "❓ `!help` — Show this help message\n\n"
        "**Examples:**\n"
        "```\n"
        "!recon hackerone.com\n"
        "!results ui.com\n"
        "!dork shein.com\n"
        "!status\n"
        "```"
    )
    await send_embed("🤖 Recon Bot Help", help_text, 0x7289DA)


# ── Auto-Dork Watcher ─────────────────────────────────────────

def _get_scan_findings(scan_dir: Path) -> dict:
    """
    Check a completed scan dir for meaningful findings.
    Returns a dict: {category: count} for each category that has data.
    Returns empty dict if no findings.
    """
    findings = {}

    # bounty_targets.json — subdomains/URLs flagged by scanner
    bt = scan_dir / "bounty_targets.json"
    if bt.exists():
        try:
            data = json.loads(bt.read_text(encoding="utf-8", errors="replace"))
            count = len(data) if isinstance(data, list) else (
                sum(len(v) for v in data.values() if isinstance(v, list))
                if isinstance(data, dict) else 0
            )
            if count > 0:
                findings["🎯 Bounty Targets"] = count
        except Exception:
            pass

    # credentials_found.json — leaked creds
    cf = scan_dir / "credentials_found.json"
    if cf.exists():
        try:
            data = json.loads(cf.read_text(encoding="utf-8", errors="replace"))
            count = len(data) if isinstance(data, list) else len(data.get("credentials", []))
            if count > 0:
                findings["🔑 Credentials Found"] = count
        except Exception:
            pass

    # js_findings.json — secrets in JS files
    jf = scan_dir / "js_findings.json"
    if jf.exists():
        try:
            data = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
            count = len(data) if isinstance(data, list) else len(data.get("findings", []))
            if count > 0:
                findings["📜 JS Secrets"] = count
        except Exception:
            pass

    # js_endpoints.txt — endpoints found in JS
    je = scan_dir / "js_endpoints.txt"
    if je.exists():
        try:
            lines = [l for l in je.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
            if len(lines) > 10:  # only interesting if substantial
                findings["🔗 JS Endpoints"] = len(lines)
        except Exception:
            pass

    # live_urls.txt — live attack surface
    lu = scan_dir / "live_urls.txt"
    if lu.exists():
        try:
            lines = [l for l in lu.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
            if len(lines) > 0:
                findings["🌐 Live URLs"] = len(lines)
        except Exception:
            pass

    return findings


async def auto_dork_watcher():
    """
    Background task: watches output/ for newly-completed scans with findings.
    When a scan dir has bounty_targets / credentials / js_findings, auto-posts
    dork links to Discord so you can investigate from your phone immediately.
    Skips dirs where .dork_sent sentinel already exists.
    """
    WATCH_INTERVAL = 60  # seconds between checks
    print("[*] Auto-dork watcher started (checking every 60s)...")

    while True:
        await asyncio.sleep(WATCH_INTERVAL)
        try:
            if not OUTPUT_DIR.exists():
                continue

            for domain_dir in sorted(OUTPUT_DIR.iterdir()):
                if not domain_dir.is_dir():
                    continue

                # Each domain dir may have multiple timestamped run subdirs
                run_dirs = sorted(
                    [d for d in domain_dir.iterdir() if d.is_dir()],
                    key=lambda d: d.name, reverse=True  # newest first
                )
                # Also check flat structure (domain dir itself contains files)
                candidates = run_dirs if run_dirs else [domain_dir]

                for scan_dir in candidates:
                    sentinel = scan_dir / ".dork_sent"
                    if sentinel.exists():
                        continue  # already auto-dorked this run

                    # Must have report.json to be considered complete
                    if not (scan_dir / "report.json").exists():
                        continue

                    findings = _get_scan_findings(scan_dir)
                    if not findings:
                        # No interesting data — mark as checked anyway to skip next time
                        try:
                            sentinel.touch()
                        except Exception:
                            pass
                        continue

                    # Has findings — auto-post dorks
                    domain = domain_dir.name
                    run_id = scan_dir.name

                    finding_summary = "\n".join(
                        f"**{cat}**: {cnt}" for cat, cnt in findings.items()
                    )

                    print(f"[AUTO-DORK] {domain} ({run_id}) — {len(findings)} finding categories")

                    # Post findings alert to dork channel
                    await send_dork_embed(
                        f"🚨 Findings Detected — Auto-Dorking `{domain}`",
                        f"Bounty scanner found data for `{domain}` — auto-generating dork links.\n\n"
                        f"{finding_summary}\n\n"
                        f"🔎 Dork links follow — click to investigate from your phone:",
                        0xFF6600,
                    )

                    # Small delay so Discord doesn't rate-limit
                    await asyncio.sleep(1)

                    # Post the dork links (reuse cmd_dork logic)
                    await cmd_dork(domain)

                    # Mark as sent
                    try:
                        sentinel.touch()
                    except Exception:
                        pass

                    await asyncio.sleep(2)  # rate limit between domains

        except Exception as e:
            print(f"[AUTO-DORK] Watcher error: {e}")


# ── Webhook Polling Bot (No Bot Token Needed!) ───────────────
# Uses a simple webhook-based approach: polls a Discord channel via
# the webhook's "wait" parameter to read messages.
#
# For a proper bot with real-time responses, set DISCORD_BOT_TOKEN.

COMMAND_MAP = {
    "!recon":   cmd_recon,
    "!status":  cmd_status,
    "!results": cmd_results,
    "!stop":    cmd_stop,
    "!dork":    cmd_dork,
    "!help":    cmd_help,
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
        # Auto-dork watcher — DISABLED (uncomment to re-enable)
        # asyncio.ensure_future(auto_dork_watcher())
        # print("[+] Auto-dork watcher scheduled.")

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
                if arg and command in ("!recon", "!results", "!dork"):
                    await handler(arg)
                elif command in ("!status", "!stop", "!help"):
                    await handler()
                elif command == "!results" and not arg:
                    await handler()
                elif command == "!dork" and not arg:
                    await send_embed("❌ Usage", "Usage: `!dork <domain>` e.g. `!dork shein.com`", 0xFF0000)
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
