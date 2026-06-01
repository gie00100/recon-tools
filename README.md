# 🎯 Recon Master — Automated Bug Bounty Reconnaissance Toolkit

An automated, 11-phase reconnaissance pipeline for bug bounty hunters. Runs on a cheap VPS ($4/mo DigitalOcean droplet), controlled via Discord bot or local scripts, with real-time vulnerability alerting.

## ⚡ Features

- **11-Phase Pipeline**: Subdomains → ASN → Live Probing → Ports → Backup Files → Credential Hunting → JS Analysis → URL Collection → Smart Dedup → Bounty Scanning → Reports
- **Discord Bot Control**: Start/stop/monitor scans from your phone
- **Dual Webhook Architecture**: Status channel + Findings channel
- **Smart URL Deduplication**: Signature-based dedup handles millions of URLs without OOM
- **SPA False Positive Filtering**: Triple-layer validation prevents AWS S3/CloudFront false positives
- **Auto-Retry on Failures**: Crashed domains are automatically re-queued
- **Memory-Safe**: Runs on 512MB RAM VPS with aggressive memory management

## 📁 Project Structure

```
tools/
├── setup.bat                # One-click Windows setup
├── requirements.txt         # Python dependencies
├── vps_config.example.ini   # VPS credentials template
├── run_recon.sh             # Single domain scan (VPS)
├── run_bulk.sh              # Bulk sequential scan (VPS)
├── run_parallel.sh          # Parallel multi-worker (VPS)
├── setup_vps.sh             # First-time VPS setup
├── recon-bot.service        # Systemd service for Discord bot
│
├── src/                     # Core source code
│   ├── recon_master.py      # Main pipeline orchestrator
│   ├── discord_bot.py       # Discord bot for remote control
│   ├── program_fetcher.py   # HackerOne/Bugcrowd scope fetcher
│   ├── .env.example         # API keys template
│   ├── waymore_config.yml   # Waymore configuration
│   │
│   ├── recon/               # Pipeline modules
│   │   ├── subdomain_enum.py    # Phase 1: Subdomain discovery
│   │   ├── asn_cidr_finder.py   # Phase 2: ASN/CIDR scanning
│   │   ├── live_probe.py        # Phase 3: HTTP probing
│   │   ├── port_scanner.py      # Phase 4: Port scanning
│   │   ├── backup_gen.py        # Phase 5: Backup file finder
│   │   ├── cred_hunter.py       # Phase 6: Credential hunting
│   │   ├── js_extractor.py      # Phase 7: JS secrets & endpoints
│   │   ├── url_dedup.py         # Phase 9: Smart URL deduplication
│   │   ├── bounty_scanner.py    # Phase 10: Bounty heuristics
│   │   ├── report_gen.py        # Phase 11: HTML/JSON reports
│   │   ├── config.py            # Centralized configuration
│   │   └── utils.py             # Shared utilities & Discord alerts
│   │
│   └── wordlists/           # Wordlists for fuzzing
│
├── scripts/
│   ├── vps/                 # VPS management scripts
│   │   ├── vps_helper.py        # Shared VPS connection helper
│   │   ├── deploy_vps.py        # Deploy code to VPS
│   │   ├── deploy_bot.py        # Deploy Discord bot
│   │   ├── start_vps_recon.py   # Trigger scans
│   │   ├── check_vps.py         # Check VPS health
│   │   └── ...
│   │
│   └── local/               # Local tools
│       └── fetch_results.py     # Download results from VPS
│
├── targets/                 # Target domain lists
│   ├── wix_ebay_targets.txt
│   └── ...
│
└── output/                  # Scan results (gitignored)
```

## 🚀 Quick Start

### First-Time Setup (New Machine)

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/recon-tools.git
cd recon-tools

# 2. Run setup (Windows)
setup.bat

# 3. Configure credentials
#    Edit src/.env → add your API keys (Shodan, VT, etc.)
#    Edit vps_config.ini → add your VPS IP/password
```

### Running Scans

```bash
# From Discord (mobile):
!recon hackerone.com
!status
!results

# From terminal (local):
.\venv\Scripts\python.exe scripts\vps\start_vps_recon.py targets.txt
.\venv\Scripts\python.exe scripts\local\fetch_results.py

# Directly on VPS:
./run_recon.sh example.com
./run_bulk.sh targets.txt
```

## 🔑 Configuration

### API Keys (`src/.env`)
| Key | Source | Required |
| :--- | :--- | :--- |
| `SHODAN_API_KEY` | [shodan.io](https://account.shodan.io/) | Yes |
| `VIRUSTOTAL_API_KEY` | [virustotal.com](https://www.virustotal.com/gui/my-apikey) | Yes |
| `URLSCAN_API_KEY` | [urlscan.io](https://urlscan.io/user/apikey) | Optional |
| `CERTSPOTTER_API_KEY` | [sslmate.com](https://sslmate.com/certspotter/) | Optional |
| `DISCORD_WEBHOOK_URL` | Discord Server Settings | Yes |
| `DISCORD_RESULTS_WEBHOOK_URL` | Discord Server Settings | Yes |

### VPS Credentials (`vps_config.ini`)
```ini
[vps]
host = YOUR_VPS_IP
user = root
password = YOUR_PASSWORD
port = 22
remote_path = /root/recon-tools
```

## 🤖 Discord Webhooks

| Channel | Variable | Purpose |
| :--- | :--- | :--- |
| **Status** | `DISCORD_WEBHOOK_URL` | Start/stop alerts, scan summaries |
| **Findings** | `DISCORD_RESULTS_WEBHOOK_URL` | Real-time vulnerabilities, exposed ports, credentials |

## 📄 License

For personal bug bounty use only. Do not scan targets without authorization.
