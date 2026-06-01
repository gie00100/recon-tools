"""
Recon Toolkit - Centralized Configuration
Loads settings from .env file with CLI override support.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root
_PROJECT_ROOT = Path(__file__).parent.parent
_ENV_FILE = _PROJECT_ROOT / ".env"
if _ENV_FILE.exists():
    load_dotenv(_ENV_FILE)


class Config:
    """Centralized configuration with .env loading and defaults."""

    # ── API Keys ──────────────────────────────────────────────
    SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    # Support multiple VT keys for rotation (comma-separated in .env)
    VIRUSTOTAL_API_KEYS = [k.strip() for k in os.getenv("VIRUSTOTAL_API_KEYS", "").split(",") if k.strip()]
    URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
    CERTSPOTTER_API_KEY = os.getenv("CERTSPOTTER_API_KEY", "")
    CENSYS_API_ID = os.getenv("CENSYS_API_ID", "")
    CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET", "")

    # ── Rate Limiting ─────────────────────────────────────────
    RATE_LIMIT_DEFAULT = int(os.getenv("RATE_LIMIT_DEFAULT", "5"))
    RATE_LIMIT_SECURITYTRAILS = int(os.getenv("RATE_LIMIT_SECURITYTRAILS", "5"))
    RATE_LIMIT_CRTSH = int(os.getenv("RATE_LIMIT_CRTSH", "2"))

    # ── Concurrency ───────────────────────────────────────────
    MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "50"))
    DNS_CONCURRENCY = int(os.getenv("DNS_CONCURRENCY", "100"))

    # ── Timeouts (seconds) ────────────────────────────────────
    HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "10"))
    DNS_TIMEOUT = int(os.getenv("DNS_TIMEOUT", "5"))

    # ── Output & Notifications ────────────────────────────────
    OUTPUT_DIR = os.getenv("OUTPUT_DIR", str(_PROJECT_ROOT / "output"))
    DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
    DISCORD_RESULTS_WEBHOOK_URL = os.getenv("DISCORD_RESULTS_WEBHOOK_URL", "") or os.getenv("DISCORD_WEBHOOK_URL", "")

    # ── Paths ─────────────────────────────────────────────────
    PROJECT_ROOT = _PROJECT_ROOT
    WORDLISTS_DIR = _PROJECT_ROOT / "wordlists"
    BACKUP_EXTENSIONS_FILE = WORDLISTS_DIR / "backup_extensions.txt"
    SUBDOMAINS_WORDLIST = WORDLISTS_DIR / "subdomains_mini.txt"
    JS_PATTERNS_FILE = WORDLISTS_DIR / "js_secrets_patterns.txt"

    # ── User Agent ────────────────────────────────────────────
    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    )

    # ── Free API Endpoints ────────────────────────────────────
    CRTSH_URL = "https://crt.sh/?q={domain}&output=json"
    HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"
    ALIENVAULT_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    URLSCAN_URL = "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
    RAPIDDNS_URL = "https://rapiddns.io/subdomain/{domain}?full=1"
    SECURITYTRAILS_SUBDOMAINS_URL = "https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    SHODAN_DNS_URL = "https://api.shodan.io/dns/domain/{domain}?key={key}"
    VIRUSTOTAL_SUBDOMAINS_URL = "https://www.virustotal.com/api/v3/domains/{domain}/subdomains"

    # ── BGP / ASN Endpoints ───────────────────────────────────
    BGP_HE_ASN_URL = "https://bgp.he.net/{asn}#_prefixes"
    RIPE_ASN_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
    HACKERTARGET_REVERSE_DNS_URL = "https://api.hackertarget.com/reversedns/?q={ip}"

    @classmethod
    def has_api_key(cls, provider: str) -> bool:
        """Check if an API key is configured for a given provider."""
        key_map = {
            "securitytrails": cls.SECURITYTRAILS_API_KEY,
            "shodan": cls.SHODAN_API_KEY,
            "virustotal": cls.VIRUSTOTAL_API_KEY,
            "censys": cls.CENSYS_API_ID,
            "certspotter": cls.CERTSPOTTER_API_KEY,
        }
        return bool(key_map.get(provider.lower(), ""))

    @classmethod
    def get_vt_keys(cls) -> list:
        """Get all VirusTotal API keys (multi-key rotation support)."""
        keys = list(cls.VIRUSTOTAL_API_KEYS)  # From VIRUSTOTAL_API_KEYS env
        if cls.VIRUSTOTAL_API_KEY and cls.VIRUSTOTAL_API_KEY not in keys:
            keys.insert(0, cls.VIRUSTOTAL_API_KEY)  # Add single key if not already in list
        return keys

    @classmethod
    def ensure_output_dir(cls, subdir: str = "") -> Path:
        """Create and return the output directory."""
        out = Path(cls.OUTPUT_DIR)
        if subdir:
            out = out / subdir
        out.mkdir(parents=True, exist_ok=True)
        return out
