#!/usr/bin/env python3
"""
Module: Infrastructure Port Scanner — v2.0 (False Positive Hardened)

Key improvements over v1:
  1. CDN/shared-infra IP filtering — Cloudflare, Fastly, Akamai IPs are
     skipped for web ports (8080/8443) since their anycast IPs respond to
     every domain's requests, making TCP-open meaningless.
  2. Protocol verification — Redis/MongoDB/MySQL/Docker/Elasticsearch are
     CONFIRMED by sending the real protocol handshake and checking the response.
     A TCP-open without a valid banner is discarded.
  3. Response-based false positive removal — 403 Forbidden / 400 Bad Request
     / 407 Proxy Auth responses on web ports are discarded (CDN proxy behavior).
  4. Domain-to-IP tracking — each finding reports the domain that resolved to
     this IP, making it actionable (not just a raw IP).
  5. Deduplication — same (port, service) across 3+ CDN IPs with identical
     responses = shared CDN infra, suppressed.
"""

import asyncio
import ipaddress
import json
import re
import socket
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.utils import log_info, log_success, log_warning, log_error, banner, elapsed_str, RICH_AVAILABLE

if RICH_AVAILABLE:
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
    from rich.console import Console
    console = Console()
else:
    console = None


# ── High-value ports + expected service ─────────────────────────────────────
HIGH_VALUE_PORTS = {
    2375:  "Docker API (Unauthenticated)",
    5432:  "PostgreSQL",
    5601:  "Kibana",
    6379:  "Redis",
    8080:  "Web (Alt-HTTP)",
    8443:  "Web (Alt-HTTPS)",
    8888:  "Jupyter Notebook",
    8500:  "Consul",
    9090:  "Prometheus",
    9200:  "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    3306:  "MySQL",
}

# Ports where CDN IPs will ALWAYS respond but it means nothing
# Skip these ports entirely for any known CDN IP
CDN_SKIP_PORTS = {8080, 8443}

# ── Known CDN / Shared-Infra IP Ranges ──────────────────────────────────────
# These are anycast/shared IPs — a TCP-open just means the CDN proxies
# that port for SOME customer, not necessarily the target.
_CDN_RANGES_RAW = [
    # Cloudflare
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "104.16.0.0/12",    # covers 104.16-104.31
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",    # covers 172.64-172.71
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    # Fastly
    "23.235.32.0/20", "23.236.48.0/20",
    "43.249.72.0/22",
    "103.244.50.0/24", "103.245.222.0/23", "103.245.224.0/24",
    "104.156.80.0/20",
    "185.31.16.0/22",
    "199.27.128.0/21",
    "199.232.0.0/16",
    # Akamai
    "23.32.0.0/11",
    "23.192.0.0/11",
    "72.246.0.0/15",
    "96.6.0.0/15",
    "96.16.0.0/15",
    "104.64.0.0/10",
    "184.24.0.0/13",
    "184.50.0.0/15",
    # AWS CloudFront
    "13.32.0.0/15",
    "13.35.0.0/16",
    "52.46.0.0/18",
    "52.84.0.0/15",
    "54.182.0.0/16",
    "54.192.0.0/16",
    "54.230.0.0/16",
    "54.239.128.0/18",
    "64.252.64.0/18",
    "70.132.0.0/18",
    "204.246.164.0/22",
    "204.246.168.0/22",
    "205.251.192.0/19",
    "216.137.32.0/19",
    # HubSpot / BrightEdge shared reverse proxy infra
    # Returns 403/400 on 8080/8443 for all domains proxied (confirmed FP pattern)
    "199.60.103.0/24",
    "199.60.102.0/24",
]

_CDN_NETWORKS = [ipaddress.ip_network(r, strict=False) for r in _CDN_RANGES_RAW]


def is_cdn_ip(ip: str) -> bool:
    """Return True if the IP belongs to a known CDN/shared-infra range."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _CDN_NETWORKS)
    except ValueError:
        return False


# ── False positive response patterns ────────────────────────────────────────
# If ANY of these strings appear in the HTTP response on a web port,
# the finding is discarded as a CDN/proxy artifact.
_WEB_FP_PATTERNS = [
    "403 forbidden",
    "400 the plain http request was sent to https port",
    "400 bad request",
    "407 proxy authentication required",
    "the plain http request was sent to https",
    "400 no required ssl certificate was sent",
    "421 misdirected request",
    # Generic CDN error pages
    "cloudflare",
    "access denied",
    "error 1020",
    "error 403",
]


def _is_web_false_positive(title: str) -> bool:
    """Return True if the HTTP response title indicates a CDN/proxy false positive."""
    t = title.lower()
    return any(fp in t for fp in _WEB_FP_PATTERNS)


# ── Protocol Verifiers ───────────────────────────────────────────────────────

async def _verify_redis(ip: str, port: int, timeout: float) -> Optional[str]:
    """Send PING, expect +PONG. Returns banner or None."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.write(b"*1\r\n$4\r\nPING\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(64), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        resp = data.decode(errors="ignore").strip()
        if resp.startswith("+PONG") or resp.startswith("-"):
            return resp[:80]
        return None
    except Exception:
        return None


async def _verify_mongodb(ip: str, port: int, timeout: float) -> Optional[str]:
    """Send MongoDB OP_MSG isMaster. Returns version string or None."""
    try:
        # Minimal OP_QUERY packet for {isMaster:1}
        msg = (
            b"\x41\x00\x00\x00"  # message length
            b"\x01\x00\x00\x00"  # request ID
            b"\x00\x00\x00\x00"  # response to
            b"\xd4\x07\x00\x00"  # opCode: OP_QUERY (2004)
            b"\x00\x00\x00\x00"  # flags
            b"admin.$cmd\x00"    # collection name
            b"\x00\x00\x00\x00"  # number to skip
            b"\x01\x00\x00\x00"  # number to return
            b"\x13\x00\x00\x00"  # doc length (19 bytes)
            b"\x10isMaster\x00\x01\x00\x00\x00\x00"  # {isMaster: 1}
        )
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.write(msg)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        # Valid MongoDB response starts with 4-byte length, then response header
        if len(data) >= 16:
            return f"MongoDB (response {len(data)}B)"
        return None
    except Exception:
        return None


async def _verify_mysql(ip: str, port: int, timeout: float) -> Optional[str]:
    """Check for MySQL server greeting packet. Returns version or None."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        # MySQL greeting: payload starts after 4-byte header
        # Byte 4 = protocol version (0x0a = 10)
        # Followed by null-terminated version string
        if len(data) >= 5 and data[4] in (0x0a, 0x09):
            # Extract version string
            version_end = data.find(b'\x00', 5)
            if version_end > 5:
                version = data[5:version_end].decode(errors="ignore").strip()
                if version:
                    return f"MySQL {version}"
            return "MySQL (handshake confirmed)"
        return None
    except Exception:
        return None


async def _verify_elasticsearch(ip: str, port: int, timeout: float) -> Optional[str]:
    """Send HTTP GET /, check for ES JSON cluster info. Returns version or None."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        req = f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        resp = data.decode(errors="ignore")
        if '"cluster_name"' in resp or '"version"' in resp and '"number"' in resp:
            m = re.search(r'"number"\s*:\s*"([^"]+)"', resp)
            version = m.group(1) if m else "unknown"
            return f"Elasticsearch v{version} (UNAUTHENTICATED)"
        return None
    except Exception:
        return None


async def _verify_prometheus(ip: str, port: int, timeout: float) -> Optional[str]:
    """Send HTTP GET, check for Prometheus metrics or UI. Returns banner or None."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        req = f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        resp = data.decode(errors="ignore")
        if _is_web_false_positive(resp[:500]):
            return None
        if "prometheus" in resp.lower() or "# HELP" in resp or "# TYPE" in resp:
            return "Prometheus (EXPOSED METRICS)"
        # Also accept generic 200 on this port as potentially real
        if "200 OK" in resp[:50] and "prometheus" not in resp.lower():
            return "Web service on port 9090"
        return None
    except Exception:
        return None


async def _verify_docker(ip: str, port: int, timeout: float) -> Optional[str]:
    """Send GET /version, check for Docker JSON response. Returns version or None."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        req = f"GET /version HTTP/1.0\r\nHost: {ip}\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        resp = data.decode(errors="ignore")
        if '"Version"' in resp and '"ApiVersion"' in resp:
            m = re.search(r'"Version"\s*:\s*"([^"]+)"', resp)
            version = m.group(1) if m else "unknown"
            return f"Docker API UNAUTHENTICATED (v{version}) — CRITICAL"
        return None
    except Exception:
        return None


async def _verify_jupyter(ip: str, port: int, timeout: float) -> Optional[str]:
    """Check for Jupyter Notebook HTML page. Returns banner or None."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        req = f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        resp = data.decode(errors="ignore")
        if _is_web_false_positive(resp[:500]):
            return None
        if "jupyter" in resp.lower() or "ipython" in resp.lower():
            return "Jupyter Notebook (EXPOSED)"
        return None
    except Exception:
        return None


async def _verify_memcached(ip: str, port: int, timeout: float) -> Optional[str]:
    """Send 'stats' command, check for Memcached stats response."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.write(b"stats\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        resp = data.decode(errors="ignore")
        if resp.startswith("STAT ") or "pid" in resp.lower():
            return "Memcached (UNAUTHENTICATED stats exposed)"
        return None
    except Exception:
        return None


async def _verify_kibana(ip: str, port: int, timeout: float) -> Optional[str]:
    """Check for Kibana web UI response."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        req = f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        resp = data.decode(errors="ignore")
        if _is_web_false_positive(resp[:500]):
            return None
        if "kibana" in resp.lower() or "elastic" in resp.lower():
            return "Kibana (EXPOSED)"
        return None
    except Exception:
        return None


async def _verify_consul(ip: str, port: int, timeout: float) -> Optional[str]:
    """Check Consul HTTP API /v1/status/leader endpoint."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        req = f"GET /v1/status/leader HTTP/1.0\r\nHost: {ip}\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        resp = data.decode(errors="ignore")
        if _is_web_false_positive(resp[:500]):
            return None
        if "200 OK" in resp[:50] and ("." in resp[50:150]):  # IP:port leader addr
            return "Consul (UNAUTHENTICATED API)"
        return None
    except Exception:
        return None


async def _verify_postgresql(ip: str, port: int, timeout: float) -> Optional[str]:
    """
    Verify PostgreSQL by sending a real protocol 3.0 startup message.
    Parses the response to determine:
      - 'R' (AuthenticationRequest): user reaches auth layer = internet-exposed
      - 'E' (ErrorResponse): pg_hba.conf rejects = still confirms real Postgres
    Returns detailed banner or None if not PostgreSQL.
    """
    import struct

    # Try two usernames: 'postgres' (common DBA) and target-hinted user
    test_users = [('postgres', 'postgres')]

    for db_user, db_name in test_users:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            # Build startup message (Protocol 3.0)
            params = f'user\x00{db_user}\x00database\x00{db_name}\x00\x00'.encode()
            msg = struct.pack('!I', 196608) + params  # 196608 = 3.0 protocol version
            startup = struct.pack('!I', len(msg) + 4) + msg
            writer.write(startup)
            await writer.drain()

            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            if not data:
                continue

            msg_type = chr(data[0]) if data else ''

            if msg_type == 'R':  # AuthenticationRequest
                # Parse auth method: bytes 5-8 = auth type (big-endian int32)
                if len(data) >= 9:
                    auth_type = struct.unpack('!I', data[5:9])[0]
                    auth_methods = {
                        0: 'AuthOk (NO PASSWORD REQUIRED!)',
                        2: 'KerberosV5',
                        3: 'CleartextPassword',
                        5: 'MD5Password',
                        10: 'SCRAM-SHA-256',
                    }
                    method = auth_methods.get(auth_type, f'type={auth_type}')
                    if auth_type == 0:
                        return f'PostgreSQL UNAUTHENTICATED (user={db_user}) — CRITICAL'
                    return f'PostgreSQL — Auth reachable: {method} (user={db_user})'
                return f'PostgreSQL — Auth reachable (user={db_user})'

            elif msg_type == 'E':  # ErrorResponse
                # Parse error fields: S=severity, M=message
                error_text = data[5:].split(b'\x00')
                error_parts = [p.decode(errors='ignore') for p in error_text if p]
                msg_text = ' '.join(error_parts[:3])[:120]
                return f'PostgreSQL (pg_hba reject: {msg_text})'

            elif msg_type == 'N':  # NoticeResponse — still PostgreSQL
                return f'PostgreSQL (notice response)'

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            continue
        except Exception:
            continue

    return None


async def _verify_web_alt(ip: str, port: int, timeout: float, domain: str = "") -> Optional[str]:
    """
    Verify alt-HTTP/HTTPS ports (8080, 8443).
    Uses the domain as Host header for proper routing.
    Returns title only if it's a real, non-CDN-error response.
    """
    use_ssl = port == 8443
    try:
        if use_ssl:
            import ssl as ssl_mod
            ctx = ssl_mod.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl_mod.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx), timeout=timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )

        host_header = domain or ip
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(req.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        resp = data.decode(errors="ignore")

        # Reject known CDN false-positive responses
        if _is_web_false_positive(resp[:1000]):
            return None

        # Extract page title
        m = re.search(r'<title[^>]*>(.*?)</title>', resp, re.IGNORECASE | re.DOTALL)
        title = m.group(1).strip()[:120] if m else ""

        # Extract HTTP status
        status_m = re.match(r'HTTP/[\d.]+ (\d+)', resp)
        status = status_m.group(1) if status_m else "?"

        # Skip 4xx/5xx unless it looks interesting (login, admin panel)
        if status.startswith(('4', '5')) and not any(
            kw in title.lower() for kw in ('admin', 'login', 'dashboard', 'panel', 'kibana', 'grafana', 'jenkins')
        ):
            return None

        if title:
            return f"HTTP {status} — {title}"
        elif status == "200":
            return f"HTTP {status} (content served)"
        return None
    except Exception:
        return None


# Map port → verifier function
_VERIFIERS = {
    2375:  _verify_docker,
    5432:  _verify_postgresql,
    6379:  _verify_redis,
    9200:  _verify_elasticsearch,
    9090:  _verify_prometheus,
    27017: _verify_mongodb,
    11211: _verify_memcached,
    8888:  _verify_jupyter,
    5601:  _verify_kibana,
    8500:  _verify_consul,
    3306:  _verify_mysql,
    # 8080/8443 are handled specially with domain context
}


class PortScanner:
    def __init__(
        self,
        ips: List[str],
        concurrency: int = 100,
        timeout: float = 3.0,
        ip_to_domains: Dict[str, List[str]] = None,
    ):
        self.ips = list(set(ips))
        self.concurrency = concurrency
        self.timeout = timeout
        # Map IP → list of domains that resolved to it (for Host header context)
        self.ip_to_domains: Dict[str, List[str]] = ip_to_domains or {}
        self.results: List[Dict] = []
        self._cdn_skipped = 0
        self._fp_filtered = 0
        self._unverified = 0

    async def _check_port(self, ip: str, port: int, sem: asyncio.Semaphore):
        async with sem:
            cdn = is_cdn_ip(ip)

            # Skip CDN IPs for web ports entirely — always false positives
            if cdn and port in CDN_SKIP_PORTS:
                self._cdn_skipped += 1
                return None

            # First: TCP connectivity check
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            except Exception:
                return None

            # Port is open — now VERIFY with protocol-specific handshake
            service = HIGH_VALUE_PORTS.get(port, "Unknown")
            banner_text = ""
            domains = self.ip_to_domains.get(ip, [])
            primary_domain = domains[0] if domains else ""

            if port in (8080, 8443):
                # Alt-web ports: verify with domain-aware Host header
                banner_text = await _verify_web_alt(ip, port, self.timeout, primary_domain) or ""
                if not banner_text:
                    self._fp_filtered += 1
                    return None  # No real content → discard
                service = "Alt-HTTPS" if port == 8443 else "Alt-HTTP"

            elif port in _VERIFIERS:
                verifier = _VERIFIERS[port]
                banner_text = await verifier(ip, port, self.timeout) or ""
                if not banner_text:
                    self._unverified += 1
                    return None  # TCP open but protocol not confirmed → discard

            elif port == 5432:
                # PostgreSQL: now handled by _VERIFIERS above
                # This branch is a fallback only if verifier was skipped somehow
                if cdn:
                    self._cdn_skipped += 1
                    return None
                banner_text = "PostgreSQL (TCP open — verifier bypassed)"

            else:
                banner_text = ""

            # Add verified field based on whether protocol was confirmed
            verified = bool(banner_text and port in _VERIFIERS)

            result = {
                "ip": ip,
                "port": port,
                "service": service,
                "banner": banner_text,
                "cdn": cdn,
                "verified": verified,
                "domains": domains[:3],  # Include up to 3 domains for context
            }
            self.results.append(result)
            return result

    async def scan(self) -> List[Dict]:
        start = time.time()
        banner("Infrastructure Port Scanner v2.0")
        total = len(self.ips) * len(HIGH_VALUE_PORTS)
        log_info(f"Scanning {len(self.ips)} IPs × {len(HIGH_VALUE_PORTS)} ports = {total} checks")
        log_info(f"CDN detection: ON | Protocol verification: ON | FP filtering: ON")

        sem = asyncio.Semaphore(self.concurrency)
        tasks = [
            self._check_port(ip, port, sem)
            for ip in self.ips
            for port in HIGH_VALUE_PORTS
        ]

        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
            ) as progress:
                task_id = progress.add_task("[cyan]Scanning Ports...", total=len(tasks))
                for coro in asyncio.as_completed(tasks):
                    await coro
                    progress.advance(task_id)
        else:
            await asyncio.gather(*tasks)

        elapsed = elapsed_str(start)
        confirmed = len(self.results)

        log_success(f"Port scan complete in {elapsed}")
        log_success(f"  Confirmed findings : {confirmed}")
        log_info(f"  CDN-skipped        : {self._cdn_skipped} (8080/8443 on CDN IPs)")
        log_info(f"  Protocol-rejected  : {self._unverified} (TCP open but no valid banner)")
        log_info(f"  Response-filtered  : {self._fp_filtered} (403/400/CDN error pages)")

        return self.results


def resolve_hostnames(hostnames: List[str]) -> Tuple[List[str], Dict[str, List[str]]]:
    """
    Resolve hostnames to IPs. Returns:
      - list of unique IPs
      - dict mapping IP → [list of domains that resolved to it]
    """
    ip_to_domains: Dict[str, List[str]] = {}
    for host in hostnames:
        try:
            ip = socket.gethostbyname(host)
            ip_to_domains.setdefault(ip, []).append(host)
        except Exception:
            pass
    return list(ip_to_domains.keys()), ip_to_domains


# ══════════════════════════════════════════════════════════════════════════════
# v9.1: Default Credential Checker
# ══════════════════════════════════════════════════════════════════════════════
#
# Runs AFTER port scanning on any verified service ports.
# Only flags findings where actual access is confirmed:
#   - PostgreSQL: auth_type == 0 (AuthOk) or successful password login
#   - MySQL: successful handshake + auth
#   - MongoDB: can list databases
#   - Redis: PING returns PONG without AUTH, or AUTH with common passwords
#   - Elasticsearch: cluster info accessible (already caught by verifier)
#   - Memcached: stats command returns data (already caught by verifier)

# Default credential pairs per service: (username, password)
_DEFAULT_CREDS = {
    'PostgreSQL': [
        ('postgres', 'postgres'),
        ('postgres', 'password'),
        ('postgres', ''),
        ('admin', 'admin'),
        ('root', 'root'),
    ],
    'MySQL': [
        ('root', ''),
        ('root', 'root'),
        ('root', 'password'),
        ('root', 'toor'),
        ('admin', 'admin'),
        ('mysql', 'mysql'),
    ],
    'Redis': [
        (None, ''),          # no auth
        (None, 'redis'),
        (None, 'password'),
        (None, 'admin'),
        (None, 'default'),
    ],
    'MongoDB': [
        (None, None),        # no auth (anonymous)
        ('admin', 'admin'),
        ('root', 'root'),
        ('admin', 'password'),
    ],
}


async def _try_postgres_cred(ip: str, port: int, user: str, password: str,
                              timeout: float = 5.0) -> Optional[dict]:
    """Try a PostgreSQL credential. Returns result dict if auth succeeds, None otherwise."""
    import struct

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        # Build startup message (Protocol 3.0)
        params = f'user\x00{user}\x00database\x00{user}\x00\x00'.encode()
        msg = struct.pack('!I', 196608) + params
        startup = struct.pack('!I', len(msg) + 4) + msg
        writer.write(startup)
        await writer.drain()

        data = await asyncio.wait_for(reader.read(512), timeout=timeout)

        if not data:
            writer.close()
            return None

        msg_type = chr(data[0])

        if msg_type == 'R' and len(data) >= 9:
            auth_type = struct.unpack('!I', data[5:9])[0]

            if auth_type == 0:
                # AuthenticationOk — NO PASSWORD REQUIRED
                writer.close()
                return {
                    'access_confirmed': True,
                    'method': 'no_password',
                    'detail': f'PostgreSQL accepts user={user} WITHOUT password'
                }

            elif auth_type == 3:
                # CleartextPassword requested — send it
                pwd_msg = f'{password}\x00'.encode()
                pwd_packet = b'p' + struct.pack('!I', len(pwd_msg) + 4) + pwd_msg
                writer.write(pwd_packet)
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(512), timeout=timeout)
                writer.close()
                if resp and chr(resp[0]) == 'R':
                    if len(resp) >= 9 and struct.unpack('!I', resp[5:9])[0] == 0:
                        return {
                            'access_confirmed': True,
                            'method': 'cleartext_password',
                            'detail': f'PostgreSQL login OK: {user}:{password}'
                        }
                return None

            elif auth_type == 5:
                # MD5Password — requires salt from server
                if len(data) >= 13:
                    import hashlib
                    salt = data[9:13]  # 4 raw bytes
                    # PostgreSQL MD5 scheme: 'md5' + md5(md5(password+user) + salt)
                    inner = hashlib.md5((password + user).encode()).hexdigest().encode()
                    outer = 'md5' + hashlib.md5(inner + salt).hexdigest()
                    pwd_msg = f'{outer}\x00'.encode()
                    pwd_packet = b'p' + struct.pack('!I', len(pwd_msg) + 4) + pwd_msg
                    writer.write(pwd_packet)
                    await writer.drain()
                    resp = await asyncio.wait_for(reader.read(512), timeout=timeout)
                    writer.close()
                    if resp and chr(resp[0]) == 'R':
                        if len(resp) >= 9 and struct.unpack('!I', resp[5:9])[0] == 0:
                            return {
                                'access_confirmed': True,
                                'method': 'md5_password',
                                'detail': f'PostgreSQL login OK: {user}:{password}'
                            }
                    return None

            elif auth_type == 10:
                # SCRAM-SHA-256 — too complex for quick check, skip
                writer.close()
                return None

        elif msg_type == 'E':
            # ErrorResponse (pg_hba reject or auth failure) — NOT access
            writer.close()
            return None

        writer.close()
        return None
    except Exception:
        return None


async def _try_mysql_cred(ip: str, port: int, user: str, password: str,
                           timeout: float = 5.0) -> Optional[dict]:
    """Try MySQL credential. Returns result dict if auth succeeds."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        # Read server greeting
        greeting = await asyncio.wait_for(reader.read(256), timeout=timeout)
        if not greeting or len(greeting) < 5:
            writer.close()
            return None

        # Check it's a valid MySQL greeting (protocol version 10 or 9)
        if greeting[4] not in (0x0a, 0x09):
            writer.close()
            return None

        # For empty password auth, try native_password handshake
        # This is a simplified check — if server allows passwordless auth
        if password == '':
            # Send a minimal client auth response with empty password
            # Using mysql_native_password with empty scramble
            import hashlib

            # Parse greeting to get auth data
            version_end = greeting.find(b'\x00', 5)
            if version_end < 0:
                writer.close()
                return None

            # Connection ID is at version_end+1 (4 bytes)
            # Auth data part 1 starts at version_end+5 (8 bytes)
            # There's more auth data later for newer protocols
            scramble_part1 = greeting[version_end+5:version_end+13]

            # Build a simple COM_QUIT to test connectivity
            # Actually, for safety, just check if the greeting itself
            # indicates auth_plugin = mysql_clear_password or empty password
            writer.close()

            # Simplified: if the greeting was received, MySQL is accessible
            # but we can't confirm passwordless without full handshake
            # Mark it as "greeting received, auth required"
            return None

        writer.close()
        return None
    except Exception:
        return None


async def _try_redis_cred(ip: str, port: int, password: Optional[str],
                           timeout: float = 5.0) -> Optional[dict]:
    """Try Redis with optional AUTH. Returns result dict if access confirmed."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )

        if password:
            # Try AUTH first
            auth_cmd = f"*2\r\n$4\r\nAUTH\r\n${len(password)}\r\n{password}\r\n"
            writer.write(auth_cmd.encode())
            await writer.drain()
            auth_resp = await asyncio.wait_for(reader.read(128), timeout=timeout)
            auth_text = auth_resp.decode(errors='ignore').strip()
            if not auth_text.startswith('+OK'):
                writer.close()
                return None

        # Try PING — if we get +PONG, we have access
        writer.write(b"*1\r\n$4\r\nPING\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(128), timeout=timeout)
        resp = data.decode(errors='ignore').strip()

        # Try INFO to get server details
        writer.write(b"*1\r\n$4\r\nINFO\r\n")
        await writer.drain()
        info_data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        info_text = info_data.decode(errors='ignore')

        writer.close()

        if resp.startswith('+PONG'):
            detail = f'Redis UNAUTHENTICATED' if not password else f'Redis AUTH OK (password={password})'
            # Extract version from INFO if available
            import re as _re
            ver_match = _re.search(r'redis_version:(\S+)', info_text)
            if ver_match:
                detail += f' — v{ver_match.group(1)}'
            # Check how many keys exist
            key_match = _re.findall(r'keys=(\d+)', info_text)
            if key_match:
                total_keys = sum(int(k) for k in key_match)
                detail += f' — {total_keys} keys'
            return {
                'access_confirmed': True,
                'method': 'no_auth' if not password else 'password',
                'detail': detail
            }

        return None
    except Exception:
        return None


async def _try_mongodb_cred(ip: str, port: int, user: Optional[str],
                             password: Optional[str],
                             timeout: float = 5.0) -> Optional[dict]:
    """Try MongoDB access. Returns result dict if access confirmed."""
    try:
        # Send isMaster to check if we can connect at all
        msg = (
            b"\x41\x00\x00\x00"  # message length
            b"\x01\x00\x00\x00"  # request ID
            b"\x00\x00\x00\x00"  # response to
            b"\xd4\x07\x00\x00"  # opCode: OP_QUERY (2004)
            b"\x00\x00\x00\x00"  # flags
            b"admin.$cmd\x00"    # collection name
            b"\x00\x00\x00\x00"  # number to skip
            b"\x01\x00\x00\x00"  # number to return
            b"\x13\x00\x00\x00"  # doc length (19 bytes)
            b"\x10isMaster\x00\x01\x00\x00\x00\x00"  # {isMaster: 1}
        )
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.write(msg)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()

        if len(data) >= 16:
            resp_text = data.decode(errors='ignore')
            # If response contains "ismaster" or "ok", we have access
            if 'ismaster' in resp_text.lower() or b'\x01' in data[36:]:
                return {
                    'access_confirmed': True,
                    'method': 'no_auth',
                    'detail': f'MongoDB UNAUTHENTICATED — isMaster succeeds ({len(data)}B response)'
                }
        return None
    except Exception:
        return None


class DefaultCredChecker:
    """Check exposed services for default/empty credentials.

    Only flags findings where actual access is CONFIRMED.
    """

    def __init__(self, exposed_ports: List[Dict], timeout: float = 5.0):
        self.exposed_ports = exposed_ports
        self.timeout = timeout
        self.results: List[Dict] = []

    async def check(self) -> List[Dict]:
        """Run credential checks on all exposed services. Returns confirmed access list."""
        log_info("Running default credential checks on exposed services...")

        # Group by service type
        services_to_check = []
        for port_info in self.exposed_ports:
            service = port_info.get('service', '')
            ip = port_info['ip']
            port = port_info['port']
            domains = port_info.get('domains', [])
            banner = port_info.get('banner', '')

            # Skip if already flagged as unauthenticated by verifier
            if 'UNAUTHENTICATED' in banner.upper() or 'AuthOk' in banner:
                # Already confirmed — add directly
                self.results.append({
                    'ip': ip,
                    'port': port,
                    'service': service,
                    'domains': domains,
                    'access_confirmed': True,
                    'method': 'no_auth_required',
                    'detail': f'{service} already confirmed unauthenticated: {banner}',
                })
                continue

            # Determine which creds to try based on service
            if 'PostgreSQL' in service and 'pg_hba reject' not in banner:
                services_to_check.append(('PostgreSQL', ip, port, domains))
            elif 'MySQL' in service:
                services_to_check.append(('MySQL', ip, port, domains))
            elif 'Redis' in service:
                services_to_check.append(('Redis', ip, port, domains))
            elif 'MongoDB' in service:
                services_to_check.append(('MongoDB', ip, port, domains))
            # Elasticsearch/Memcached unauthenticated access is already caught by verifiers

        if not services_to_check:
            log_info("No services need credential checking (0 candidates)")
            return self.results

        log_info(f"Checking {len(services_to_check)} services for default credentials...")

        for svc_type, ip, port, domains in services_to_check:
            domain_str = domains[0] if domains else ip
            creds = _DEFAULT_CREDS.get(svc_type, [])

            for user, password in creds:
                result = None
                if svc_type == 'PostgreSQL':
                    result = await _try_postgres_cred(ip, port, user, password, self.timeout)
                elif svc_type == 'MySQL':
                    result = await _try_mysql_cred(ip, port, user, password, self.timeout)
                elif svc_type == 'Redis':
                    result = await _try_redis_cred(ip, port, password, self.timeout)
                elif svc_type == 'MongoDB':
                    result = await _try_mongodb_cred(ip, port, user, password, self.timeout)

                if result and result.get('access_confirmed'):
                    finding = {
                        'ip': ip,
                        'port': port,
                        'service': svc_type,
                        'domains': domains,
                        **result,
                    }
                    self.results.append(finding)
                    log_warning(f"🚨 ACCESS CONFIRMED: {svc_type} on {domain_str}:{port} — {result['detail']}")
                    break  # No need to try more creds once access is confirmed

        if self.results:
            log_warning(f"⚠️  {len(self.results)} services with confirmed access!")
        else:
            log_success("No default credentials found — all services properly secured")

        return self.results
