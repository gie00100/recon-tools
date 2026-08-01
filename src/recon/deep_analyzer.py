#!/usr/bin/env python3
"""
Deep Findings Analyzer — Post-scan triage and active verification.

Scans output/ and all_output/ directories for high-value findings,
ranks them by exploitability based on real HackerOne outcomes,
and optionally performs active HTTP verification on config/debug URLs.

Usage:
  python deep_analyzer.py                    # Analyze output/ only
  python deep_analyzer.py --all              # Analyze output/ + all_output/
  python deep_analyzer.py --verify           # Also do active HTTP verification
  python deep_analyzer.py --output report.md # Write triage report
"""

import argparse
import asyncio
import json
import re
import ssl
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, unquote

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

# ══════════════════════════════════════════════════════════════════════════════
# EXPLOITABILITY TIERS — learned from real HackerOne outcomes
# ══════════════════════════════════════════════════════════════════════════════

# Tier 1: Report immediately — high acceptance rate
TIER_1_TYPES = {
    'Credential_In_URL',           # email:password in URL — always CRITICAL
    'Keycloak_Action_Token',       # password reset JWTs — confirmed reportable
    'Password_Reset_Param',        # reset tokens in params
    'Password_Reset_UUID',         # UUID reset tokens — zero FP
}

# Tier 2: Verify first — good signal but needs confirmation
TIER_2_TYPES = {
    'JWT_In_URL',                  # JWTs on auth/KYC endpoints — real if on prod
    'Signed_Document_URL',         # Signed invoices — real if still valid
    'Token_Leak',                  # API keys — real if service-specific prefix
    'Cloud_Storage_Exposure',      # Pre-signed S3 URLs
    'API_Spec_Exposed',            # openapi.yaml on prod
    'Metrics_Endpoint',            # /metrics, /actuator on prod
    'Staging_Environment',         # Live staging/test/preprod hosts
    'JS_URL_with_Credentials',     # Embedded credentials in JS URLs
    'URL with Credentials',
}

# Tier 3: Low priority — mostly noise from passive analysis
TIER_3_TYPES = {
    'PII_Email_Leak',              # 44% of all findings, mostly marketing
    'IDOR_Endpoint',               # Mostly doc/blog paths
    'PII_Data_Leak',               # Rare, usually FP
    'SSRF_Param',                  # Can't verify without active testing
}

# Patterns that HackerOne consistently rejects — skip these
REJECTED_PATTERNS = [
    # Invitation links — designed behavior
    (r'accept-invitation|accept_invitation|invite.*token', 'Invitation link (designed behavior)'),
    # Email marketing tracking
    (r'ablink\.|/ls/click\?|/wf/click\?|emailblastid|utm_medium=email', 'Email tracking link'),
    # HubSpot/SendGrid managed URLs
    (r'hubspot\.com|sendgrid\.com|mailchimp\.com', 'Third-party email platform'),
    # OAuth login_hint (standard OIDC)
    (r'/oauth2?/auth.*login_hint|/authorize.*login_hint', 'OAuth login_hint (standard)'),
    # Adjust/AppsFlyer deep links
    (r'adjust\.com|appsflyer\.com|af_sig=', 'Mobile attribution deep link'),
]


def _get_tier(finding_type: str) -> int:
    """Return exploitability tier (1=best, 3=lowest)."""
    if finding_type in TIER_1_TYPES:
        return 1
    if finding_type in TIER_2_TYPES:
        return 2
    return 3


def _is_rejected_pattern(url: str) -> Optional[str]:
    """Return rejection reason if URL matches a known rejected pattern."""
    lower = url.lower()
    for pattern, reason in REJECTED_PATTERNS:
        if re.search(pattern, lower):
            return reason
    return None


# ══════════════════════════════════════════════════════════════════════════════
# FINDING ENRICHMENT
# ══════════════════════════════════════════════════════════════════════════════

def _enrich_finding(finding: dict) -> dict:
    """Add exploitability metadata to a finding."""
    f = finding.copy()
    url = f.get('url', '')
    ftype = f.get('type', '')
    evidence = f.get('evidence', '')

    # Tier
    f['tier'] = _get_tier(ftype)

    # Rejection check
    rejection = _is_rejected_pattern(url)
    if rejection:
        f['rejected'] = rejection
        f['tier'] = 99  # Push to bottom

    # Token subclass enrichment
    if ftype == 'Token_Leak' and evidence:
        if any(prefix in evidence for prefix in ['sk_live_', 'rk_live_', 'pk_live_']):
            f['tier'] = 1  # Stripe live keys = critical
            f['subclass'] = 'Stripe Live Key'
        elif any(prefix in evidence for prefix in ['ghp_', 'glpat-', 'xoxb-', 'xoxp-', 'SG.']):
            f['tier'] = 1  # Known service tokens
            f['subclass'] = 'Service-Specific Secret'
        elif 'autologin_token' in evidence:
            f['tier'] = 1
            f['subclass'] = 'Autologin Token'
        elif 'oauth_token' in evidence:
            f['tier'] = 1
            f['subclass'] = 'OAuth Token'
        elif 'session_id' in evidence and 'expire' in evidence:
            f['tier'] = 1
            f['subclass'] = 'Live Session+Expiry'

    # Signed document: check if still valid
    if ftype == 'Signed_Document_URL' and evidence:
        if 'STILL VALID' in evidence:
            f['tier'] = 1
            f['subclass'] = 'Still Valid — Access Now'
        else:
            f['tier'] = 3
            f['subclass'] = 'Expired — Pattern Confirmed'

    # JWT enrichment: check if on auth/KYC/reset endpoint
    if ftype == 'JWT_In_URL':
        path_lower = urlparse(url).path.lower()
        if any(k in path_lower for k in ['/kyc', '/reset', '/action-token', '/verify',
                                          '/autologin', '/magic-link']):
            f['tier'] = 1
            f['subclass'] = 'JWT on Auth/Reset Endpoint'
        elif '/login-actions/' in path_lower:
            f['tier'] = 1
            f['subclass'] = 'Keycloak Action Token'

    # Credential enrichment
    if ftype == 'Credential_In_URL':
        f['subclass'] = 'Plaintext Credentials'
        if 'EMAIL_CRED_IN_PATH' in evidence or 'PHONE_CRED_IN_PATH' in evidence:
            f['subclass'] = 'VirusTotal Credential Submission'

    # Domain extraction
    try:
        f['domain'] = urlparse(url).netloc.lower()
    except Exception:
        f['domain'] = ''

    return f


# ══════════════════════════════════════════════════════════════════════════════
# ACTIVE HTTP VERIFICATION
# ══════════════════════════════════════════════════════════════════════════════

# Content markers that confirm a finding is real (not 401/403/generic error page)
VERIFICATION_MARKERS = {
    '.env': [b'DB_HOST=', b'DB_PASSWORD=', b'API_KEY=', b'SECRET_KEY=',
             b'APP_KEY=', b'MAIL_PASSWORD=', b'AWS_SECRET'],
    '.git/config': [b'[core]', b'[remote', b'repositoryformatversion'],
    '.git/HEAD': [b'ref: refs/heads/'],
    'phpinfo': [b'phpinfo()', b'PHP Version', b'Configure Command'],
    'server-status': [b'Apache Server Status', b'Total Accesses'],
    'actuator/env': [b'propertySources', b'activeProfiles'],
    'actuator/heapdump': [b'JAVA PROFILE'],  # Binary header
    'swagger-ui': [b'swagger-ui', b'Swagger UI', b'openapi'],
    'openapi': [b'"openapi"', b'openapi:', b'"paths"', b'paths:'],
    'metrics': [b'# HELP', b'# TYPE', b'process_cpu', b'jvm_memory'],
}


def _get_verification_markers(url: str) -> list:
    """Return the content markers to check for this URL type."""
    path = urlparse(url).path.lower()
    for key, markers in VERIFICATION_MARKERS.items():
        if key in path:
            return markers
    return []


async def _verify_url(session: 'aiohttp.ClientSession', url: str) -> dict:
    """Actively fetch a URL and check if it returns exploitable content."""
    markers = _get_verification_markers(url)
    if not markers:
        return {'verified': None, 'reason': 'no_markers'}

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                               allow_redirects=True, ssl=False) as resp:
            status = resp.status
            if status in (401, 403, 404, 405, 500, 502, 503):
                return {'verified': False, 'reason': f'HTTP {status}'}

            body = await resp.read()
            body_lower = body[:10000].lower()

            matched = [m for m in markers if m.lower() in body_lower]
            if matched:
                return {
                    'verified': True,
                    'reason': f'HTTP {status} — content confirmed',
                    'status': status,
                    'content_size': len(body),
                    'matched_markers': [m.decode(errors='replace') for m in matched[:3]],
                }
            else:
                return {'verified': False, 'reason': f'HTTP {status} but no expected content'}
    except asyncio.TimeoutError:
        return {'verified': False, 'reason': 'timeout'}
    except Exception as e:
        return {'verified': False, 'reason': str(e)[:80]}


async def verify_findings(findings: List[dict], concurrency: int = 10) -> List[dict]:
    """Actively verify a list of findings via HTTP."""
    if not HAS_AIOHTTP:
        print("[!] aiohttp not available — skipping active verification")
        return findings

    # Only verify URL-based findings that benefit from active checking
    verifiable_types = {'API_Spec_Exposed', 'Metrics_Endpoint', 'Config_File_Exposed',
                        'Debug_Admin_Panel', 'Signed_Document_URL'}
    to_verify = [f for f in findings if f.get('type') in verifiable_types]

    if not to_verify:
        return findings

    print(f"[*] Actively verifying {len(to_verify)} URLs...")
    sem = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)
    async with aiohttp.ClientSession(connector=connector) as session:
        async def _check(finding):
            async with sem:
                result = await _verify_url(session, finding['url'])
                finding['verification'] = result
                if result.get('verified'):
                    finding['tier'] = 1  # Promote to Tier 1 if verified
                    print(f"  [+] VERIFIED: {finding['url'][:80]}")
                return finding

        tasks = [_check(f) for f in to_verify]
        await asyncio.gather(*tasks, return_exceptions=True)

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# EXPOSED PORTS ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

def _collect_exposed_ports(scan_dirs: List[Path]) -> List[dict]:
    """Collect all exposed ports across all scan directories.
    Applies CDN IP filtering even on older data that may not have had it."""
    # Try to import CDN checker from port_scanner
    try:
        from recon.port_scanner import is_cdn_ip
    except ImportError:
        is_cdn_ip = lambda ip: False

    # High-value database/service ports worth reporting (filter out web noise)
    HIGH_VALUE_PORTS = {5432, 3306, 27017, 6379, 9200, 2375, 8888, 5601, 8500, 9090, 11211}

    ports = []
    seen = set()  # dedup by ip:port

    for scan_dir in scan_dirs:
        ep_file = scan_dir / 'exposed_ports.json'
        if not ep_file.exists():
            continue
        try:
            data = json.loads(ep_file.read_text(encoding='utf-8', errors='replace'))
            if not isinstance(data, list):
                continue
            for entry in data:
                ip = entry.get('ip', '')
                port = entry.get('port', 0)
                key = f"{ip}:{port}"
                if key in seen:
                    continue
                seen.add(key)

                # Skip CDN IPs (retroactive filtering for older data)
                if entry.get('cdn', False) or is_cdn_ip(ip):
                    continue

                # Require protocol verification or non-empty banner (eliminates TCP-open false positives)
                if not entry.get('verified', False) and not entry.get('banner'):
                    continue

                # Filter out Alt-Web ports (8080/8443) — these are standard web servers, not exposed DBs
                if port not in HIGH_VALUE_PORTS:
                    continue

                entry['tier'] = 1
                entry['source_dir'] = str(scan_dir)
                ports.append(entry)
        except Exception:
            continue

    return ports


# ══════════════════════════════════════════════════════════════════════════════
# SCANNER
# ══════════════════════════════════════════════════════════════════════════════

def _collect_scan_dirs(output_root: Path) -> List[Path]:
    """Collect all scan directories (handles both flat and nested structures)."""
    scan_dirs = []
    if not output_root.exists():
        return scan_dirs

    for entry in output_root.iterdir():
        if not entry.is_dir():
            continue
        # Check if entry itself contains scan files (flat structure)
        if (entry / 'report.json').exists() or (entry / 'bounty_targets.json').exists():
            scan_dirs.append(entry)
        else:
            # Nested: entry is domain dir, subdirs are timestamped scans
            for sub in entry.iterdir():
                if sub.is_dir() and ((sub / 'report.json').exists() or
                                      (sub / 'bounty_targets.json').exists()):
                    scan_dirs.append(sub)
    return scan_dirs


def collect_all_findings(scan_dirs: List[Path]) -> List[dict]:
    """Collect and enrich all findings across bounty_targets.json, staging_environments.json, and js_url_credentials.json."""
    all_findings = []

    for scan_dir in scan_dirs:
        # Extract program domain
        parts = scan_dir.parts
        program_domain = 'unknown'
        for i, p in enumerate(parts):
            if p in ('output', 'all_output') or p.startswith('output_'):
                if i + 1 < len(parts):
                    program_domain = parts[i + 1]
                    break

        # 1. Read bounty_targets.json
        bt_file = scan_dir / 'bounty_targets.json'
        if bt_file.exists():
            try:
                data = json.loads(bt_file.read_text(encoding='utf-8', errors='replace'))
                findings = data.get('findings', []) if isinstance(data, dict) else data
                if isinstance(findings, list):
                    for f in findings:
                        f['source_dir'] = str(scan_dir)
                        f['program_domain'] = program_domain
                        all_findings.append(_enrich_finding(f))
            except Exception:
                pass

        # 2. Read staging_environments.json
        se_file = scan_dir / 'staging_environments.json'
        if se_file.exists():
            try:
                data = json.loads(se_file.read_text(encoding='utf-8', errors='replace'))
                envs = data.get('environments', []) if isinstance(data, dict) else []
                for env in envs:
                    env['source_dir'] = str(scan_dir)
                    env['program_domain'] = program_domain
                    all_findings.append(_enrich_finding(env))
            except Exception:
                pass

        # 3. Read js_url_credentials.json
        cred_file = scan_dir / 'js_url_credentials.json'
        if cred_file.exists():
            try:
                data = json.loads(cred_file.read_text(encoding='utf-8', errors='replace'))
                creds = data.get('credentials', []) if isinstance(data, dict) else []
                for c in creds:
                    c['source_dir'] = str(scan_dir)
                    c['program_domain'] = program_domain
                    all_findings.append(_enrich_finding(c))
            except Exception:
                pass

    return all_findings


def generate_triage_report(findings: List[dict], exposed_ports: List[dict],
                           output_path: Optional[str] = None) -> str:
    """Generate a prioritized triage report."""
    # Sort: tier ASC, then severity (CRITICAL > HIGH > MEDIUM)
    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    findings.sort(key=lambda f: (f.get('tier', 99), sev_order.get(f.get('severity', 'LOW'), 9)))

    lines = []
    lines.append("# 🎯 Deep Findings Triage Report")
    lines.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"**Total findings:** {len(findings)}")
    lines.append(f"**Exposed ports:** {len(exposed_ports)}")

    # Summary stats
    tier_counts = defaultdict(int)
    for f in findings:
        tier_counts[f.get('tier', 99)] += 1
    rejected_count = tier_counts.pop(99, 0)

    lines.append("\n## Summary")
    lines.append(f"| Tier | Count | Action |")
    lines.append(f"|---|---|---|")
    lines.append(f"| 🔴 Tier 1 (Report Now) | {tier_counts.get(1, 0)} | Submit to HackerOne immediately |")
    lines.append(f"| 🟡 Tier 2 (Verify First) | {tier_counts.get(2, 0)} | Manually verify, then report |")
    lines.append(f"| ⚪ Tier 3 (Low Priority) | {tier_counts.get(3, 0)} | Investigate if time permits |")
    lines.append(f"| ❌ Rejected | {rejected_count} | Skip — HackerOne will reject |")

    # Exposed Ports section (always Tier 1)
    if exposed_ports:
        lines.append("\n---\n## 🔴 Exposed Database & Infrastructure Ports (Tier 1)")
        lines.append("> [!CAUTION]")
        lines.append("> Unauthenticated database and management infrastructure ports (PostgreSQL, MySQL, Redis, MongoDB, Elastic, Docker API).")
        lines.append("")
        lines.append("| IP | Port | Service | Domains |")
        lines.append("|---|---|---|---|")
        for p in exposed_ports:
            domains = ', '.join(p.get('domains', []))
            lines.append(f"| `{p.get('ip')}` | {p.get('port')} | {p.get('service')} | {domains} |")

    # Tier 1 findings
    t1 = [f for f in findings if f.get('tier') == 1]
    if t1:
        lines.append("\n---\n## 🔴 Tier 1 — Report Now")
        lines.append("> [!IMPORTANT]")
        lines.append("> These findings have proven HackerOne acceptance. Report immediately.")
        lines.append("")
        for f in t1:
            subclass = f.get('subclass', f.get('type'))
            verified = f.get('verification', {})
            v_status = " ✅ VERIFIED" if verified.get('verified') else ""
            lines.append(f"### [{subclass}] {f.get('domain', 'unknown')}{v_status}")
            lines.append(f"- **Type:** `{f.get('type')}`")
            lines.append(f"- **Severity:** {f.get('severity')}")
            if f.get('evidence'):
                lines.append(f"- **Evidence:** `{f['evidence'][:120]}`")
            lines.append(f"- **URL:** `{f.get('url', '')[:200]}`")
            if verified.get('matched_markers'):
                lines.append(f"- **Verified content:** {', '.join(verified['matched_markers'])}")
            lines.append("")

    # Tier 2 findings
    t2 = [f for f in findings if f.get('tier') == 2]
    if t2:
        lines.append("\n---\n## 🟡 Tier 2 — Verify First")
        # Group by type for cleaner reading
        by_type = defaultdict(list)
        for f in t2:
            by_type[f.get('type', 'unknown')].append(f)

        for ftype, group in sorted(by_type.items()):
            lines.append(f"\n### {ftype} ({len(group)} findings)")
            for f in group[:10]:  # Cap at 10 per type
                ev = f.get('evidence', '')[:80]
                domain = f.get('domain', '')
                lines.append(f"- `{domain}` — {ev}")
            if len(group) > 10:
                lines.append(f"- ... and {len(group) - 10} more")

    # Tier 3 summary (just counts, not individual findings)
    t3 = [f for f in findings if f.get('tier') == 3]
    if t3:
        lines.append("\n---\n## ⚪ Tier 3 — Low Priority")
        by_type = defaultdict(int)
        for f in t3:
            by_type[f.get('type', 'unknown')] += 1
        lines.append("| Type | Count | Note |")
        lines.append("|---|---|---|")
        for ftype, count in sorted(by_type.items(), key=lambda x: -x[1]):
            note = {
                'PII_Email_Leak': 'Mostly marketing/transactional email noise',
                'IDOR_Endpoint': 'Requires manual verification of auth',
                'PII_Data_Leak': 'Check if real PII or template',
                'SSRF_Param': 'Needs active testing to confirm',
            }.get(ftype, '')
            lines.append(f"| {ftype} | {count} | {note} |")

    # Rejected findings summary
    rejected = [f for f in findings if f.get('tier') == 99]
    if rejected:
        lines.append(f"\n---\n## ❌ Rejected ({len(rejected)} findings)")
        lines.append("These match patterns HackerOne has consistently rejected:")
        by_reason = defaultdict(int)
        for f in rejected:
            by_reason[f.get('rejected', 'unknown')] += 1
        for reason, count in sorted(by_reason.items(), key=lambda x: -x[1]):
            lines.append(f"- **{reason}**: {count} findings")

    report = '\n'.join(lines)

    if output_path:
        Path(output_path).write_text(report, encoding='utf-8')
        print(f"\n[+] Triage report saved to {output_path}")

    return report


# ══════════════════════════════════════════════════════════════════════════════
# CLOUD METADATA / INTERNAL IP DETECTION
# ══════════════════════════════════════════════════════════════════════════════

CLOUD_METADATA_PATTERNS = [
    (r'169\.254\.169\.254', 'AWS/Azure metadata endpoint'),
    (r'metadata\.google\.internal', 'GCP metadata endpoint'),
    (r'100\.100\.100\.200', 'Alibaba Cloud metadata'),
    (r'fd00:ec2::254', 'AWS IMDSv2 IPv6'),
]

INTERNAL_IP_RE = re.compile(
    r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3})'
)


def scan_urls_for_cloud_metadata(scan_dirs: List[Path]) -> List[dict]:
    """Scan unique_urls.txt files for cloud metadata and internal IP references."""
    findings = []

    for scan_dir in scan_dirs:
        urls_file = scan_dir / 'unique_urls.txt'
        if not urls_file.exists():
            continue

        try:
            content = urls_file.read_text(encoding='utf-8', errors='replace')
        except Exception:
            continue

        for line in content.splitlines():
            url = line.strip()
            if not url:
                continue

            # Cloud metadata endpoints
            for pattern, desc in CLOUD_METADATA_PATTERNS:
                if re.search(pattern, url, re.I):
                    findings.append({
                        'type': 'Cloud_Metadata_SSRF',
                        'severity': 'CRITICAL',
                        'tier': 1,
                        'url': url,
                        'evidence': desc,
                        'source_dir': str(scan_dir),
                    })
                    break

            # Internal IPs in URLs that target external domains (SSRF indicators)
            try:
                parsed = urlparse(url)
                # Only flag if the URL host is external but contains internal IPs in params/path
                host = parsed.hostname or ''
                if not INTERNAL_IP_RE.match(host):
                    # Check params and path for internal IPs
                    rest = parsed.path + '?' + (parsed.query or '')
                    internal_match = INTERNAL_IP_RE.search(rest)
                    if internal_match:
                        findings.append({
                            'type': 'Internal_IP_Reference',
                            'severity': 'HIGH',
                            'tier': 2,
                            'url': url[:300],
                            'evidence': f'Internal IP {internal_match.group()} in URL params/path',
                            'source_dir': str(scan_dir),
                        })
            except Exception:
                continue

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description='Deep Findings Analyzer — Post-scan Triage')
    parser.add_argument('--all', action='store_true',
                        help='Also scan all_output/ directories')
    parser.add_argument('--verify', action='store_true',
                        help='Actively verify config/debug/API spec URLs via HTTP')
    parser.add_argument('--output', '-o', type=str, default=None,
                        help='Output path for triage report (markdown)')
    parser.add_argument('--output-dir', type=str, default=None,
                        help='Override output directory path')
    args = parser.parse_args()

    # Find project root (script is at src/recon/deep_analyzer.py)
    script_dir = Path(__file__).parent.parent.parent  # → project root
    output_dir = Path(args.output_dir) if args.output_dir else script_dir / 'output'

    print("=" * 60)
    print("  Deep Findings Analyzer — Post-scan Triage")
    print("=" * 60)

    # Collect scan directories
    scan_dirs = _collect_scan_dirs(output_dir)
    print(f"[*] Found {len(scan_dirs)} scan directories in output/")

    if args.all:
        all_output_dir = script_dir / 'all_output'
        if all_output_dir.exists():
            for batch_dir in all_output_dir.iterdir():
                if batch_dir.is_dir():
                    batch_scans = _collect_scan_dirs(batch_dir)
                    scan_dirs.extend(batch_scans)
            print(f"[*] Total scan directories (incl. all_output): {len(scan_dirs)}")

    # Phase 1: Collect bounty_targets findings
    print(f"\n[*] Phase 1: Collecting bounty_targets findings...")
    findings = collect_all_findings(scan_dirs)
    print(f"    Found {len(findings)} total findings")

    # Phase 2: Collect exposed ports
    print(f"[*] Phase 2: Collecting exposed ports...")
    exposed_ports = _collect_exposed_ports(scan_dirs)
    print(f"    Found {len(exposed_ports)} exposed non-CDN ports")

    # Phase 3: Scan for cloud metadata / internal IPs
    print(f"[*] Phase 3: Scanning for cloud metadata / internal IPs...")
    cloud_findings = scan_urls_for_cloud_metadata(scan_dirs)
    print(f"    Found {len(cloud_findings)} cloud metadata / internal IP references")
    findings.extend(cloud_findings)

    # Phase 4: Active HTTP verification (optional)
    if args.verify:
        print(f"[*] Phase 4: Active HTTP verification...")
        findings = asyncio.run(verify_findings(findings))
    else:
        print(f"[*] Phase 4: Skipped (use --verify to enable)")

    # Phase 5: Generate triage report
    print(f"\n[*] Phase 5: Generating triage report...")
    report_path = args.output or str(script_dir / 'triage_report.md')
    report = generate_triage_report(findings, exposed_ports, report_path)

    # Console summary
    tier_counts = defaultdict(int)
    for f in findings:
        tier_counts[f.get('tier', 99)] += 1

    print(f"\n{'=' * 60}")
    print(f"  TRIAGE SUMMARY")
    print(f"{'=' * 60}")
    print(f"  🔴 Tier 1 (Report Now):     {tier_counts.get(1, 0)}")
    print(f"  🟡 Tier 2 (Verify First):   {tier_counts.get(2, 0)}")
    print(f"  ⚪ Tier 3 (Low Priority):   {tier_counts.get(3, 0)}")
    print(f"  ❌ Rejected:                {tier_counts.get(99, 0)}")
    print(f"  🔒 Exposed Ports:           {len(exposed_ports)}")
    print(f"{'=' * 60}")


if __name__ == '__main__':
    main()
