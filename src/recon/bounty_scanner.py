#!/usr/bin/env python3
"""
Module: Bounty Scanner (URL Heuristics) — v2.0
Passively analyzes massive URL collections for high-value bug bounty endpoints.

PHILOSOPHY (from a decade of bounty hunting):
  - Only flag things that have REAL security impact and are ACCEPTED by programs
  - A URL with node_modules on a CDN/SPA is NOT a finding — it's noise
  - Open redirects are dead — programs don't accept them anymore
  - Source maps are informational at best — not worth reporting
  - Focus on: leaked tokens, leaked PII, exposed admin panels, IDOR patterns,
    password reset takeover, and real credential exposure
  - Every finding should be something you'd ACTUALLY submit as a bounty report

NOISE KILLED IN v2.0:
  - node_modules on CDNs (CloudFront, S3, Akamai, etc.) — that's how JS is served
  - node_modules on SPA domains — React/Vue/Angular serve index.html for all paths
  - GraphQL endpoints without introspection evidence — every modern app has /graphql
  - Source maps (.map files) — low/no security impact
  - Auth API endpoints without actual leaked data — just endpoint discovery, not a vuln
  - 8080/8443 ports behind Cloudflare — standard CF behavior, returns 403
  - Internal IPs in tracking pixels / analytics params — not exploitable
"""

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse, parse_qs, unquote

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.utils import log_info, log_success, log_warning, banner, elapsed_str, read_lines, RICH_AVAILABLE


# ── Value Validators ─────────────────────────────────────────
# These check if a parameter VALUE actually contains real leaked data

EMAIL_REGEX = re.compile(r'[\w.+-]+@[\w-]+\.[\w.]+')
UUID_REGEX = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
TOKEN_REGEX = re.compile(r'^[A-Za-z0-9_/+=.-]{20,}$')  # JWT, API keys, session tokens, base64 blobs
JWT_REGEX = re.compile(r'^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')  # Actual JWT
NUMERIC_ID_REGEX = re.compile(r'^\d{4,}$')  # Sequential IDs (IDOR candidates)

# Junk values that are NOT real data
JUNK_VALUES = {
    '', 'true', 'false', 'null', 'none', 'undefined', 'test', 'example',
    '{token}', '{{token}}', '{email}', '{{email}}', '{id}', '{{id}}',
    'placeholder', 'default', '0', '1', 'en', 'us', 'gb',
    'asc', 'desc', 'all', 'active', 'inactive', 'pending',
}

# ── CDN / Static Asset Domains (always noise) ────────────────
CDN_PATTERNS = [
    'cloudfront.net', 'cdn.', 'static.', 'assets.', 'media.',
    'akamaized.net', 'fastly.net', 'azureedge.net', 'cloudflare.com',
    's3.amazonaws.com', 'googleapis.com/storage', 'gstatic.com',
    'unpkg.com', 'jsdelivr.net', 'cdnjs.cloudflare.com',
    'ebaystatic.com', 'ebayimg.com',
]

# ── Third-party domains (not in scope, always noise) ─────────
THIRD_PARTY_DOMAINS = [
    'google.com', 'googletagmanager.com', 'googleapis.com', 'gstatic.com',
    'facebook.com', 'fbcdn.net', 'twitter.com', 'linkedin.com',
    'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
    'trustarc.com', 'onetrust.com', 'cookielaw.org',
    'newrelic.com', 'nr-data.net', 'sentry.io', 'bugsnag.com',
    'segment.io', 'mixpanel.com', 'amplitude.com', 'heap.io',
    'intercom.io', 'zendesk.com', 'freshdesk.com',
    'stripe.com', 'braintreegateway.com', 'paypal.com',
    'recaptcha.net', 'hcaptcha.com',
    'bigmarker.com', 'corp.google.com',
]

def _is_noise_domain(url: str) -> bool:
    """Check if URL belongs to a CDN, third-party, or otherwise noisy domain."""
    lower = url.lower()
    return any(p in lower for p in CDN_PATTERNS + THIRD_PARTY_DOMAINS)


def _has_real_email(params: dict) -> str:
    """Check if any param contains a real email address."""
    email_params = {'email', 'mail', 'e-mail', 'user_email', 'useremail',
                    'login', 'username', 'recipient', 'to', 'from', 'sender',
                    'login_hint', 'user', 'account', 'upn', 'preferred_username'}
    for key, values in params.items():
        val = unquote(values[0]) if values else ''
        if val.lower() in JUNK_VALUES:
            continue
        if key.lower() in email_params and EMAIL_REGEX.search(val):
            return val
        if '@' in val and EMAIL_REGEX.search(val):
            # Skip tracking emails (noreply, notifications, etc.)
            email_match = EMAIL_REGEX.search(val)
            if email_match:
                email = email_match.group(0).lower()
                if any(x in email for x in ['noreply', 'no-reply', 'notifications', 'mailer-daemon',
                                             'postmaster', 'donotreply', 'bounce', 'unsubscribe']):
                    continue
                return val
    return ''


def _has_real_token(params: dict) -> str:
    """Check if any param contains a real token/secret/password value."""
    token_params = {'token', 'access_token', 'refresh_token', 'id_token',
                    'auth_token', 'reset_token', 'verification_token',
                    'api_key', 'apikey', 'secret', 'client_secret',
                    'session_id', 'sessionid', 'jsessionid',
                    'password', 'passwd', 'pwd', 'jwt',
                    'bearer', 'authorization', 'oauth_token',
                    'csrf_token', 'xsrf',
                    'samlresponse', 'samlrequest',
                    'assertion', 'stoken', 'sso_token', 'auth_code'}
    
    # Params that look like tokens but are actually analytics junk
    analytics_junk_params = {
        '_gl', '_ga', '_gid', 'utm_source', 'utm_medium', 'utm_campaign',
        'utm_content', 'utm_term', 'utm_referrer', 'fbclid', 'gclid',
        'mc_cid', 'mc_eid', 'ext-anonymousid', 'ext-gaclientid',
        'ext-gasessionid', '_gcl_au', '_gcl_aw', 'site',
    }
    
    for key, values in params.items():
        val = values[0] if values else ''
        key_lower = key.lower()
        
        if val.lower() in JUNK_VALUES or len(val) < 8:
            continue
        if key_lower in analytics_junk_params:
            continue
            
        if key_lower in token_params and TOKEN_REGEX.match(val):
            # Bonus: check for actual JWT
            if JWT_REGEX.match(val):
                return f"JWT: {key}={val[:40]}..."
            return f"{key}={val[:30]}..."
    return ''


def _has_real_pii(params: dict) -> str:
    """Check if any param contains real PII (SSN, phone, etc.)."""
    pii_params = {'ssn', 'dob', 'date_of_birth', 'passport', 'phone',
                  'mobile', 'credit_card', 'card_number',
                  'account_number', 'routing_number', 'cvv',
                  'social_security'}
    for key, values in params.items():
        val = values[0] if values else ''
        if val.lower() in JUNK_VALUES or len(val) < 3:
            continue
        if key.lower() in pii_params:
            if len(val) >= 5 and not val.isalpha():
                return f"{key}={val[:20]}"
    return ''


# ── Heuristic Definitions ────────────────────────────────────

HEURISTICS = {
    # ── PII Leaks — ONLY flag if actual email/PII data present ──
    "PII_Email_Leak": {
        "severity": "HIGH",
        "description": "Real email address leaked in URL parameters — privacy violation, potential ATO vector.",
        "check": lambda url, params: _has_real_email(params),
    },
    "PII_Data_Leak": {
        "severity": "HIGH",
        "description": "Sensitive PII (SSN, phone, DOB, card number) leaked in URL.",
        "check": lambda url, params: _has_real_pii(params),
    },
    "Token_Leak": {
        "severity": "CRITICAL",
        "description": "Authentication token/secret/password leaked in URL — session hijack risk.",
        "check": lambda url, params: _has_real_token(params),
    },

    # ── Corporate SSO Leak (CRITICAL) ──
    "SSO_Corp_Leak": {
        "severity": "CRITICAL",
        "description": "Corporate SSO/ADFS endpoint leaking employee email and auth context.",
        "check": lambda url, params: (
            bool(re.search(r'(?i)(?:sso|adfs|idp|saml|federation|auth\.corp|login\.corp)', url))
            and (_has_real_email(params) or _has_real_token(params))
        ) or '',
    },

    # ── Unsubscribe with real email (ATO risk) ──
    "Unsubscribe_ATO": {
        "severity": "HIGH",
        "description": "Unsubscribe endpoint with real email — potential account manipulation.",
        "check": lambda url, params: (
            '/unsubscribe' in url.lower() and _has_real_email(params)
        ) or '',
    },

    # ── Order/Invoice with email (data leak) ──
    "Order_Data_Leak": {
        "severity": "HIGH",
        "description": "Order/invoice/receipt endpoint with PII in URL — data exposure.",
        "check": lambda url, params: (
            bool(re.search(r'(?i)/(?:order|invoice|receipt|payment|checkout)', url))
            and (_has_real_email(params) or _has_real_token(params))
        ) or '',
    },

    # ── IDOR with real numeric IDs ──
    "IDOR_Endpoints": {
        "severity": "MEDIUM",
        "description": "API endpoint with sequential/predictable user IDs — test for IDOR.",
        "check": lambda url, params: (
            bool(re.search(r'(?i)/api/v\d+/users/\d{4,}', url))
            or (bool(re.search(r'(?i)/(?:invoice|receipt|order)s?/[a-f0-9-]{20,}', url))
                and _has_real_email(params))
        ) or '',
    },

    # ── Password Reset UUID in path (ATO) ──
    "Password_Reset_UUID": {
        "severity": "CRITICAL",
        "description": "Password reset link with UUID — allows account takeover if token is still valid.",
        "check": lambda url, params: (
            bool(re.search(r'(?i)/(?:reset-password|password-reset|forgot-password)/[a-f0-9-]{30,}', url))
        ) or '',
    },

    # ── Verification/Reset links with tokens ──
    "Verification_Link": {
        "severity": "HIGH",
        "description": "Account verification/reset link with token — session hijack / ATO risk.",
        "check": lambda url, params: (
            bool(re.search(r'(?i)/(?:verify|reset|confirm|activate|validation)', url))
            and (_has_real_token(params) or _has_real_email(params))
        ) or '',
    },

    # ── Internal IP Leaked in URL (ONLY in meaningful context) ──
    "Internal_IP_Leak": {
        "severity": "MEDIUM",
        "description": "Internal/private IP address exposed in URL — SSRF / infrastructure mapping.",
        "check": lambda url, params: _check_internal_ip(url),
    },

    # ── Debug / Admin Panels ──
    "Debug_Admin_Panel": {
        "severity": "CRITICAL",
        "description": "Debug or admin panel endpoint accessible — full application compromise risk.",
        "check": lambda url, params: _check_debug_admin(url),
    },

    # ── Exposed Config / Secrets Files ──
    "Exposed_Config_File": {
        "severity": "CRITICAL",
        "description": "Configuration file with potential secrets exposed (NOT behind SPA routing).",
        "check": lambda url, params: _check_config_files(url),
    },
}


def _check_internal_ip(url: str) -> str:
    """Check for internal/private IP addresses in URL — skip analytics/tracking noise."""
    decoded = unquote(url)

    # Skip tracking/analytics URLs entirely — IPs here are cache/CDN tags, not exploitable
    tracking_patterns = [
        '/fdbk/', 'clientId=urn', 'ebaystatic.com',
        'googletagmanager.com', 'google-analytics.com', 'gtag/',
        'pixel', 'tracking', 'beacon', 'telemetry',
    ]
    if any(p in decoded.lower() for p in tracking_patterns):
        return ''

    ip_match = re.search(
        r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
        decoded
    )
    if ip_match:
        ip = ip_match.group(0)
        # Only flag if IP appears in an actual URL/connection context
        if re.search(r'https?://[^/]*' + re.escape(ip), decoded) or \
           re.search(r'(?:host|url|addr|server|device|inform|redirect|proxy|backend).*' + re.escape(ip), decoded, re.I):
            return ip
    return ''


def _check_debug_admin(url: str) -> str:
    """Check for exposed debug/admin panels — skip CDNs and SPAs."""
    lower = url.lower()
    
    # Must be on a real application domain, not CDN
    if _is_noise_domain(url):
        return ''
    
    debug_patterns = [
        r'/(?:phpinfo|server-info|server-status)(?:\.php)?$',
        r'/(?:elmah|trace|diagnostics)\.axd',
        r'/(?:actuator/(?:env|health|info|beans|mappings|configprops))',
        r'/swagger-ui(?:\.html|/index\.html)',
        r'/(?:_debug|debug|_profiler|profiler)/',
        r'/admin/(?:config|settings|database|users)',
        r'/wp-admin/(?:install|setup-config)\.php',
        r'/solr/admin',
        r'/(?:kibana|grafana|prometheus)(?:/|$)',
        r'/(?:_cat/(?:indices|nodes|health))',  # Elasticsearch
    ]
    
    for pattern in debug_patterns:
        if re.search(pattern, lower):
            return re.search(pattern, lower).group(0)
    return ''


def _check_config_files(url: str) -> str:
    """Check for exposed config files — strict matching to avoid SPA false positives."""
    lower = url.lower()
    
    # Skip CDNs and noise domains
    if _is_noise_domain(url):
        return ''
    
    # These are ONLY worth reporting if they're on a real server, not a SPA
    # SPA routing means *.sendgrid.com/anything returns index.html (200 OK)
    config_patterns = [
        r'/\.env(?:\.(?:bak|old|local|production|staging|dev|example))?$',
        r'/\.git/(?:config|HEAD|index|objects|refs)',
        r'/\.svn/entries',
        r'/\.htpasswd',
        r'/wp-config\.php(?:\.bak|\.old|~)?$',
        r'/web\.config(?:\.bak|\.old)?$',
        r'/config\.(?:php|yml|yaml|json)(?:\.bak|\.old)?$',
        r'/database\.yml$',
        r'/secrets\.yml$',
        r'/credentials\.json$',
    ]
    
    for pattern in config_patterns:
        if re.search(pattern, lower):
            return re.search(pattern, lower).group(0)
    return ''


class BountyScanner:
    def __init__(self, urls: List[str]):
        self.urls = urls
        self.findings = []
        self.stats = {k: 0 for k in HEURISTICS.keys()}
        self._dedup = set()  # Deduplicate findings by (type, domain)

    def scan(self) -> Dict:
        start = time.time()
        banner("Passive Bounty Scanner v2.0")
        log_info(f"Scanning {len(self.urls)} unique URLs against {len(HEURISTICS)} heuristics...")

        for url in self.urls:
            url = url.strip()
            if not url or not url.startswith('http'):
                continue

            # Skip noise domains entirely — saves CPU on large scans
            if _is_noise_domain(url):
                continue

            # Parse params once for all checks
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
            except Exception:
                params = {}

            for vuln_id, config in HEURISTICS.items():
                matched = False
                evidence = ""

                if "regex" in config:
                    if config["regex"].search(url):
                        matched = True
                elif "check" in config:
                    result = config["check"](url, params)
                    if result:
                        matched = True
                        evidence = str(result) if isinstance(result, str) else ""

                if matched:
                    # Deduplicate: only one finding per (type, domain) to reduce noise
                    parsed_url = urlparse(url)
                    dedup_key = (vuln_id, parsed_url.netloc)
                    if dedup_key in self._dedup:
                        self.stats[vuln_id] += 1
                        continue
                    self._dedup.add(dedup_key)

                    finding = {
                        "type": vuln_id,
                        "severity": config["severity"],
                        "description": config["description"],
                        "url": url,
                    }
                    if evidence and evidence != 'True':
                        finding["evidence"] = evidence
                    self.findings.append(finding)
                    self.stats[vuln_id] += 1

        # Summary
        total = len(self.findings)
        critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")

        log_success(f"Bounty Scan complete in {elapsed_str(start)}")
        if total:
            log_success(f"Actionable findings: {total} ({critical} CRITICAL, {high} HIGH)")
        else:
            log_info("No bounty-worthy findings detected — clean scan.")

        return {
            "findings": self.findings,
            "stats": self.stats,
            "total_urls": len(self.urls)
        }


def main():
    parser = argparse.ArgumentParser(description="Passive Bounty URL Scanner v2.0")
    parser.add_argument("-l", "--list", required=True, help="File containing URLs to scan (e.g., unique_urls.txt)")
    parser.add_argument("-o", "--output", help="Output JSON file for findings")

    args = parser.parse_args()
    urls = read_lines(args.list)

    if not urls:
        print("No URLs to scan.")
        return

    scanner = BountyScanner(urls)
    results = scanner.scan()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        log_success(f"Findings saved to {args.output}")


if __name__ == "__main__":
    main()
