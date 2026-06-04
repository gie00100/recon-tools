#!/usr/bin/env python3
"""
Module: Bounty Scanner (URL Heuristics)
Passively analyzes massive URL collections for high-value bug bounty endpoints.

STRATEGY: Only flag URLs that contain ACTUAL leaked data in parameters,
not just parameter names. A URL with `email=` (empty) is worthless.
A URL with `email=john%40example.com` is a real PII leak.
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
NUMERIC_ID_REGEX = re.compile(r'^\d{4,}$')  # Sequential IDs (IDOR candidates)

# Junk values that are NOT real data
JUNK_VALUES = {
    '', 'true', 'false', 'null', 'none', 'undefined', 'test', 'example',
    '{token}', '{{token}}', '{email}', '{{email}}', '{id}', '{{id}}',
    'placeholder', 'default', '0', '1', 'en', 'us', 'gb',
}


def _has_real_email(params: dict) -> str:
    """Check if any param contains a real email address."""
    email_params = {'email', 'mail', 'e-mail', 'user_email', 'useremail',
                    'login', 'username', 'recipient', 'to', 'from', 'sender',
                    'login_hint', 'user', 'account', 'upn', 'preferred_username'}
    for key, values in params.items():
        val = unquote(values[0]) if values else ''
        if val.lower() in JUNK_VALUES:
            continue
        # Check param name is email-related AND value looks like an email
        if key.lower() in email_params and EMAIL_REGEX.search(val):
            return val
        # Or any param value containing an email
        if '@' in val and EMAIL_REGEX.search(val):
            return val
    return ''


def _has_real_token(params: dict) -> str:
    """Check if any param contains a real token/secret/password value."""
    token_params = {'token', 'access_token', 'refresh_token', 'id_token',
                    'auth_token', 'reset_token', 'verification_token',
                    'api_key', 'apikey', 'key', 'secret', 'client_secret',
                    'session', 'session_id', 'sessionid', 'sid', 'jsessionid',
                    'password', 'passwd', 'pwd', 'pass', 'auth', 'jwt',
                    'bearer', 'authorization', 'code', 'grant', 'oauth_token',
                    'csrf', 'csrf_token', 'xsrf', 'nonce', 'hash',
                    'signature', 'sig', 'hmac', 'ticket',
                    # SSO / WS-Federation / SAML
                    'wctx', 'wresult', 'samlresponse', 'samlrequest',
                    'assertion', 'id_token_hint', 'client-request-id',
                    'stoken', 'sso_token', 'auth_code'}
    for key, values in params.items():
        val = values[0] if values else ''
        if val.lower() in JUNK_VALUES or len(val) < 8:
            continue
        if key.lower() in token_params and TOKEN_REGEX.match(val):
            return f"{key}={val[:30]}..."
    return ''


def _has_real_pii(params: dict) -> str:
    """Check if any param contains real PII (SSN, phone, etc.)."""
    pii_params = {'ssn', 'dob', 'date_of_birth', 'passport', 'phone',
                  'mobile', 'address', 'credit_card', 'card_number',
                  'account_number', 'routing_number', 'cvv', 'zip',
                  'social_security'}
    for key, values in params.items():
        val = values[0] if values else ''
        if val.lower() in JUNK_VALUES or len(val) < 3:
            continue
        if key.lower() in pii_params:
            # Must have a meaningful value (not just a param name)
            if len(val) >= 5 and not val.isalpha():
                return f"{key}={val[:20]}"
    return ''


# ── Heuristic Definitions ────────────────────────────────────

HEURISTICS = {
    # ── PII Leaks — ONLY flag if actual email/PII data present ──
    "PII_Email_Leak": {
        "severity": "HIGH",
        "description": "Real email address leaked in URL parameters.",
        "check": lambda url, params: _has_real_email(params),
    },
    "PII_Data_Leak": {
        "severity": "HIGH",
        "description": "Sensitive PII (SSN, phone, DOB) leaked in URL.",
        "check": lambda url, params: _has_real_pii(params),
    },
    "Token_Leak": {
        "severity": "CRITICAL",
        "description": "Authentication token/secret/password leaked in URL.",
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
        "description": "Unsubscribe endpoint with real email — potential ATO.",
        "check": lambda url, params: (
            '/unsubscribe' in url.lower() and _has_real_email(params)
        ) or '',
    },

    # ── Order/Invoice with email (data leak) ──
    "Order_Data_Leak": {
        "severity": "HIGH",
        "description": "Order/invoice/receipt endpoint with PII in URL.",
        "check": lambda url, params: (
            bool(re.search(r'(?i)/(?:order|invoice|receipt|payment|checkout)', url))
            and (_has_real_email(params) or _has_real_token(params))
        ) or '',
    },

    # ── IDOR with real numeric IDs ──
    "IDOR_Endpoints": {
        "severity": "MEDIUM",
        "description": "API endpoint with sequential/predictable user IDs.",
        "check": lambda url, params: (
            bool(re.search(r'(?i)/api/v\d+/users/\d{4,}', url))
            or (bool(re.search(r'(?i)/(?:invoice|receipt|order)s?/[a-f0-9-]{20,}', url))
                and _has_real_email(params))
        ) or '',
    },

    # ── Verification/Reset links with tokens ──
    "Verification_Link": {
        "severity": "HIGH",
        "description": "Account verification/reset link with token — session hijack risk.",
        "check": lambda url, params: (
            bool(re.search(r'(?i)/(?:verify|reset|confirm|activate|validation)', url))
            and (_has_real_token(params) or _has_real_email(params))
        ) or '',
    },

    # ── Password Reset UUID in path (ATO) ──
    "Password_Reset_UUID": {
        "severity": "CRITICAL",
        "description": "Password reset link with UUID — allows account takeover if valid.",
        "check": lambda url, params: (
            bool(re.search(r'(?i)/(?:reset-password|password-reset|forgot-password)/[a-f0-9-]{30,}', url))
        ) or '',
    },

    # ── Internal IP Leaked in URL ──
    "Internal_IP_Leak": {
        "severity": "MEDIUM",
        "description": "Internal/private IP address exposed in URL — info disclosure / SSRF target.",
        "check": lambda url, params: _check_internal_ip(url),
    },

    # ── GraphQL Endpoint ──
    "GraphQL_Endpoint": {
        "severity": "MEDIUM",
        "description": "GraphQL endpoint found — test for introspection and query injection.",
        "check": lambda url, params: (
            bool(re.search(r'(?i)/graphql\b', url))
        ) or '',
    },

    # ── Exposed Source Code / node_modules ──
    "Exposed_Source_Code": {
        "severity": "HIGH",
        "description": "Application source code or dependency tree exposed in URL path.",
        "check": lambda url, params: _check_exposed_source(url),
    },

    # ── Auth API Endpoints with sensitive paths ──
    "Auth_API_Endpoint": {
        "severity": "HIGH",
        "description": "Authentication API endpoint — verify-creds, authCallback, check-email.",
        "check": lambda url, params: (
            bool(re.search(r'(?i)/(?:api|signin)/v?\d*/(?:verify-creds|auth.*callback|check-email|start-auth|resend)', url))
        ) or '',
    },
}


def _check_internal_ip(url: str) -> str:
    """Check for internal/private IP addresses in URL."""
    decoded = unquote(url)

    # Skip eBay CDN/fdbk metadata URLs — IPs are backend cache server tags, not exploitable
    if '/fdbk/' in decoded or 'clientId=urn' in decoded or 'ebaystatic.com' in decoded:
        return ''

    ip_match = re.search(
        r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
        decoded
    )
    if ip_match:
        ip = ip_match.group(0)
        # Only flag if IP appears in an actual URL/connection context
        if re.search(r'https?://[^/]*' + re.escape(ip), decoded) or \
           re.search(r'(?:host|url|addr|ip|server|device|inform).*' + re.escape(ip), decoded, re.I):
            return ip
    return ''


def _check_exposed_source(url: str) -> str:
    """Check for exposed source code paths — skip known FP patterns."""
    lower = url.lower()

    # Skip source maps (user requested to ignore these as low impact)
    if lower.endswith('.map') or '.map?' in lower or '.js.map' in lower:
        return ''

    # Skip known false positives
    # eBay shipping apps where /private/src/ is a legitimate app route
    if any(x in lower for x in [
        'ebay-versand.', 'delivery.ebay.', 'envios.ebay.',
        'expeditions.ebay.', 'community.ui.com/questions/',
        'ebaystatic.com', 'webpack:',
    ]):
        return ''

    # Skip source map references (node_modules in source maps, not actual exposure)
    if '/node_modules/' in url and any(x in lower for x in [
        'uisp.com', '.pnpm/', 'react-aria', 'react-stately',
    ]):
        return ''

    # Check for actual source code exposure
    if re.search(r'(?i)/node_modules/', url):
        return 'node_modules exposed'
    if re.search(r'(?i)/(?:private/)?src/.*\.(?:tsx?|jsx?|py|rb|go|java|php)\b', url):
        return 'source code path'

    return ''


class BountyScanner:
    def __init__(self, urls: List[str]):
        self.urls = urls
        self.findings = []
        self.stats = {k: 0 for k in HEURISTICS.keys()}

    def scan(self) -> Dict:
        start = time.time()
        banner("Passive Bounty Scanner")
        log_info(f"Scanning {len(self.urls)} unique URLs against {len(HEURISTICS)} heuristics...")

        for url in self.urls:
            url = url.strip()
            if not url:
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
                    # Path-only regex checks (no param validation needed)
                    if config["regex"].search(url):
                        matched = True
                elif "check" in config:
                    # Smart checks that validate actual param VALUES
                    result = config["check"](url, params)
                    if result:
                        matched = True
                        evidence = str(result) if isinstance(result, str) else ""

                if matched:
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
            log_success(f"Total flags: {total} ({critical} CRITICAL, {high} HIGH)")
        else:
            log_info("No bounty-worthy findings detected.")

        return {
            "findings": self.findings,
            "stats": self.stats,
            "total_urls": len(self.urls)
        }


def main():
    parser = argparse.ArgumentParser(description="Passive Bounty URL Scanner")
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
