#!/usr/bin/env python3
"""
Module: Bounty Scanner (URL Heuristics) — v4.1
Passively analyzes massive URL collections for high-value bug bounty endpoints.

PHILOSOPHY (from decades of bounty hunting):
  - Only flag things that have REAL security impact and are ACCEPTED by programs
  - Every finding should be something you'd ACTUALLY submit as a report
  - Signal-to-noise ratio matters more than finding count — one real bug > 100 FPs

WHAT'S NEW IN v3.0 (based on deep analysis of 295 findings from 37 real targets):
  - Kill 6sense analytics beacon tokens (b.6sc.co) — not exploitable
  - Kill SendGrid documentation URLs (api_user=ryan.burrer@sendgrid.com) — doc examples
  - Kill Zendesk chat session IDs (help.*/submit?sessionId=) — not auth sessions
  - Kill http:// token URLs — real auth tokens are never served over plain HTTP in prod
  - Kill AdWords/template variable values ({keyword}, {ifmobile:1}) — unfilled placeholders
  - Kill grafana/kibana matches on image URLs (e.g., /assets/images/kic/grafana/*.png)
  - Kill duplicate Password_Reset_UUID findings (dedup on path, not full URL)
  - Added SSRF param detection (url=, redirect=, next= with full http:// values)
  - Added GraphQL introspection detection (only if query contains __schema)

WHAT'S NEW IN v3.1:
  - Credential_In_URL: detects plaintext user:password embedded in URL paths
    (VirusTotal pattern: https://auth.example.com/:user@gmail.com:P@ssw0rd)
  - Also detects RFC 3986 basic-auth URLs (https://user:pass@host/)

WHAT'S NEW IN v4.0 (based on deep analysis of 166 findings from 23 real targets):
  - Kill SAMLRequest/SAMLResponse Token_Leak FPs — expected in every SSO flow, not leaked secrets
  - Kill http:// + port-in-host URLs for ALL checks — not valid in big bounty programs
  - Kill :UNKNOWN:password Credential_In_URL FPs — VT scanner artifacts with no username
  - Kill same-program-family SSRF FPs (ReturnUrl=https://sub.same-domain.com)
  - Kill WhatsApp/Telegram phone link PII_Data_Leak FPs — public contact links, not leaks
  - Kill Trustpilot apikey Token_Leak FPs — public business-unit lookup API, not secret
  - Kill PIN= in casino/gaming URLs — these are customer-facing PINs, not auth secrets

WHAT'S NEW IN v4.1 (based on forensic analysis of ALL 166 findings from 23 targets):
  - Kill IR feed public apiKey FPs (ir.*/feed/Event.svc — Q4 Inc investor platform, public key)
  - Kill Wix analytics session_id FPs (frog.wix.com — performance telemetry, not auth)
  - Kill marketing unsubscribe email FPs (/unsubscribe, /suppression/ — required by CAN-SPAM)
  - Kill Microsoft SafeLinks email artifacts (|01|email|guid| pattern in URL rewrites)
  - Kill cross-TLD same-program SSRF FPs (varonis.com → varonis.io = same company)
  - Kill Chartbeat analytics PII FPs (ping.chartbeat.net — 3rd party analytics)
  - Remove SAMLRequest/SAMLResponse from token_params entirely (SSO flows, not secrets)
  - Added apiKey value dedup (same key across 7 /feed/ paths = 1 finding, not 7)
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
TEMPLATE_VAR_REGEX = re.compile(r'^\{[^}]+\}$|^\{\{[^}]+\}\}$')  # {keyword}, {{email}} — unfilled placeholders

# Junk values that are NOT real data
JUNK_VALUES = {
    '', 'true', 'false', 'null', 'none', 'undefined', 'test', 'example',
    '{token}', '{{token}}', '{email}', '{{email}}', '{id}', '{{id}}',
    'placeholder', 'default', '0', '1', 'en', 'us', 'gb',
    'asc', 'desc', 'all', 'active', 'inactive', 'pending',
    # SendGrid documentation placeholder values
    'your_sendgrid_username', 'your_sendgrid_password', 'your_api_key',
    'xxxxxx', 'xxxx', 'your.already.existing.authenticated_domain',
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
    'github.com', 'hackerone.com',
    # Publishing / content platforms
    'medium.com', 'substack.com', 'wordpress.com', 'ghost.io',
    # Analytics / tracking SDKs
    '6sc.co', 'b.6sc.co',         # 6sense analytics beacons
    'googleoptimize.com',
    'hotjar.com', 'mouseflow.com',
    'crazyegg.com', 'fullstory.com',
    'bing.com', 'clarity.ms',
    'chartbeat.net', 'ping.chartbeat.net',  # Chartbeat analytics
    'frog.wix.com', 'wix.com',             # Wix analytics/telemetry beacons
    # Chat/messaging contact links (public links, not PII leaks)
    'api.whatsapp.com', 'wa.me', 't.me', 'telegram.me',
    # Public review platforms (business lookup APIs are public)
    'trustpilot.com', 'g2.com', 'capterra.com',
    # SSO identity providers (SAML flows go through these — expected)
    'login.microsoftonline.com', 'accounts.google.com', 'okta.com',
    'auth0.com', 'onelogin.com', 'pingidentity.com', 'idp.ssocircle.com',
]

# ── Static asset file extensions (path-based checks ignore these) ───
STATIC_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico',
                     '.woff', '.woff2', '.ttf', '.eot', '.otf', '.mp4', '.mp3',
                     '.pdf', '.zip', '.tar', '.gz'}

# ── Static asset path patterns ───────────────────────────────
STATIC_PATH_PATTERNS = [
    '/assets/', '/images/', '/static/', '/img/', '/media/',
    '/fonts/', '/icons/', '/dist/', '/build/',
]


def _is_noise_domain(url: str) -> bool:
    """Check if URL belongs to a CDN, third-party, or otherwise noisy domain."""
    lower = url.lower()
    return any(p in lower for p in CDN_PATTERNS + THIRD_PARTY_DOMAINS)


def _is_static_asset(url: str) -> bool:
    """Check if URL is a static asset (image, font, etc.) — path-based checks should skip these."""
    parsed = urlparse(url.lower())
    path = parsed.path
    # Check extension
    ext = Path(path).suffix
    if ext in STATIC_EXTENSIONS:
        return True
    # Check path pattern
    if any(p in path for p in STATIC_PATH_PATTERNS):
        return True
    return False


def _is_http_not_https(url: str) -> bool:
    """Return True if URL uses plain HTTP (not HTTPS). Real auth tokens are always HTTPS."""
    return url.startswith('http://') and not url.startswith('https://')


def _is_http_with_port(url: str) -> bool:
    """
    Return True if URL is plain HTTP with an explicit port number in the host.
    e.g. http://192.168.1.1:8080/ or http://example.com:80/path
    These are port-scan artifacts — big bounty programs don't accept http://:port findings.
    """
    if not url.startswith('http://') or url.startswith('https://'):
        return False
    try:
        from urllib.parse import urlparse as _up
        parsed = _up(url)
        return parsed.port is not None
    except Exception:
        return False


def _is_ip_url(url: str) -> bool:
    """
    Return True if URL host is a raw IP address.
    Port-scan IPs often appear in URL lists but are never valid bounty targets.
    """
    try:
        from urllib.parse import urlparse as _up
        import ipaddress
        host = _up(url).hostname or ''
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def _is_saml_url(url: str, params: dict) -> bool:
    """
    Return True if URL contains a SAMLRequest or SAMLResponse parameter.
    SAML assertions are expected in every SSO flow — they are NOT leaked secrets.
    They appear in waymore/VT data because users visit SSO endpoints, not because
    the app is leaking auth tokens.
    """
    saml_keys = {'samlrequest', 'samlresponse', 'saml_request', 'saml_response',
                 'SAMLRequest', 'SAMLResponse'}
    return bool(saml_keys & set(params.keys()))


def _is_pin_gaming_url(url: str, params: dict) -> bool:
    """
    Return True if URL contains a PIN= parameter in a gaming/casino/sports context.
    These are customer-facing game PINs, not authentication secrets.
    """
    if 'pin' not in {k.lower() for k in params}:
        return False
    gaming_keywords = ['sportsbook', 'casino', 'game', 'sport', 'bet', 'slot', 'poker',
                       'lottery', 'bingo', 'jackpot', 'play']
    url_lower = url.lower()
    return any(kw in url_lower for kw in gaming_keywords)


def _is_ir_feed_apikey(url: str, params: dict) -> bool:
    """
    Detect investor relations (IR) feed API keys — these are PUBLIC client-side keys.
    Powered by Q4 Inc and similar IR platforms, the same apiKey is embedded in the
    page JavaScript on every company's IR site. They grant read-only access to
    public press releases, stock quotes, and events. NOT a secret.
    Pattern: ir.*/feed/Event.svc?apiKey=... or /feed/StockQuote.svc?apiKey=...
    """
    lower = url.lower()
    parsed = urlparse(lower)
    host = parsed.netloc
    path = parsed.path
    # Must be on an IR subdomain or IR domain
    if not (host.startswith('ir.') or 'investor' in host):
        return False
    # Must be a /feed/ service endpoint
    if '/feed/' not in path:
        return False
    # Must have an apiKey param
    if 'apikey' not in {k.lower() for k in params}:
        return False
    return True


def _is_notification_email_url(url: str) -> bool:
    """
    Detect marketing notification/unsubscribe URLs where emails are expected.
    These are legally required (CAN-SPAM/GDPR) and are NOT security findings.
    Patterns:
    - /unsubscribe, /suppression/ — email opt-out endpoints
    - push-notification subdomains — mass-mailing infrastructure
    - track., tracking. subdomains — email click-tracking
    - /public/view/ — email web-view with embedded unsubscribe links
    """
    lower = url.lower()
    parsed = urlparse(lower)
    host = parsed.netloc
    path = parsed.path

    # Notification infrastructure subdomains
    if host.startswith('push-notification') or host.startswith('track.') or host.startswith('tracking.'):
        return True

    # Unsubscribe / suppression endpoints
    if any(seg in path for seg in ['/unsubscribe', '/suppression/', '/email-abuse',
                                    '/subscription/unsubscribe', '/email_abuse']):
        return True

    # Email web-view pages with unsubscribe links embedded
    if '/public/view/' in path and 'unsubscribelink' in lower:
        return True

    return False


def _is_safelinks_email(val: str) -> bool:
    """
    Detect Microsoft SafeLinks/Defender URL rewriting artifacts.
    Pattern: 02|01|email@domain.com|GUID|GUID|0|0|timestamp
    These appear when a corporate email user clicks a link — their employer's
    email security gateway rewrites the URL. The email belongs to the clicker,
    NOT a vulnerability in the target application.
    """
    # Microsoft SafeLinks format: pipe-delimited with email at position 3
    if '|01|' in val or '|02|' in val:
        parts = val.split('|')
        if len(parts) >= 5:
            # Check if any part looks like an email
            for part in parts:
                if '@' in part and '.' in part.split('@')[-1]:
                    return True
    return False


def _is_sendgrid_doc_url(url: str, params: dict) -> bool:
    """
    Detect SendGrid documentation example URLs.
    These appear in tutorials and docs, not real user sessions.
    Pattern: api.sendgrid.com + api_user=ryan.burrer@sendgrid.com or api_key=placeholder
    """
    if 'api.sendgrid.com' not in url:
        return False
    api_user = params.get('api_user', [''])[0]
    api_key = params.get('api_key', [''])[0]
    # If api_user is a sendgrid.com employee email in docs or api_key is a placeholder
    if 'sendgrid.com' in api_user.lower():
        return True
    if api_key.lower() in JUNK_VALUES:
        return True
    return False


def _is_zendesk_chat_session(url: str, params: dict) -> bool:
    """
    Detect Zendesk/support chat session IDs — these are not auth sessions.
    Pattern: /submit endpoint with sessionId + optional chatId or conversationId params
    """
    parsed = urlparse(url)
    path = parsed.path.lower()
    if '/submit' in path or '/chat' in path:
        if 'sessionid' in {k.lower() for k in params}:
            # Look for chat-specific co-params
            param_keys = {k.lower() for k in params}
            if param_keys & {'chatid', 'conversationid', 'interactionid'}:
                return True
    return False


def _is_seo_doorway(url: str) -> bool:
    """
    Detect SEO doorway pages — scraped junk URLs that look like:
    http://ripio.com:80/ashaway_ri.php?q=ashaway+ri&q_type=rx&token=...
    Pattern: http:// + port 80 + *.php with geo-slug filenames
    """
    if not url.startswith('http://'):
        return False
    try:
        parsed = urlparse(url)
        port = parsed.port  # may raise ValueError on malformed ports
        if port == 80 and parsed.path.endswith('.php'):
            # City/state slug pattern: /cityname_state.php
            if re.match(r'^/[a-z_]+-?[a-z]+_[a-z]{2}\.php$', parsed.path):
                return True
    except ValueError:
        pass
    return False


def _has_template_variable(value: str) -> bool:
    """Check if value is an unfilled template placeholder like {keyword} or {ifmobile:1}."""
    return bool(TEMPLATE_VAR_REGEX.match(value)) or ('{' in value and '}' in value and len(value) < 50)


def _has_real_email(params: dict) -> str:
    """Check if any param contains a real email address."""
    email_params = {'email', 'mail', 'e-mail', 'user_email', 'useremail',
                    'login', 'username', 'recipient', 'to', 'from', 'sender',
                    'login_hint', 'user', 'account', 'upn', 'preferred_username',
                    'invited_email', 'filter'}
    for key, values in params.items():
        val = unquote(values[0]) if values else ''
        if val.lower() in JUNK_VALUES:
            continue
        # Skip template variables
        if _has_template_variable(val):
            continue
        # Skip retina image filenames (contain @2x, @3x) — NOT emails
        if re.search(r'@[23]x', val):
            continue
        # Skip encoded URLs falsely matching as emails (@2F, @3A patterns)
        if re.search(r'@[0-9A-F]{2}', val):
            continue
        # Skip Microsoft SafeLinks URL rewriting artifacts
        if _is_safelinks_email(val):
            continue
        if key.lower() in email_params and EMAIL_REGEX.search(val):
            return val
        if '@' in val and EMAIL_REGEX.search(val):
            email_match = EMAIL_REGEX.search(val)
            if email_match:
                email = email_match.group(0).lower()
                # Skip system/notification addresses
                if any(x in email for x in ['noreply', 'no-reply', 'notifications', 'mailer-daemon',
                                              'postmaster', 'donotreply', 'bounce', 'unsubscribe']):
                    continue
                # Skip SendGrid's own documentation emails
                if email.endswith('@sendgrid.com') and 'ryan.burrer' in email:
                    continue
                # Skip Apple Private Relay emails (randomized, not real PII)
                if email.endswith('@privaterelay.appleid.com'):
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
                    # NOTE: samlrequest/samlresponse REMOVED in v4.1 — they are expected
                    # in every SSO flow, not leaked secrets
                    'assertion', 'stoken', 'sso_token', 'auth_code'}

    # Params that look like tokens but are analytics junk
    analytics_junk_params = {
        '_gl', '_ga', '_gid', 'utm_source', 'utm_medium', 'utm_campaign',
        'utm_content', 'utm_term', 'utm_referrer', 'fbclid', 'gclid',
        'mc_cid', 'mc_eid', 'ext-anonymousid', 'ext-gaclientid',
        'ext-gasessionid', '_gcl_au', '_gcl_aw', 'site',
        # Zendesk chat co-params — not auth
        'chatid', 'conversationid', 'sessionid',
    }

    for key, values in params.items():
        val = values[0] if values else ''
        key_lower = key.lower()

        if not val or val.lower() in JUNK_VALUES or len(val) < 8:
            continue
        if key_lower in analytics_junk_params:
            continue
        # Skip template variable values
        if _has_template_variable(val):
            continue

        if key_lower in token_params and TOKEN_REGEX.match(val):
            # Bonus: check for actual JWT
            if JWT_REGEX.match(val):
                return f"JWT: {key}={val[:40]}..."
            return f"{key}={val[:30]}..."
    return ''


def _has_real_pii(params: dict) -> str:
    """Check if any param contains real PII (SSN, phone, DOB, etc.)."""
    pii_params = {'ssn', 'dob', 'date_of_birth', 'passport', 'phone',
                  'mobile', 'credit_card', 'card_number',
                  'account_number', 'routing_number', 'cvv',
                  'social_security'}
    for key, values in params.items():
        val = values[0] if values else ''
        if val.lower() in JUNK_VALUES or len(val) < 3:
            continue
        # Skip template variables ({ifmobile:1} etc.)
        if _has_template_variable(val):
            continue
        if key.lower() in pii_params:
            if len(val) >= 5 and not val.isalpha():
                return f"{key}={val[:20]}"
    return ''


# ── Credential-in-URL regex patterns ────────────────────────────────────────
# Pattern 1: VirusTotal path-based credentials — /:username:password
# e.g. https://auth.ripio.com/:aravenav941@gmail.com:Viviana89
_CRED_PATH_REGEX = re.compile(
    r'/:([\w.+@%-]{3,}):([^/?#\s]{4,})(?:[/?#]|$)'
)
# Pattern 2: RFC 3986 authority credentials — user:pass@host
# e.g. https://admin:secret123@dashboard.example.com/
_CRED_AUTH_REGEX = re.compile(
    r'https?://([\w.+%-]{3,}):([^@/?#\s]{4,})@'
)

# Common false-positive values — path segments, not real creds
_CRED_FP_VALUES = {
    'www', 'http', 'https', 'ftp', 'ssh', 'null', 'user', 'pass',
    'admin', 'guest', 'test', 'demo', 'example', 'placeholder',
    'username', 'password', 'login', 'secret', 'v1', 'v2', 'v3',
    'api', 'rest', 'graphql', 'query', 'action', 'method',
    # VT scanner artifacts — no real username was captured
    'unknown', 'UNKNOWN',
}


def _check_credential_in_url(url: str) -> str:
    """
    Detect plaintext credentials embedded in URLs — a CRITICAL finding.

    Two patterns:
    1. Path-based (VirusTotal format): https://auth.example.com/:user:password
       Seen when users accidentally submit authenticated URLs to VirusTotal scanners.
    2. RFC 3986 basic auth: https://user:password@host/
       Some scripts/apps embed creds directly in the URL.

    Filters:
    - Skip known placeholder/version-tag values (v1, v2, api, etc.)
    - Require password complexity: must NOT be all-lowercase-alpha
      (purely lowercase alpha strings are likely path params, not passwords)
    - Require password length >= 4
    """
    decoded = unquote(url)

    # Skip mailto: links — they look like user:pass@host but aren't URLs
    if 'mailto:' in decoded.lower():
        return ''

    # Pattern 1: /:user:password in path
    m = _CRED_PATH_REGEX.search(decoded)
    if m:
        username, password = m.group(1), m.group(2)
        if (username.lower() not in _CRED_FP_VALUES
                and password.lower() not in _CRED_FP_VALUES):
            # Skip pure lowercase alpha (path params like /:action:subaction)
            if not (password.isalpha() and password.islower()):
                return f"PATH_CRED: {username}:{password[:30]}"

    # Pattern 2: user:pass@host (RFC 3986 basic auth in URL authority)
    m = _CRED_AUTH_REGEX.search(url)
    if m:
        username, password = m.group(1), m.group(2)
        if (username.lower() not in _CRED_FP_VALUES
                and password.lower() not in _CRED_FP_VALUES):
            return f"BASIC_AUTH: {username}:{password[:30]}"

    return ''


def _check_ssrf_params(url: str, params: dict) -> str:
    """
    Detect SSRF-prone parameters with external URLs as values.
    Only flag high-confidence params pointing to genuinely external hosts.

    FALSE POSITIVE PATTERNS KILLED:
    - redirect_uri in OAuth flows (expected, whitelisted by server)
    - url= on GitBook image proxy paths (~gitbook/image) — that's how GitBook serves images
    - url= pointing to same parent domain (e.g., twilio.com -> www.twilio.com)
    - url=/redirect on analytics/tracking pixels (google, contentsquare, etc.)
    - Generic params like url, src, href, path, to, uri — way too broad
    - returnUrl/ReturnUrl to sibling subdomains (expected in enterprise SSO/app suites)
    """
    # Only high-confidence SSRF params — open redirect / SSRF
    # Deliberately EXCLUDE: url, src, href, path, uri, to, redirect_uri
    # Those catch too many false positives (image proxies, OAuth, analytics)
    ssrf_params = {'redirect', 'next', 'return_to', 'returnurl', 'return_url',
                   'callback', 'target', 'dest', 'destination', 'forward',
                   'continue', 'proxy', 'fetch', 'load',
                   'image_url', 'img_url'}

    # Skip GitBook image proxy pages entirely — url= is their image CDN, not SSRF
    if '~gitbook/image' in url or '~gitbook/' in url:
        return ''

    # Skip if this is a third-party domain (analytics pixels, etc.)
    if _is_noise_domain(url):
        return ''

    source_parsed = urlparse(url)
    source_host = source_parsed.netloc.lower()
    # Get parent domain (last 2 parts) for same-domain redirect checks
    source_parts = source_host.split('.')
    source_parent = '.'.join(source_parts[-2:]) if len(source_parts) >= 2 else source_host

    for key, values in params.items():
        val = unquote(values[0]) if values else ''
        key_lower = key.lower()
        if key_lower not in ssrf_params:
            continue
        # Only flag if value is a full http(s):// URL
        if not re.match(r'https?://', val):
            continue
        target_parsed = urlparse(val)
        target_host = target_parsed.netloc.lower()
        if not target_host:
            continue
        # Skip if hostname contains non-ASCII characters (malformed/garbled URLs)
        try:
            target_host.encode('ascii')
        except UnicodeEncodeError:
            continue
        # Skip if target is same host
        if target_host == source_host:
            continue
        # Skip if target is same parent domain (subdomain redirects — expected)
        target_parts = target_host.split('.')
        target_parent = '.'.join(target_parts[-2:]) if len(target_parts) >= 2 else target_host
        if target_parent == source_parent:
            continue
        # Skip if target shares the same brand across different TLDs
        # e.g., varonis.com → varonis.io, earlywarning.com → earlywarning.io
        source_brand = source_parts[-2] if len(source_parts) >= 2 else source_host
        target_brand = target_parts[-2] if len(target_parts) >= 2 else target_host
        if source_brand == target_brand and source_brand not in {'com', 'net', 'org', 'io', 'co'}:
            continue
        # Skip if target is a known CDN/image/analytics domain
        if _is_noise_domain(val):
            continue
        # Skip test/PoC values — pentesters often embed evil.com/attacker.com in VT URLs
        # These appear in VT scan history, not in real app traffic
        known_poc_hosts = {'evil.com', 'attacker.com', 'test.com', 'example.com',
                           'burp.com', 'ngrok.io', 'requestbin.com', 'webhook.site',
                           'collaborator.net', 'interactsh.com'}
        if target_host in known_poc_hosts or any(target_host.endswith('.' + h) for h in known_poc_hosts):
            return ''
        return f"{key}={val[:60]}"
    return ''


def _check_graphql_introspection(url: str, params: dict) -> str:
    """
    Detect GraphQL introspection queries in URLs.
    Only flag if the query actually contains introspection keywords — 
    not just any /graphql endpoint.
    """
    if '/graphql' not in url.lower():
        return ''
    query = unquote(params.get('query', [''])[0])
    if not query:
        return ''
    # Only flag actual introspection
    if re.search(r'__schema|__type|IntrospectionQuery', query, re.I):
        return f"Introspection query: {query[:60]}"
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

    # ── Debug / Admin Panels ──
    "Debug_Admin_Panel": {
        "severity": "CRITICAL",
        "description": "Debug or admin panel endpoint accessible — full application compromise risk.",
        "check": lambda url, params: _check_debug_admin(url),
    },

    # ── SSRF-prone params ── (NEW in v3.0)
    "SSRF_Param": {
        "severity": "HIGH",
        "description": "SSRF-prone parameter with external URL value — test for server-side request forgery.",
        "check": lambda url, params: _check_ssrf_params(url, params),
    },

    # ── GraphQL introspection ── (NEW in v3.0 — ONLY if actual introspection query)
    "GraphQL_Introspection": {
        "severity": "MEDIUM",
        "description": "GraphQL introspection query in URL — schema disclosure, helps map attack surface.",
        "check": lambda url, params: _check_graphql_introspection(url, params),
    },

    # ── Plaintext credentials in URL ── (NEW in v3.1)
    "Credential_In_URL": {
        "severity": "CRITICAL",
        "description": "Plaintext username:password embedded in URL path or authority — "
                       "immediate ATO risk. Commonly found in VirusTotal URL submissions.",
        "check": lambda url, params: _check_credential_in_url(url),
    },
}


def _check_internal_ip(url: str) -> str:
    """Check for internal/private IP addresses in URL — skip analytics/tracking noise."""
    decoded = unquote(url)

    # Skip tracking/analytics URLs entirely
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
        if re.search(r'https?://[^/]*' + re.escape(ip), decoded) or \
           re.search(r'(?:host|url|addr|server|device|inform|redirect|proxy|backend).*' + re.escape(ip), decoded, re.I):
            return ip
    return ''


# Documentation path segments — if URL contains these, it's a doc page NOT a live tool
_DOC_PATH_SEGMENTS = [
    '/plugins/', '/docs/', '/documentation/', '/blog/', '/examples/',
    '/reference/', '/changelog/', '/guides/', '/observability/', '/how-to/',
    '/kubernetes-ingress-controller/', '/tutorials/', '/learn/', '/support/',
    '/metering-and-billing/', '/collectors/', '/operator/', '/concepts/',
    '/getting-started/', '/overview/', '/faqs/',
]


def _check_debug_admin(url: str) -> str:
    """Check for exposed debug/admin panels — skip CDNs, SPAs, static assets, and documentation pages."""
    lower = url.lower()

    # Must be on a real application domain, not CDN
    if _is_noise_domain(url):
        return ''

    # Skip static assets — /assets/images/kic/grafana/*.png is NOT an actual Grafana instance
    if _is_static_asset(url):
        return ''

    # Skip documentation pages — /plugins/prometheus is a doc page, not a live Prometheus
    # These paths indicate the URL is about a tool, not running one
    parsed_path = urlparse(url).path.lower()
    parsed_host = urlparse(url).netloc.lower()

    # Skip if the hostname itself is a documentation subdomain
    if parsed_host.startswith('docs.') or '.docs.' in parsed_host:
        return ''

    if any(seg in parsed_path for seg in _DOC_PATH_SEGMENTS):
        return ''

    debug_patterns = [
        r'/(?:phpinfo|server-info|server-status)(?:\.php)?$',
        r'/(?:elmah|trace|diagnostics)\.axd',
        r'/(?:actuator/(?:env|health|info|beans|mappings|configprops))',
        r'/swagger-ui(?:\.html|/index\.html)',
        r'/(?:_debug|_profiler|profiler)/',
        # Admin panels — only flag actual admin endpoints, not API subpaths
        r'/admin/(?:config|settings|database|users)(?:/|$)',
        r'/wp-admin/(?:install|setup-config)\.php',
        r'/solr/admin',
        # Monitoring tools — only flag if they appear to be live instances (at root or /ui)
        r'/(?:kibana|grafana|prometheus)/(?:ui|app|api|explore|graph|dashboard)',
        r'/(?:kibana|grafana|prometheus)(?:\?|$)',  # At root with query or bare
        r'/(?:_cat/(?:indices|nodes|health))',      # Elasticsearch
    ]

    for pattern in debug_patterns:
        m = re.search(pattern, lower)
        if m:
            return m.group(0)
    return ''


def _check_config_files(url: str) -> str:
    """Check for exposed config files — strict matching to avoid SPA false positives."""
    lower = url.lower()

    if _is_noise_domain(url):
        return ''

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
        self._dedup_full = set()   # Full URL dedup (one finding per URL)
        self._dedup_path = set()   # Path-only dedup for path-based checks (Password_Reset, Debug, etc.)
        self._dedup_token_val = set()  # Dedup same token/apiKey value across different paths

    # Path-based checks that should dedup on path, not full URL (strips query strings)
    PATH_DEDUP_CHECKS = {'Password_Reset_UUID', 'Debug_Admin_Panel', 'GraphQL_Introspection'}

    def scan(self) -> Dict:
        start = time.time()
        banner("Passive Bounty Scanner v4.1")
        log_info(f"Scanning {len(self.urls)} unique URLs against {len(HEURISTICS)} heuristics...")

        for url in self.urls:
            url = url.strip()
            if not url or not url.startswith('http'):
                continue

            # Skip noise domains entirely
            if _is_noise_domain(url):
                continue

            # Skip SEO doorway pages (scraped junk)
            if _is_seo_doorway(url):
                continue

            # Parse params once for all checks
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                url_path = f"{parsed.netloc}{parsed.path}"
            except Exception:
                params = {}
                url_path = url

            # Pre-checks: filter out URL-level noise before running heuristics
            is_non_https = _is_http_not_https(url)
            is_http_port = _is_http_with_port(url)  # e.g. http://host:8080/ — port-scan artifact
            is_ip_url = _is_ip_url(url)              # e.g. http://192.168.1.1/ — not a bounty target
            is_sendgrid_doc = _is_sendgrid_doc_url(url, params)
            is_zendesk_chat = _is_zendesk_chat_session(url, params)
            is_saml = _is_saml_url(url, params)     # SAML SSO flows — not leaked secrets
            is_pin_gaming = _is_pin_gaming_url(url, params)  # Casino PIN params
            is_ir_feed = _is_ir_feed_apikey(url, params)  # Public IR feed API keys
            is_notif_email = _is_notification_email_url(url)  # Marketing unsubscribe URLs

            # Entire URL is noise — skip all checks
            # http:// + port = port-scan artifact; raw IPs = not valid bounty targets
            if is_http_port or is_ip_url:
                continue

            for vuln_id, config in HEURISTICS.items():
                # Apply pre-filter rules per check type
                if vuln_id == 'Token_Leak':
                    # Real auth tokens are NEVER served over plain HTTP in production
                    if is_non_https:
                        continue
                    # Skip SendGrid documentation URLs
                    if is_sendgrid_doc:
                        continue
                    # Skip Zendesk chat sessions
                    if is_zendesk_chat:
                        continue
                    # Skip SAML SSO params — expected in every enterprise SSO flow
                    if is_saml:
                        continue
                    # Skip gaming PINs — customer-facing, not auth secrets
                    if is_pin_gaming:
                        continue
                    # Skip public IR feed API keys — embedded in public page JS
                    if is_ir_feed:
                        continue

                if vuln_id == 'PII_Email_Leak':
                    # Skip SendGrid doc URLs
                    if is_sendgrid_doc:
                        continue
                    # Skip marketing notification/unsubscribe emails — legally required
                    if is_notif_email:
                        continue

                if vuln_id == 'PII_Data_Leak':
                    # WhatsApp/Telegram contact links with phone= are public contact buttons,
                    # not PII leaks — already handled by THIRD_PARTY_DOMAINS filter but
                    # double-check here in case URL comes from a redirect
                    if _is_noise_domain(url):
                        continue

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
                    # Path-based dedup for checks that should be unique per path
                    if vuln_id in self.PATH_DEDUP_CHECKS:
                        if url_path in self._dedup_path:
                            self.stats[vuln_id] += 1
                            continue
                        self._dedup_path.add(url_path)
                    else:
                        # Full URL dedup for param-based checks
                        if url in self._dedup_full:
                            self.stats[vuln_id] += 1
                            continue
                        self._dedup_full.add(url)

                    # Token value dedup — same apiKey/token value across multiple
                    # endpoint paths should be ONE finding, not N
                    if vuln_id == 'Token_Leak' and evidence:
                        # Extract the value part (after =) for dedup
                        token_dedup_key = evidence.split('=', 1)[-1][:30] if '=' in evidence else evidence[:30]
                        if token_dedup_key in self._dedup_token_val:
                            self.stats[vuln_id] += 1
                            continue
                        self._dedup_token_val.add(token_dedup_key)

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
        medium = sum(1 for f in self.findings if f["severity"] == "MEDIUM")

        log_success(f"Bounty Scan complete in {elapsed_str(start)}")
        if total:
            log_success(f"Actionable findings: {total} ({critical} CRITICAL, {high} HIGH, {medium} MEDIUM)")
        else:
            log_info("No bounty-worthy findings detected — clean scan.")

        return {
            "findings": self.findings,
            "stats": self.stats,
            "total_urls": len(self.urls)
        }


def main():
    parser = argparse.ArgumentParser(description="Passive Bounty URL Scanner v3.0")
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
