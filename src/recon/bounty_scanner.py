#!/usr/bin/env python3
"""
Module: Bounty Scanner (URL Heuristics) — v7.0
Passively analyzes massive URL collections for high-value bug bounty findings.

════════════════════════════════════════════════════════════════════════════════
DESIGN PHILOSOPHY — GENERAL FRAMEWORK, NOT CASE-BY-CASE PATCHING
════════════════════════════════════════════════════════════════════════════════

Bug bounty programs pay for things that have REAL security impact and aren't
expected behavior. From passive URL analysis, 8 high-signal classes exist:

  1. Credentials in URLs        — email:password in path/authority  [CRITICAL]
  2. Auth token leaks            — session/API tokens in params      [CRITICAL]
  3. Password reset tokens       — reset/verify paths with tokens    [CRITICAL]
  4. JWT in URLs                 — JWTs should never appear in URLs  [CRITICAL]
  5. PII in URLs                 — real emails, SSNs in params       [HIGH]
  6. Open Redirects              — redirect params to external hosts [HIGH]
  7. SSRF-prone params           — server fetches external URLs      [CRITICAL]
  8. Exposed admin/debug/config  — actuator, .env, phpinfo           [CRITICAL]
  9. IDOR API endpoints          — sequential IDs in user-data APIs  [MEDIUM]
 10. Cloud storage exposure      — pre-signed URLs, S3 credentials   [HIGH]

NOT detectable from URLs alone: XSS, SQLi, RCE, CSRF, business logic.

════════════════════════════════════════════════════════════════════════════════
THREE-LAYER FILTER ARCHITECTURE
════════════════════════════════════════════════════════════════════════════════

  Layer 1 — DOMAIN SKIP LIST (before any check)
    → Third-party analytics, CDN, SSO IdPs, marketing infrastructure
    → http:// with explicit port (port-scan artifacts)
    → Raw IP addresses (never valid bounty targets)
    → SEO doorway pages (scraped junk)

  Layer 2 — URL-LEVEL GUARDS (per check-type, before running the check)
    → Token_Leak: skip http://, SAML flows, IR feed public keys, Wix beacons
    → PII_Email_Leak: skip unsubscribe endpoints, SafeLinks artifacts, push-notification infra
    → Open_Redirect / SSRF: skip same-family domains, known PoC hosts

  Layer 3 — SIGNAL VALIDATORS (inside each detection function)
    → Require real values (not junk/placeholder/template variables)
    → Require plausible entropy (not pure lowercase alpha, too short)
    → Type-classified confidence: CRITICAL = report now, HIGH = likely real, MEDIUM = verify

════════════════════════════════════════════════════════════════════════════════
WHAT'S NEW IN v5.0 (complete framework redesign)
════════════════════════════════════════════════════════════════════════════════
  - Token classification engine: types tokens by subclass (autologin, OAuth, API key, session)
    instead of generic "any 20+ char string in a token param"
  - JWT_In_URL: standalone CRITICAL heuristic — JWTs in URL path or fragment
  - Open_Redirect: separated from SSRF with wider param list (r=, go=, from=, etc.)
  - SSRF_Param: true server-side SSRF params (proxy=, fetch=, webhook=, image_url=)
  - Config_File_Exposed: wires up existing _check_config_files() into HEURISTICS
  - Cloud_Storage: detects pre-signed S3/GCS URLs with credential params
  - IDOR_Endpoints: broader API path patterns for user/order/account objects
  - Finding grouping: same type+host+path_prefix collapses to one finding with count
  - Confidence scoring: 0-100 per finding for triage prioritization
  - All v4.1 noise filters preserved and generalized into the architecture
"""

import argparse
import ipaddress
import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.utils import log_info, log_success, log_warning, banner, elapsed_str, read_lines, RICH_AVAILABLE


# ══════════════════════════════════════════════════════════════════════════════
# COMPILED REGEXES
# ══════════════════════════════════════════════════════════════════════════════

EMAIL_REGEX      = re.compile(r'[\w.+-]+@[\w-]+\.[\w.]+')
UUID_REGEX       = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
# Tokens: 20+ chars of base64/hex/alphanumeric — JWTs, API keys, session tokens
TOKEN_REGEX      = re.compile(r'^[A-Za-z0-9_/+=.\-]{20,}$')
# Real JWTs: three base64url segments separated by dots
JWT_REGEX        = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
# Template variables: {keyword}, {{email}}, {ifmobile:1}
TEMPLATE_VAR_RE  = re.compile(r'^\{[^}]+\}$|^\{\{[^}]+\}\}$')
# Private IP ranges
PRIVATE_IP_REGEX = re.compile(
    r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3})'
)
# Unix epoch: 10-digit number (seconds since 1970, ~year 2001-2286)
_EPOCH_10_RE     = re.compile(r'^\d{10}$')


# ══════════════════════════════════════════════════════════════════════════════
# JWT CLAIM DECODER — extract expiry, subject, email from JWT payloads
# ══════════════════════════════════════════════════════════════════════════════

def _decode_jwt_claims(jwt_str: str) -> dict:
    """Decode the payload of a JWT and return key claims.
    Returns dict with: exp, sub, email, typ, azp, iss (if present).
    Returns empty dict on failure."""
    import base64
    try:
        parts = jwt_str.split('.')
        if len(parts) < 2:
            return {}
        payload_b64 = parts[1]
        # Fix base64 padding
        payload_b64 += '=' * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode('utf-8', errors='ignore'))
        claims = {}
        for key in ('exp', 'iat', 'sub', 'email', 'eml', 'typ', 'type', 'azp', 'iss', 'aud', 'user_id', 'scope'):
            if key in payload:
                claims[key] = payload[key]
        return claims
    except Exception:
        return {}


def _jwt_evidence_with_claims(jwt_str: str, prefix: str = '') -> str:
    """Build evidence string for a JWT finding, including decoded claims."""
    claims = _decode_jwt_claims(jwt_str)
    parts = []
    if prefix:
        parts.append(prefix)
    parts.append(f'JWT: {jwt_str[:60]}...')
    if claims.get('exp'):
        import time as _time
        exp = claims['exp']
        if isinstance(exp, (int, float)):
            if exp > _time.time():
                days_left = int((exp - _time.time()) / 86400)
                parts.append(f'STILL VALID ({days_left}d left)')
            else:
                days_ago = int((_time.time() - exp) / 86400)
                parts.append(f'Expired {days_ago}d ago')
    if claims.get('email') or claims.get('eml'):
        email = claims.get('email') or claims.get('eml')
        parts.append(f'User: {email}')
    elif claims.get('sub'):
        parts.append(f'Sub: {str(claims["sub"])[:40]}')
    if claims.get('typ') or claims.get('type'):
        typ = claims.get('typ') or claims.get('type')
        parts.append(f'Type: {typ}')
    return ' | '.join(parts)


def _is_oauth_callback_jwt(url: str, params: dict) -> bool:
    """Return True if the JWT is in a standard OAuth2 authorization code callback.
    These are single-use, short-lived authorization codes — expected behavior.
    Pattern: ?code=eyJ... on callback/redirect paths or root paths.
    Adobe, Coinbase, Shopify etc. all use JWT-format auth codes."""
    code_val = (params.get('code', params.get('Code', ['']))[0])
    if not code_val or not JWT_REGEX.match(code_val):
        return False
    # Decode claims to check if it's an authorization_code type
    claims = _decode_jwt_claims(code_val)
    token_type = claims.get('type', claims.get('typ', '')).lower()
    if token_type in ('authorization_code', 'auth_code', 'code'):
        return True
    # Even without explicit type, ?code= on known OAuth callback patterns is expected
    path = urlparse(url).path.lower()
    oauth_callback_paths = ('/callback', '/oauth/callback', '/oauth2/callback',
                             '/auth/callback', '/login/callback', '/sso/callback',
                             '/signin-oidc', '/connect/callback')
    if any(path.endswith(p) or path == p for p in oauth_callback_paths):
        return True
    # Root path with ?code= and other OAuth params (state=, scope=) is also a callback
    if path in ('/', '') and ('state' in params or 'scope' in params):
        return True
    return False


def _is_invitation_link(url: str, params: dict) -> bool:
    """Return True for invitation/onboarding links — designed behavior.
    Pattern: /accept-invitation, /invite, /join with email/token params.
    These links are intentionally sent to users; emails in them are by design."""
    path = urlparse(url).path.lower()
    invitation_segs = ('/accept-invitation', '/accept_invitation', '/acceptinvitation',
                        '/invite/', '/invitation/', '/join/', '/onboard/',
                        '/team-invite', '/org-invite', '/workspace-invite')
    return any(seg in path for seg in invitation_segs)


# ══════════════════════════════════════════════════════════════════════════════
# JUNK / PLACEHOLDER VALUES (not real data)
# ══════════════════════════════════════════════════════════════════════════════

JUNK_VALUES = {
    '', 'true', 'false', 'null', 'none', 'undefined', 'test', 'example',
    '{token}', '{{token}}', '{email}', '{{email}}', '{id}', '{{id}}',
    'placeholder', 'default', '0', '1', 'en', 'us', 'gb',
    'asc', 'desc', 'all', 'active', 'inactive', 'pending',
    'your_sendgrid_username', 'your_sendgrid_password', 'your_api_key',
    'xxxxxx', 'xxxx', 'your.already.existing.authenticated_domain',
    'unknown', 'UNKNOWN',   # VT scanner artifacts with no real username
}


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 1: DOMAIN SKIP LISTS
# ══════════════════════════════════════════════════════════════════════════════

# CDN & static asset delivery — never contain app logic or secrets
CDN_PATTERNS = [
    'cloudfront.net', 'akamaized.net', 'fastly.net', 'azureedge.net',
    's3.amazonaws.com', 'googleapis.com/storage', 'gstatic.com',
    # Google Fonts — CSS/font delivery, never contains app logic or secrets
    'fonts.googleapis.com', 'fonts.gstatic.com',
    'unpkg.com', 'jsdelivr.net', 'cdnjs.cloudflare.com',
    'ebaystatic.com', 'ebayimg.com',
    # Broad CDN subdomain patterns (check these last — substring match)
    'cdn.', 'static.', 'assets.', 'media.',
]

# Third-party services — not in scope for any program, always noise
THIRD_PARTY_DOMAINS = [
    # Advertising & tag management
    'googletagmanager.com', 'doubleclick.net', 'googlesyndication.com',
    'googleadservices.com', 'googleoptimize.com', 'google.com',
    'bing.com', 'clarity.ms', 'facebook.com', 'fbcdn.net',
    'twitter.com', 'linkedin.com',
    # Analytics & monitoring
    'newrelic.com', 'nr-data.net', 'sentry.io', 'bugsnag.com',
    'segment.io', 'mixpanel.com', 'amplitude.com', 'heap.io',
    'hotjar.com', 'mouseflow.com', 'crazyegg.com', 'fullstory.com',
    'chartbeat.net', 'ping.chartbeat.net',
    '6sc.co', 'b.6sc.co',
    # Wix analytics/telemetry (frog.wix.com = performance beacon, not app)
    'frog.wix.com', 'wix.com',
    # Consent / privacy
    'trustarc.com', 'onetrust.com', 'cookielaw.org',
    # Support / chat
    'intercom.io', 'zendesk.com', 'freshdesk.com',
    # Payment processors (not the target company's servers)
    'stripe.com', 'braintreegateway.com', 'paypal.com',
    # Bot protection
    'recaptcha.net', 'hcaptcha.com',
    # Public platforms
    'github.com', 'hackerone.com', 'medium.com', 'substack.com',
    'wordpress.com', 'ghost.io', 'bigmarker.com', 'corp.google.com',
    # Public contact links (not PII leaks — these are intentional public links)
    'api.whatsapp.com', 'wa.me', 't.me', 'telegram.me',
    # Public review platforms
    'trustpilot.com', 'g2.com', 'capterra.com',
    # SSO Identity Providers — SAML/OAuth flows go through these; expected
    'login.microsoftonline.com', 'accounts.google.com', 'okta.com',
    'auth0.com', 'onelogin.com', 'pingidentity.com', 'idp.ssocircle.com',
    # Email marketing infrastructure
    'sendgrid.net', 'mailchimp.com', 'mandrillapp.com',
    'sparkpostmail.com', 'mailgun.org',
    # SendGrid application domain — login, app, api subdomains
    # api.sendgrid.com is handled separately (special guard); login.sendgrid.com and
    # app.sendgrid.com are SendGrid's own product, NOT bug bounty targets
    'sendgrid.com',
    # Public investor relations platform (Q4 Inc) — API keys are public/embedded in page JS
    'q4inc.com', 'q4cdn.com',
    # Cloudflare Zero Trust / Access — JWTs in /cdn-cgi/access/login callbacks are expected
    # cf. https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/
    'cloudflareaccess.com',
    # GeoIP service — referrer param is just the source page, not an open redirect
    'geoip-js.com',
]

# Email marketing / transactional email platforms where emails-in-URLs are
# expected (required by CAN-SPAM, GDPR). NOT a PII leak when found here.
EMAIL_MARKETING_DOMAINS = {
    'sendgrid.com', 'sendgrid.net', 'api.sendgrid.com', 'app.sendgrid.com',
    'mc.sendgrid.com', 'hubspot.com', 'hubspotpagebuilder.com', 'hs-sites.com',
    'hs-sites-eu1.com', 'hs-email.com', 'mailchimp.com', 'mandrillapp.com',
    'mailgun.org', 'mailgun.net', 'klaviyo.com', 'klaviyo.net',
    'sparkpostmail.com', 'sparkpost.com', 'postmarkapp.com',
    'sendwithus.com', 'brevo.com', 'sendinblue.com',
    # Additional ESP / CRM platforms (v6.1 — reduce PII_Email_Leak FP rate)
    'braze.com', 'iterable.com', 'sailthru.com', 'responsys.com',
    'exacttarget.com', 'customer.io', 'intercom.io', 'drift.com',
    'drip.com', 'activecampaign.com', 'constantcontact.com',
    'campaignmonitor.com', 'getresponse.com', 'aweber.com',
    'convertkit.com', 'moosend.com', 'mailerlite.com', 'omnisend.com',
    'emarsys.com', 'emarsys.net', 'adobe.com',  # Adobe Campaign
    'pardot.com', 'marketo.com', 'act-on.com', 'zoho.com',
    # Transactional email services
    'amazonses.com', 'ses.amazonaws.com', 'mailtrap.io', 'mailjet.com',
    # Mobile attribution platforms — campaign links with emails are by design
    'adjust.com', 'adjust.net', 'branch.io', 'appsflyer.com',
    'kochava.com', 'singular.net',
}


# Static file extensions — path-based checks skip these
STATIC_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp4', '.mp3', '.webm', '.ogg',
    '.pdf', '.zip', '.tar', '.gz',
    '.css', '.map',
}

# Documentation subpaths — tool name in a doc URL ≠ live running instance
DOC_PATH_SEGMENTS = [
    '/plugins/', '/docs/', '/documentation/', '/blog/', '/examples/',
    '/reference/', '/changelog/', '/guides/', '/how-to/', '/learn/',
    '/tutorials/', '/support/', '/getting-started/', '/overview/', '/faqs/',
    '/kubernetes-ingress-controller/', '/concepts/', '/observability/',
    '/metering-and-billing/', '/collectors/', '/operator/',
]


def _is_noise_domain(url: str) -> bool:
    """Return True if URL belongs to a CDN, third-party, or marketing domain."""
    lower = url.lower()
    return any(p in lower for p in CDN_PATTERNS + THIRD_PARTY_DOMAINS)


def _is_static_asset(url: str) -> bool:
    """Return True if URL points to a static asset (image, font, CSS, etc.)."""
    path = urlparse(url.lower()).path
    if Path(path).suffix in STATIC_EXTENSIONS:
        return True
    static_path_markers = ['/assets/', '/images/', '/static/', '/img/',
                           '/media/', '/fonts/', '/icons/', '/dist/', '/build/']
    return any(m in path for m in static_path_markers)


def _is_http_with_port(url: str) -> bool:
    """
    Return True if URL is http:// with an explicit non-standard port.
    These are port-scan artifacts — bounty programs don't accept http://:port findings.
    """
    if not url.startswith('http://') or url.startswith('https://'):
        return False
    try:
        return urlparse(url).port is not None
    except Exception:
        return False


def _is_ip_url(url: str) -> bool:
    """Return True if host is a raw IP — never a valid bounty target in programs."""
    try:
        host = urlparse(url).hostname or ''
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def _is_seo_doorway(url: str) -> bool:
    """
    Return True for scraped SEO doorway pages: http://host:80/city_state.php?token=...
    These flood URL archives but have no security value.
    """
    if not url.startswith('http://'):
        return False
    try:
        parsed = urlparse(url)
        if parsed.port == 80 and parsed.path.endswith('.php'):
            if re.match(r'^/[a-z_]+-?[a-z]+_[a-z]{2}\.php$', parsed.path):
                return True
    except ValueError:
        pass
    return False


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 2: URL-LEVEL GUARD FUNCTIONS (applied per check-type)
# ══════════════════════════════════════════════════════════════════════════════

def _is_saml_url(params: dict) -> bool:
    """
    Return True if URL carries SAMLRequest/SAMLResponse parameters.
    These are base64-encoded XML signed documents — expected in every SSO login flow,
    NOT leaked secrets. No bounty program accepts "I found a SAML request."
    """
    saml_keys = {'samlrequest', 'samlresponse', 'saml_request', 'saml_response'}
    return bool(saml_keys & {k.lower() for k in params})


def _is_ir_feed_apikey(url: str, params: dict) -> bool:
    """
    Return True for investor-relations feed API keys — these are PUBLIC client-side keys.
    Q4 Inc / similar IR platforms embed the same apiKey in every company's public IR page JS.
    Grants read-only access to public press releases and stock quotes. NOT a secret.
    Pattern: ir.*/feed/Event.svc?apiKey=  or  /feed/StockQuote.svc?apiKey=
    """
    try:
        parsed = urlparse(url.lower())
        host, path = parsed.netloc, parsed.path
    except Exception:
        return False
    if not (host.startswith('ir.') or 'investor' in host):
        return False
    if '/feed/' not in path:
        return False
    return 'apikey' in {k.lower() for k in params}


def _is_notification_email_url(url: str) -> bool:
    """
    Return True for marketing email infrastructure URLs where emails in params are expected.
    CAN-SPAM / GDPR *require* that unsubscribe links contain the recipient's email.
    Also returns True for OAuth2 flows where login_hint carries the user's email —
    this is the standard OAuth2 authorization request mechanism, not a PII leak.

    Patterns killed:
      - push-notification.*, track.*, tracking.* subdomains
      - /unsubscribe, /suppression/, /email-abuse, /email_abuse endpoints
      - /public/view/ email web-view pages with embedded unsubscribeLink
      - /view/ hash-addressed email view pages
      - Inbox notification payloads (?first_name=&last_name=&unsubscribeLink=)
      - OAuth2 /oauth2/auth or /authorize with login_hint param (standard OIDC flow)
    """
    lower = url.lower()
    try:
        parsed = urlparse(lower)
        host, path = parsed.netloc, parsed.path
    except Exception:
        return False

    # Marketing infrastructure subdomains
    infra_prefixes = ('push-notification', 'track.', 'tracking.', 'email.',
                      'mailer.', 'newsletter.', 'broadcast.')
    if any(host.startswith(p) for p in infra_prefixes):
        return True

    # Opt-out / suppression endpoints
    opt_out_segs = ['/unsubscribe', '/suppression/', '/email-abuse',
                    '/subscription/unsubscribe', '/email_abuse',
                    '/optout', '/opt-out', '/manage-preferences']
    if any(seg in path for seg in opt_out_segs):
        return True

    # Auth / Registration / Checkout / Profile endpoints — passing email is expected
    auth_segs = ['/login', '/signin', '/sign-in', '/signup', '/sign-up', 
                 '/register', '/welcome', '/verify', '/checkout', '/email_activity']
    if any(seg in path for seg in auth_segs):
        return True

    # Email web-view pages (hash-addressed, contain unsubscribeLink in query)
    if '/public/view/' in path or ('/view/' in path and 'unsubscribelink' in lower):
        return True

    # Marketing subscription/preference centers — JWT in URL is the auth mechanism for
    # the link (unsubscribe, subscription_center) — expected pattern in ESPs
    if '/subscription_center' in path or '/subscription-center' in path:
        return True
    if '/preference' in path and ('center' in path or 'manage' in path):
        return True

    # OAuth2 / OIDC authorization endpoint with login_hint:
    # RFC 6749 + OIDC Core allow login_hint to pre-fill the user's identity.
    # This is standard behavior, not a PII leak.
    oauth_paths = ('/oauth2/auth', '/oauth/authorize', '/oauth2/authorize',
                   '/connect/authorize', '/as/authorization', '/authorize')
    if any(path.startswith(p) or path.endswith(p) for p in oauth_paths):
        if 'login_hint' in lower or 'login_hint' in url:
            return True

    return False


def _is_safelinks_email(val: str) -> bool:
    """
    Return True for Microsoft SafeLinks / Defender URL rewriting artifacts.
    Pattern: 02|01|email@domain|GUID|GUID|0|0|timestamp
    The email belongs to the corporate user who clicked the link through their employer's
    email security gateway. NOT a vulnerability in the target application.
    """
    if '|01|' in val or '|02|' in val:
        parts = val.split('|')
        if len(parts) >= 5:
            for part in parts:
                if '@' in part and '.' in part.split('@')[-1]:
                    return True
    return False


def _same_brand_different_tld(source_host: str, target_host: str) -> bool:
    """
    Return True when source and target share the same brand name but different TLDs.
    e.g. varonis.com → varonis.io, earlywarning.com → earlywarning.io
    These are expected SSO / app-family redirects, not open redirects.
    """
    def brand(host: str) -> str:
        parts = host.split('.')
        return parts[-2] if len(parts) >= 2 else host

    src_brand = brand(source_host)
    tgt_brand = brand(target_host)
    # Exclude generic words that aren't brands
    generic = {'com', 'net', 'org', 'io', 'co', 'app', 'api', 'www'}
    return src_brand == tgt_brand and src_brand not in generic


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 3: SIGNAL VALIDATORS — the detection logic
# ══════════════════════════════════════════════════════════════════════════════

def _has_template_variable(value: str) -> bool:
    """Return True if value is an unfilled template placeholder: {keyword}, {{email}}."""
    return bool(TEMPLATE_VAR_RE.match(value)) or ('{' in value and '}' in value and len(value) < 50)


def _has_real_email(params: dict, url: str = '') -> str:
    """
    Return the first real email address found in params, or ''.
    Guards against: template variables, retina filenames (@2x/@3x), encoded URL
    fragments (@2F), Microsoft SafeLinks, system addresses, Apple Private Relay,
    known-junk values, and email marketing platform URLs.

    Email marketing platforms (SendGrid, HubSpot, Adjust, etc.) routinely include
    the recipient's email in URL params by design — required by CAN-SPAM/GDPR.
    These are NOT PII leaks.
    """
    # Skip email marketing/transactional platforms — emails in their URLs are expected
    if url:
        try:
            _host = urlparse(url.lower()).netloc.lstrip('www.')
            if any(_host == d or _host.endswith('.' + d) for d in EMAIL_MARKETING_DOMAINS):
                return ''
        except Exception:
            pass
    email_params = {
        'email', 'mail', 'e-mail', 'user_email', 'useremail',
        'login', 'username', 'recipient', 'to', 'from', 'sender',
        'login_hint', 'user', 'account', 'upn', 'preferred_username',
        'invited_email', 'filter',
        'emailaddress', 'cc_email', 'customer_email', 'your_email',
    }
    # Analytics/tracking params that may contain binary blobs with embedded emails
    # These are marketing campaign metadata, not PII leaks
    analytics_params = {
        'utm_campaign', 'utm_content', 'utm_term', 'cid', 'mc_cid',
        'emailblastid', 'mkt_tok', 'trk', 'trkEmail', 'nlf',
    }
    skip_patterns = [
        'noreply', 'no-reply', 'notifications', 'mailer-daemon',
        'postmaster', 'donotreply', 'bounce', 'unsubscribe',
        # System / functional addresses — not PII, these are role accounts (v6.1)
        'commerce@', 'info@', 'support@', 'admin@', 'billing@',
        'sales@', 'hello@', 'contact@', 'team@', 'help@',
        'feedback@', 'service@', 'marketing@', 'press@', 'legal@',
        'security@', 'abuse@', 'webmaster@', 'hostmaster@', 'ops@',
    ]
    # UTM newsletter tracking URLs
    url_lower = url.lower() if url else ''
    is_newsletter_tracking = (
        'utm_medium=email' in url_lower or
        'utm_source=newsletter' in url_lower or
        'utm_source=email' in url_lower or
        'emailblastid' in url_lower or
        ('em=' in url_lower and 'utm_' in url_lower)
    )
    # Click/open tracking pixel URLs — emails here are delivery metadata, not PII (v6.1)
    tracking_path_segs = ['/wf/', '/open?', '/click?', '/track/', '/tracking/',
                          '/t/', '/c/', '/pixel/', '/beacon/', '/e/o/', '/e/c/']
    try:
        _path = urlparse(url_lower).path
    except Exception:
        _path = ''
    is_tracking_url = any(seg in _path for seg in tracking_path_segs)
    for key, values in params.items():
        # Skip analytics/tracking metadata params — may have binary blobs with emails
        if key.lower() in analytics_params:
            continue
        val = unquote(values[0]) if values else ''
        if not val or val.lower() in JUNK_VALUES:
            continue
        if _has_template_variable(val):
            continue
        if re.search(r'@[23]x', val):               # retina filenames
            continue
        if re.search(r'@[0-9A-F]{2}', val):         # URL-encoded hex
            continue
        if re.search(r'@[0-9]', val.split('@')[-1] if '@' in val else ''):  # CSS font metric e.g. YTDE@8
            continue
        if _is_safelinks_email(val):                 # MS Defender rewrites
            continue

        match = EMAIL_REGEX.search(val)
        if not match:
            continue
        email = match.group(0).lower()

        # System / notification addresses
        if any(x in email for x in skip_patterns):
            continue
        # Apple Private Relay — randomized opaque addresses, not real PII
        if email.endswith('@privaterelay.appleid.com'):
            continue
        # SendGrid internal doc examples
        if 'sendgrid.com' in email:
            continue

        # Skip newsletter tracking URLs — triage lesson from WF/Amazon:
        # emails in utm_medium=email URLs are archival artifacts, not active PII leaks
        if is_newsletter_tracking:
            continue
        # Skip click/open tracking pixel URLs (v6.1)
        if is_tracking_url:
            continue

        # Only report if this is a clearly email-typed param OR email was clearly present
        if key.lower() in email_params or '@' in val:
            return val
    return ''


def _classify_token(url: str, params: dict) -> Tuple[str, str]:
    """
    Classify tokens by subclass, returning (severity, evidence).
    severity: 'CRITICAL', 'HIGH', or '' (not a real token)

    Subclasses in priority order:
      CRITICAL — autologin tokens, live sessions with expiry, OAuth tokens, passwords
      HIGH     — API keys on in-scope app paths
      ''       — everything else (generic token params that are likely noise)

    This replaces the old generic "any 20+ char string in a token param" approach.
    """
    params_lower = {k.lower(): v for k, v in params.items()}

    # ── CRITICAL: Autologin / magic-link tokens — instant session hijack ──
    if re.search(r'/autologin\b', url, re.I):
        tok = (params_lower.get('token', []) or [''])[0]
        if tok and TOKEN_REGEX.match(tok) and len(tok) > 15:
            return 'CRITICAL', f'autologin_token={tok[:40]}'

    # ── CRITICAL: Live session ID with an explicit expiry timestamp ──
    # session_id= alone is noise; session_id= + expire= means the server sent a live session
    sid_key = next((k for k in ('session_id', 'sessionid', 'jsessionid') if k in params_lower), None)
    if sid_key:
        sid = (params_lower[sid_key] or [''])[0]
        expire = (params_lower.get('expire', params_lower.get('expires', ['']))[0])
        if sid and TOKEN_REGEX.match(sid) and len(sid) > 20 and expire.isdigit():
            return 'CRITICAL', f'session_id={sid[:40]} expire={expire}'

    # ── CRITICAL: OAuth token in URL (both token and consumer key present) ──
    oauth_tok = (params_lower.get('oauth_token', []) or [''])[0]
    if oauth_tok and TOKEN_REGEX.match(oauth_tok):
        oauth_key = (params_lower.get('oauth_consumer_key', []) or [''])[0]
        return 'CRITICAL', f'oauth_token={oauth_tok[:40]}' + (f' key={oauth_key[:20]}' if oauth_key else '')

    # ── CRITICAL: Password in URL (not gaming PIN) ──
    for pwd_key in ('password', 'passwd', 'pwd'):
        pwd = (params_lower.get(pwd_key, []) or [''])[0]
        if pwd and len(pwd) > 5 and pwd.lower() not in JUNK_VALUES:
            if not _has_template_variable(pwd):
                return 'CRITICAL', f'{pwd_key}={pwd[:30]}'

    # ── CRITICAL: JWT appearing as a param value ──
    # Skip AppsFlyer attribution params — af_sig/af_token are deep-link JWTs, not session tokens
    appsflyer_params_lower = {'af_sig', 'af_token', 'af_sub1', 'af_c_id', 'af_adset_id'}
    for key, values in params.items():
        if key.lower() in appsflyer_params_lower:
            continue
        val = (values or [''])[0]
        if val and JWT_REGEX.match(val):
            return 'CRITICAL', f'JWT:{key}={val[:50]}...'

    # ── CRITICAL: Service-specific high-value API keys ──────────────────────
    # These prefixes uniquely identify live secret credentials for specific services.
    # Unlike generic 'api_key=' params, these are unambiguous secrets with known impact.
    for api_key_name in ('api_key', 'apikey', 'apiKey', 'api-key', 'key', 'token', 'secret'):
        val = (params_lower.get(api_key_name.lower(), []) or [''])[0]
        if not val or len(val) < 15:
            continue
        # Stripe live secret keys — full account access
        if val.startswith('sk_live_'):
            return 'CRITICAL', f'Stripe live secret key: {api_key_name}={val[:50]}'
        # Stripe restricted keys — scoped but still live
        if val.startswith('rk_live_'):
            return 'HIGH', f'Stripe restricted key: {api_key_name}={val[:50]}'
        # MoonPay live publishable key — crypto payment processor
        if val.startswith('pk_live_') and len(val) > 20:
            return 'CRITICAL', f'Live payment API key (pk_live_): {api_key_name}={val[:50]}'
        # GitHub personal access token
        if val.startswith('ghp_') and len(val) >= 36:
            return 'CRITICAL', f'GitHub PAT: {api_key_name}={val[:50]}'
        # GitLab personal access token
        if val.startswith('glpat-') and len(val) >= 20:
            return 'CRITICAL', f'GitLab PAT: {api_key_name}={val[:50]}'
        # Slack API token
        if val.startswith('xoxb-') or val.startswith('xoxp-') or val.startswith('xoxa-'):
            return 'CRITICAL', f'Slack token: {api_key_name}={val[:50]}'
        # SendGrid API key format: SG.<22 chars>.<43 chars>
        if val.startswith('SG.') and len(val) > 50:
            return 'CRITICAL', f'SendGrid API key: {api_key_name}={val[:50]}'
        # Twilio Account SID + Auth Token
        if val.startswith('AC') and len(val) == 34 and val[2:].isalnum():
            return 'HIGH', f'Twilio Account SID: {api_key_name}={val[:50]}'

    # ── HIGH: Real API key on an in-scope endpoint (not a public IR feed) ──
    for api_key_name in ('api_key', 'apikey', 'apiKey', 'api-key'):
        val = (params_lower.get(api_key_name.lower(), []) or [''])[0]
        if val and TOKEN_REGEX.match(val) and len(val) > 15 and val.lower() not in JUNK_VALUES:
            if not _is_ir_feed_apikey(url, params):
                # Skip Firebase web API keys — format: AIzaSy... (39 chars)
                # These are public client-side keys embedded in web app JS by design.
                # They are not secrets; they are required to use Firebase services from a browser.
                if val.startswith('AIzaSy') and len(val) == 39:
                    continue
                return 'HIGH', f'{api_key_name}={val[:40]}'

    # ── HIGH: Named auth tokens (access_token, reset_token, etc.) ──
    high_token_params = {
        'access_token', 'refresh_token', 'id_token', 'auth_token',
        'reset_token', 'verification_token', 'auth_code', 'sso_token',
        'stoken', 'client_secret', 'secret',
    }
    # AppsFlyer attribution params — af_sig etc. are mobile attribution SDK JWTs.
    # These appear in deep-links and are NOT session tokens. Entirely different threat model.
    appsflyer_params = {'af_sig', 'af_token', 'af_c_id'}
    for key, values in params.items():
        if key.lower() not in high_token_params:
            continue
        if key.lower() in appsflyer_params:
            continue
        val = (values or [''])[0]
        if not val or len(val) < 12 or val.lower() in JUNK_VALUES:
            continue
        if _has_template_variable(val):
            continue
        if not TOKEN_REGEX.match(val):
            continue
        return 'HIGH', f'{key}={val[:40]}'

    return '', ''


def _has_real_pii(params: dict) -> str:
    """Return evidence string if a param contains non-email PII (SSN, DOB, card, phone)."""
    pii_params = {
        'ssn', 'dob', 'date_of_birth', 'passport', 'passport_number',
        'phone', 'mobile', 'phone_number',
        'credit_card', 'card_number', 'account_number', 'routing_number', 'cvv',
        'social_security', 'tax_id', 'national_id',
    }
    for key, values in params.items():
        val = (values or [''])[0]
        if not val or val.lower() in JUNK_VALUES or len(val) < 5:
            continue
        if _has_template_variable(val):
            continue
        if key.lower() in pii_params and not val.isalpha() and sum(c.isdigit() for c in val) >= 5:
            return f'{key}={val[:25]}'
    return ''


# ── Credential-in-URL patterns ────────────────────────────────────────────────
# Pattern 1: RFC 3986 basic-auth — https://user:pass@host/
_CRED_AUTH_RE = re.compile(r'https?://([^:@/?#\s]{3,}):([^@/?#\s]{4,})@')

_CRED_FP_VALUES = {
    'www', 'http', 'https', 'ftp', 'ssh', 'null', 'user', 'pass',
    'admin', 'guest', 'test', 'demo', 'example', 'placeholder',
    'username', 'password', 'login', 'secret', 'v1', 'v2', 'v3',
    'api', 'rest', 'graphql', 'query', 'action', 'method',
    'unknown', 'UNKNOWN',
}


# Pattern for phone/credential in URL path: /:+countrycode+phone:password
# Common in VirusTotal submissions from booking.com, mercadolibre, registration portals
_PHONE_CRED_PATH_RE = re.compile(
    r'/:((?:\+\d{1,3})?\d{7,15}):([^/?#\s]{4,})',
)
# Pattern for email:password in path: /:email@domain.com:password
_EMAIL_CRED_PATH_RE = re.compile(
    r'/:([\w.+%-]+@[\w.-]+\.[\w]{2,}):([^/?#\s]{4,})',
)


def _check_credential_in_url(url: str, params: dict = None) -> str:
    """
    Detect plaintext credentials embedded in URLs — always CRITICAL.

    Four patterns:
    1. RFC 3986 basic-auth:          https://user:password@dashboard.example.com/
    2. Email:password in path:       https://join.booking.com/:email@gmail.com:P@ssw0rd
    3. Phone:password in path:       https://registration.site.com/:+15551234567:password
    4. Credential param pairs:       ?username=admin&password=secret123

    Guards: skip mailto:, known placeholder values, pure-lowercase-alpha passwords.
    """
    decoded = unquote(url)
    if 'mailto:' in decoded.lower():
        return ''

    # Pattern 1: RFC 3986 basic-auth
    m = _CRED_AUTH_RE.search(url)
    if m:
        username, password = m.group(1), m.group(2)
        if (username.lower() not in _CRED_FP_VALUES
                and password.lower() not in _CRED_FP_VALUES):
            return f'BASIC_AUTH: {username}:{password[:30]}'

    # Pattern 2: Email:password in URL path (VirusTotal pattern)
    m = _EMAIL_CRED_PATH_RE.search(decoded)
    if m:
        email_part, pwd = m.group(1), m.group(2)
        if pwd.lower() not in _CRED_FP_VALUES and not pwd.isalpha():
            return f'EMAIL_CRED_IN_PATH: {email_part}:{pwd[:30]}'

    # Pattern 3: Phone:password in URL path
    m = _PHONE_CRED_PATH_RE.search(decoded)
    if m:
        phone, pwd = m.group(1), m.group(2)
        if pwd.lower() not in _CRED_FP_VALUES and not pwd.isalpha():
            return f'PHONE_CRED_IN_PATH: {phone}:{pwd[:30]}'

    # Pattern 4: Credential param pairs — ?username=X&password=Y
    if params:
        params_lower = {k.lower(): v for k, v in params.items()}
        user_keys = ('username', 'user', 'login', 'email', 'user_email')
        pwd_keys = ('password', 'passwd', 'pwd', 'pass', 'secret')
        user_val = ''
        pwd_val = ''
        for uk in user_keys:
            v = (params_lower.get(uk, [''])[0])
            if v and len(v) > 2 and v.lower() not in JUNK_VALUES and not _has_template_variable(v):
                user_val = v
                break
        for pk in pwd_keys:
            v = (params_lower.get(pk, [''])[0])
            if v and len(v) > 5 and v.lower() not in JUNK_VALUES and not _has_template_variable(v):
                # Require password complexity: not pure lowercase alpha
                if not v.isalpha() or not v.islower():
                    pwd_val = v
                    break
        if user_val and pwd_val:
            # Skip login form submissions to auth endpoints (expected)
            path = urlparse(url).path.lower()
            if not any(seg in path for seg in ('/login', '/signin', '/auth', '/signup')):
                return f'PARAM_CREDS: {user_val}:{pwd_val[:30]}'

    return ''


def _check_jwt_in_url(url: str, params: dict) -> str:
    """
    Detect JWTs appearing anywhere in the URL — path, fragment, or query.
    JWTs should NEVER appear in URLs (they get logged in access logs, browser history,
    Referer headers). This is always CRITICAL regardless of where it appears.

    Exclusions:
    - AppsFlyer attribution params (af_sig, af_token) — deep-link attribution JWTs
    - OAuth2 callback ?code= with JWT-format auth codes — standard OAuth2 flow
    - Invitation links — emails in invitation URLs are designed behavior
    - Marketing subscription_center / preference links with JWT auth
    """
    # Skip AppsFlyer attribution URLs — they put JWTs in deep-links by design
    appsflyer_jwt_params = {'af_sig', 'af_token'}
    if any(k.lower() in appsflyer_jwt_params for k in params):
        if all(k.lower() in appsflyer_jwt_params or not JWT_REGEX.match((v or [''])[0])
               for k, v in params.items()):
            return ''

    # Skip OAuth2 authorization code callbacks — JWT in ?code= is standard
    if _is_oauth_callback_jwt(url, params):
        return ''

    # Skip invitation links — JWTs in invite URLs are by design
    if _is_invitation_link(url, params):
        return ''

    # Check URL body (path and query string combined)
    decoded = unquote(url)
    m = JWT_REGEX.search(decoded)
    if m:
        jwt = m.group(0)
        # Enrich with decoded claims
        return _jwt_evidence_with_claims(jwt)
    return ''


def _check_open_redirect(url: str, params: dict) -> str:
    """
    Detect open redirect parameters — client-side redirect to an external domain.
    Separated from SSRF: open redirects are HIGH (phishing vector), SSRF is CRITICAL.

    Param list is deliberately wide — open redirects appear in many param names.
    Guards against same-domain, same-brand-different-TLD, known PoC hosts, noise domains.
    """
    # Wide param set — open redirects appear in many names
    redirect_params = {
        'redirect', 'redirect_to', 'redirect_url', 'redirecturl',
        'next', 'return', 'return_to', 'return_url', 'returnurl', 'returnto',
        'redir', 'r', 'destination', 'dest',
        'go', 'goto', 'out', 'view',
        'login_redirect', 'post_login_url', 'login_url',
        'success_url', 'failure_url', 'cancel_url',
        'from', 'come_from', 'referrer',
        'continue', 'forward',
        'target',
    }
    # Known PoC / test hosts — pentesters embed these; not real vulnerabilities
    poc_hosts = {
        'evil.com', 'attacker.com', 'test.com', 'example.com', 'localhost',
        'burp.com', 'ngrok.io', 'requestbin.com', 'webhook.site',
        'collaborator.net', 'interactsh.com', 'oastify.com',
    }

    if _is_noise_domain(url):
        return ''

    try:
        src = urlparse(url)
        src_host = src.netloc.lower()
        src_parts = src_host.split('.')
        src_parent = '.'.join(src_parts[-2:]) if len(src_parts) >= 2 else src_host
    except Exception:
        return ''

    for key, values in params.items():
        if key.lower() not in redirect_params:
            continue
        val = unquote(values[0]) if values else ''
        if not re.match(r'https?://', val):
            continue
        try:
            tgt = urlparse(val)
            tgt_host = tgt.netloc.lower()
        except Exception:
            continue
        if not tgt_host:
            continue
        # Skip non-ASCII hostnames (garbled/encoded URLs)
        try:
            tgt_host.encode('ascii')
        except UnicodeEncodeError:
            continue
        # Skip same host
        if tgt_host == src_host:
            continue
        # Skip same parent domain (subdomain redirects — expected)
        tgt_parts = tgt_host.split('.')
        tgt_parent = '.'.join(tgt_parts[-2:]) if len(tgt_parts) >= 2 else tgt_host
        if tgt_parent == src_parent:
            continue
        # Skip same-brand across different TLDs (varonis.com → varonis.io = expected SSO)
        if _same_brand_different_tld(src_host, tgt_host):
            continue
        # Skip known CDN/analytics targets
        if _is_noise_domain(val):
            continue
        # Skip PoC hosts
        if tgt_host in poc_hosts or any(tgt_host.endswith('.' + h) for h in poc_hosts):
            continue
        return f'{key}={val[:80]}'
    return ''


def _check_ssrf_param(url: str, params: dict) -> str:
    """
    Detect true server-side SSRF parameters — where the server fetches the URL value.
    Separated from open redirect (client-side).

    Param list is narrow and specific — these params cause the server to make HTTP requests.
    Guards: same as open_redirect plus GitBook image proxy bypass.
    """
    # Narrow param set — these specific names indicate server-side fetching
    ssrf_params = {
        'proxy', 'fetch', 'load', 'pull', 'get_url', 'request_url',
        'image_url', 'img_url', 'avatar_url', 'photo_url', 'logo_url',
        'webhook', 'hook_url', 'callback_url', 'notify_url', 'ping_url',
        'import_url', 'export_url', 'feed_url', 'rss_url',
        'backend', 'server', 'host_url',
    }
    poc_hosts = {
        'evil.com', 'attacker.com', 'test.com', 'example.com', 'localhost',
        'burp.com', 'ngrok.io', 'requestbin.com', 'webhook.site',
        'collaborator.net', 'interactsh.com', 'oastify.com',
    }

    # GitBook image proxy — url= is their CDN pattern, not SSRF
    if '~gitbook/' in url:
        return ''
    if _is_noise_domain(url):
        return ''

    try:
        src = urlparse(url)
        src_host = src.netloc.lower()
        src_parts = src_host.split('.')
        src_parent = '.'.join(src_parts[-2:]) if len(src_parts) >= 2 else src_host
    except Exception:
        return ''

    for key, values in params.items():
        if key.lower() not in ssrf_params:
            continue
        val = unquote(values[0]) if values else ''
        if not re.match(r'https?://', val):
            continue
        try:
            tgt = urlparse(val)
            tgt_host = tgt.netloc.lower()
        except Exception:
            continue
        if not tgt_host:
            continue
        try:
            tgt_host.encode('ascii')
        except UnicodeEncodeError:
            continue
        if tgt_host == src_host:
            continue
        tgt_parts = tgt_host.split('.')
        tgt_parent = '.'.join(tgt_parts[-2:]) if len(tgt_parts) >= 2 else tgt_host
        if tgt_parent == src_parent:
            continue
        if _same_brand_different_tld(src_host, tgt_host):
            continue
        if _is_noise_domain(val):
            continue
        if tgt_host in poc_hosts or any(tgt_host.endswith('.' + h) for h in poc_hosts):
            continue
        return f'{key}={val[:80]}'
    return ''


def _check_debug_admin(url: str) -> str:
    """
    Detect exposed debug/admin panels — skip CDNs, static assets, and doc pages.

    Patterns:
    - Spring Boot Actuator endpoints (env/beans/configprops)
    - phpinfo, server-status, server-info
    - Swagger UI, GraphQL Playground
    - Debug profilers (_debug, _profiler)
    - Admin config/database panels
    - Elasticsearch /_cat/ API
    - Live Kibana/Grafana/Prometheus instances (at root or /ui)
    """
    if _is_noise_domain(url) or _is_static_asset(url):
        return ''

    parsed = urlparse(url)
    path = parsed.path.lower()
    host = parsed.netloc.lower()

    # Documentation subdomains and paths
    if host.startswith('docs.') or '.docs.' in host:
        return ''
    if any(seg in path for seg in DOC_PATH_SEGMENTS):
        return ''

    debug_patterns = [
        r'/(?:phpinfo|server-info|server-status)(?:\.php)?(?:\?|$)',
        r'/(?:elmah|trace|diagnostics)\.axd',
        r'/actuator/(?:env|beans|configprops|heapdump|mappings|loggers|httptrace|threaddump)',
        r'/swagger-ui(?:\.html|/index\.html|\.json)(?:\?|$)',
        r'/api-docs(?:/v\d+)?(?:\?|$)',
        r'/openapi\.(?:json|yaml)(?:\?|$)',
        r'/(?:_debug|_profiler|profiler)/',
        r'/admin/(?:config|settings|database|users|backup)(?:/|$)',
        r'/wp-admin/(?:install|setup-config)\.php',
        r'/solr/admin(?:/|$)',
        r'/(?:kibana|grafana|prometheus)/(?:ui|app|api|explore|graph|dashboard)',
        r'/(?:kibana|grafana|prometheus)(?:\?|$)',
        r'/_cat/(?:indices|nodes|health|shards)',  # Elasticsearch
        # NOTE: /health, /metrics, /ping are intentionally EXCLUDED:
        #   /health  — standard load-balancer probe, publicly exposed by design on every service
        #   /metrics — Prometheus scrape target; only a bug if unauthenticated AND exposes secrets
        #              (a URL alone cannot tell us whether auth is required — too many FPs)
        #   /ping    — trivial availability check
        # These paths generate near-100% false positives in bounty programs.
        r'/console(?:\?|$)',                        # H2 console, Rails console
        r'/rails/info/',                            # Rails debug info
        r'/heapdump(?:\?|$)',                       # JVM heap dump — always CRITICAL if exposed
        r'/env(?:\?|$)',                            # Spring Boot /env — exposes all config
        r'/actuator(?:\?|$)',                       # Spring Boot actuator root
    ]

    for pattern in debug_patterns:
        m = re.search(pattern, path)
        if m:
            return m.group(0)
    return ''


def _check_config_file(url: str) -> str:
    """
    Detect exposed configuration files — secrets, credentials, source control metadata.

    These appear in URL archives when crawlers index misconfigured servers.
    Each pattern is precise to avoid matching legitimate app routes.
    """
    if _is_noise_domain(url) or _is_static_asset(url):
        return ''

    path = urlparse(url).path.lower()

    config_patterns = [
        # Environment / secrets files
        r'/\.env(?:\.(?:bak|old|local|production|staging|prod|dev|example|backup))?(?:\?|$)',
        r'/\.env\d*(?:\?|$)',
        # Source control metadata (often contains credentials)
        r'/\.git/(?:config|HEAD|index|packed-refs|FETCH_HEAD)',
        r'/\.svn/(?:entries|wc\.db)',
        r'/\.hg/(?:store|dirstate)',
        # Web server / framework config
        r'/\.htpasswd(?:\?|$)',
        r'/\.htaccess(?:\?|$)',
        r'/wp-config\.php(?:\.bak|\.old|~)?(?:\?|$)',
        r'/web\.config(?:\.bak|\.old)?(?:\?|$)',
        r'/config\.(?:php|yml|yaml|json|rb|py)(?:\.bak|\.old)?(?:\?|$)',
        r'/database\.(?:yml|json|php)(?:\?|$)',
        r'/secrets\.(?:yml|json|env)(?:\?|$)',
        r'/credentials\.(?:json|yml)(?:\?|$)',
        r'/application\.(?:properties|yml|yaml)(?:\?|$)',
        # Sensitive data dumps
        r'/backup(?:s)?/.*\.(?:sql|zip|tar\.gz|tar\.bz2)(?:\?|$)',
        r'/dump\.sql(?:\?|$)',
        r'/database\.sql(?:\?|$)',
        r'/.*\.sql\.gz(?:\?|$)',
        # Cloud provider credential files
        r'/\.aws/credentials(?:\?|$)',
        r'/\.ssh/(?:id_rsa|id_ed25519|authorized_keys)(?:\?|$)',
    ]

    for pattern in config_patterns:
        m = re.search(pattern, path)
        if m:
            return m.group(0)
    return ''


def _check_idor_endpoint(url: str, params: dict) -> str:
    """
    Detect IDOR-prone API endpoints where sequential or predictable IDs appear
    in paths that operate on user-owned objects (accounts, orders, invoices).

    EXPANDED COVERAGE (v5.4):
    - Invoice, receipt, billing statement endpoints (financial documents)
    - Order status pages with email param (PII+IDOR combined)
    - Subscription, shipment, tracking endpoints
    - Payment confirmation and refund endpoints
    - Support ticket / case number enumeration

    NOISE GUARDS:
    - UUID-based patterns (/document/UUID) restricted to API paths.
    - Require /api/ prefix for UUID-based findings only.
    - Numeric IDOR requires minimum digit count by object type.
    - Skip CDN, static asset and doc URLs (handled by Layer 1).

    REPORTABILITY LESSONS (from WF/Amazon triage):
    - /order/UUID/status?email= IS reportable: the email param leaks PII to anyone with order UUID
    - Historical Wayback archive URLs are N/A: only flag live endpoints
    - Third-party vendor subdomains (zix, securemail) have low bounty likelihood
    """
    try:
        parsed = urlparse(url)
        path = parsed.path
        host = parsed.netloc.lower()
    except Exception:
        return ''
    path_lower = path.lower()

    # ── Early exits: paths that are never IDOR-exploitable ──
    # Community forums, documentation, blog paths look like resource URLs but aren't
    non_idor_segments = [
        '/docs/', '/documentation/', '/blog/', '/questions/', '/community/',
        '/forum/', '/help/', '/support/article', '/learn/', '/guides/',
        '/reference/', '/tutorials/', '/changelog/', '/faq',
    ]
    if any(seg in path_lower for seg in non_idor_segments):
        return ''

    # ── Pattern 1: REST API user/account objects ──
    idor_patterns = [
        # User/account objects in REST APIs
        r'/api/v?\d*/(?:users?|accounts?|customers?|members?|profiles?)/(\d{4,})',
        r'/api/v?\d*/(?:users?|accounts?)/(\d{4,})/(?:edit|settings|details|data|profile)',

        # Financial objects — API context or standalone paths
        r'/api/v?\d*/(?:orders?|invoices?|receipts?|payments?|transactions?|refunds?)/(\d{5,})',
        r'/(?:orders?|invoices?|receipts?|statements?)/(\d{6,})(?:/|\?|$)',

        # Billing, subscription, payment endpoints (common in SaaS)
        r'/(?:billing|subscription|subscriptions?)/(?:invoices?|receipts?|statements?)/(\d{4,})',
        r'/(?:billing|payments?|checkout)/([a-f0-9-]{32,})(?:/|\?|$)',
        r'/(?:invoice|receipt)/([a-zA-Z0-9_-]{6,})(?:\.pdf|\.html)?(?:\?|$)',

        # Shipment/tracking/fulfillment — require specific resource ID format
        # Note: only match uppercase alphanumeric (real tracking IDs) not /tracking/identify doc paths
        r'/(?:shipments?|fulfillment|parcels?)/([A-Z0-9]{8,})(?:/|\?|$)',
        r'/(?:orders?|shipments?|deliveries)/(\d{5,})/(?:track|status|details|invoice)',

        # Support tickets / case numbers — enumerable by sequential ID
        r'/(?:support|helpdesk|tickets?|cases?)/(?:portal/\d+/)?([A-Z]+-\d{4,})(?:/|\?|$)',
        r'/(?:servicedesk|jira)/.*?/(\w+-\d{4,})/(?!unsubscribe)',

        # Admin operations on user objects
        r'/(?:admin|dashboard|manage)/(?:users?|accounts?|customers?)/(\d{4,})',

        # Download/export links with UUIDs — ONLY in API context
        r'/api/(?:v\d+/)?(?:download|export|report)/([a-f0-9-]{30,})(?:\?|$)',
        r'/api/(?:v\d+/)?(?:files?|documents?|attachments?)/([a-f0-9-]{25,})(?:/|$)',
    ]

    for pattern in idor_patterns:
        m = re.search(pattern, path, re.I)
        if m:
            obj_id = m.group(1)
            return f'ID={obj_id} in {m.group(0)[:60]}'

    # ── Pattern 2: Order/Purchase status page with email param ──
    # e.g. /order/UUID/status?email=user@corp.com  OR  /orders/UUID?email=
    # This is a combined IDOR+PII: the email of the ordering customer is exposed
    # to anyone who obtains the order UUID (from receipt forwarding, search, etc.)
    # Triage lesson: this IS reportable — the customer email has no business reason
    # to be in the URL; it serves as a secondary auth factor but exposes PII.
    order_status_patterns = [
        r'/(?:order|orders?|purchase|purchases?)/([a-f0-9-]{32,})/(?:status|confirm|details|receipt|invoice)',
        r'/(?:order|orders?)/([a-f0-9-]{32,})(?:\?|$)',
    ]
    has_email_param = any(
        k.lower() in ('email', 'mail', 'user_email', 'customer_email')
        for k in params
    )
    if has_email_param:
        for pattern in order_status_patterns:
            m = re.search(pattern, path, re.I)
            if m:
                order_id = m.group(1)
                email_val = next(
                    (v[0] for k, v in params.items() if k.lower() in ('email', 'mail', 'user_email', 'customer_email') and v),
                    ''
                )
                return f'ORDER_PII: order={order_id[:20]} email={email_val[:40]}'

    return ''



def _check_keycloak_action_token(url: str, params: dict) -> str:
    """
    Detect Keycloak SSO action tokens — password reset and account linking tokens
    that appear in VirusTotal/Wayback when users click reset links while their
    browser/email client sends the URL to URL scanners.

    Two forms:
    1. action-token?key=eyJ...  — JWT-encoded token (5-min TTL, ATO if valid)
    2. reset-credentials?client_id=...&tab_id=...  — full reset flow URL

    These are CRITICAL — confirmed reportable against malwarebytes.com.
    Skip: known third-party IdP domains (okta, auth0) where the target IS the SSO.
    """
    lower = url.lower()
    # Must be on a login-actions path
    if 'login-actions/' not in lower:
        return ''
    # Skip noise: known SSO platform domains are expected to have these
    sso_platforms = ('okta.com', 'auth0.com', 'onelogin.com', 'pingidentity.com',
                     'idp.ssocircle.com', 'login.microsoftonline.com', 'accounts.google.com')
    try:
        host = urlparse(url).netloc.lower()
    except Exception:
        return ''
    if any(host == p or host.endswith('.' + p) for p in sso_platforms):
        return ''

    # Pattern 1: action-token with JWT key param
    if 'login-actions/action-token' in lower:
        key_val = (params.get('key', params.get('Key', ['']))[0])
        if key_val and JWT_REGEX.match(key_val):
            # Try to extract expiry from JWT (base64 decode middle segment)
            try:
                import base64
                payload_b64 = key_val.split('.')[1]
                payload_b64 += '=' * (-len(payload_b64) % 4)  # fix padding
                payload = json.loads(base64.b64decode(payload_b64).decode('utf-8', errors='ignore'))
                exp = payload.get('exp', 0)
                import time as _time
                if exp and exp > _time.time():
                    return f'Keycloak action-token JWT (STILL VALID until {exp}): key={key_val[:60]}'
                return f'Keycloak action-token JWT (expired): key={key_val[:60]}'
            except Exception:
                return f'Keycloak action-token JWT: key={key_val[:60]}'
        elif key_val and len(key_val) > 20:
            return f'Keycloak action-token: key={key_val[:60]}'

    # Pattern 2: reset-credentials with tab_id (full reset flow link)
    if 'login-actions/reset-credentials' in lower or 'login-actions/idp-verify' in lower:
        tab_id = (params.get('tab_id', [''])[0])
        client_id = (params.get('client_id', [''])[0])
        client_data = (params.get('client_data', [''])[0])
        if tab_id and (client_id or client_data):
            action = 'reset-credentials' if 'reset-credentials' in lower else 'idp-verify'
            return f'Keycloak {action} link (tab_id={tab_id[:20]} client_id={client_id[:40]})'

    return ''


def _check_signed_document_url(url: str, params: dict) -> str:
    """
    Detect signed invoice/document URLs with time-based expiry.
    These appear when email security scanners follow signed links in transactional
    emails, indexing the URL on VirusTotal/Wayback Machine.

    Pattern: path ends with .pdf (or /invoice/) + s=<epoch>&e=<epoch>&c=<hmac>
    When e > now() → CRITICAL (still valid, PII accessible right now)
    When e < now() → HIGH (was valid, confirms the pattern — report for token duration)

    Confirmed: store.malwarebytes.com/invoice/*.pdf?s=...&e=...&c=...
    """
    import time as _time

    lower = url.lower()
    path = urlparse(url).path.lower()

    # Must look like an invoice/document path
    is_doc_path = (
        path.endswith('.pdf') or
        '/invoice' in path or
        '/receipt' in path or
        '/statement' in path or
        '/document' in path or
        '/order-confirmation' in path
    )
    if not is_doc_path:
        return ''

    # Must have s= (issued) and e= (expiry) unix epoch params
    s_val = (params.get('s', params.get('S', ['']))[0])
    e_val = (params.get('e', params.get('E', ['']))[0])
    c_val = (params.get('c', params.get('C', ['']))[0])

    if not (_EPOCH_10_RE.match(s_val or '') and _EPOCH_10_RE.match(e_val or '')):
        return ''

    issued  = int(s_val)
    expires = int(e_val)
    now     = int(_time.time())

    # Sanity: expiry must be after issue, and issue must be plausible (after 2020)
    if expires <= issued or issued < 1577836800:  # 2020-01-01
        return ''

    from datetime import datetime, timezone
    exp_dt = datetime.fromtimestamp(expires, tz=timezone.utc).strftime('%Y-%m-%d')
    iss_dt = datetime.fromtimestamp(issued,  tz=timezone.utc).strftime('%Y-%m-%d')
    c_short = (c_val or 'N/A')[:16]

    if expires > now:
        days_left = (expires - now) // 86400
        return (f'STILL VALID ({days_left}d left, expires {exp_dt}) '
                f'signed document URL — s={iss_dt} c={c_short}')
    else:
        return (f'Expired signed document URL (was valid {iss_dt}→{exp_dt}) '
                f'confirms pattern — c={c_short}')


def _check_password_reset_token_params(url: str, params: dict) -> str:
    """
    Detect password reset token params on reset/password/account endpoints.
    Targets patterns like:
      /v3/user/password/reset?resetToken=<long_opaque_token>
      /api/users/password?reset_token=<token>
      /account/password/change?token=<token>&email=<email>

    Separated from _check_password_reset_uuid (UUID-specific) and
    _check_password_reset_token (path-segment token).
    This targets QUERY PARAM tokens on explicit password/account reset endpoints.

    Confirmed real: neo-account.grindr.com/v3/user/password/reset?resetToken=...
    """
    path = urlparse(url).path.lower()

    # Skip static assets
    if path.endswith(('.js', '.css', '.map', '.ts')):
        return ''
    if '/_next/static/' in path or '/static/chunks/' in path:
        return ''

    # Must be on a password/account/auth reset endpoint
    is_reset_endpoint = bool(re.search(
        r'/(?:password|account|user|auth)/(?:.*?/)?(?:reset|forgot|recover|change)',
        path, re.I
    )) or bool(re.search(
        r'/(?:reset-?password|password-?reset|forgot-?password)',
        path, re.I
    ))
    if not is_reset_endpoint:
        return ''

    # Look for token params — broader list including resetToken, t, k
    reset_token_params = {
        'resettoken', 'reset_token', 'resetpasswordtoken', 'reset_password_token',
        'token', 'verification_token', 'verificationtoken', 'authtoken', 'auth_token',
        'key', 'k', 't', 'code', 'otp', 'pin',
    }
    params_lower = {k.lower(): v for k, v in params.items()}
    for param_name, param_key in [(k, k) for k in params_lower if k in reset_token_params]:
        val = (params_lower.get(param_name, [''])[0])
        if not val or len(val) < 16 or val.lower() in JUNK_VALUES:
            continue
        if _has_template_variable(val):
            continue
        # Must have real entropy — not pure lowercase alpha (route name)
        if val.isalpha() and val.islower():
            continue
        # UUID format = handled by Password_Reset_UUID heuristic already
        if UUID_REGEX.fullmatch(val):
            continue
        return f'{param_name}={val[:50]}'

    return ''


def _check_cloud_storage(url: str, params: dict) -> str:
    """
    Detect cloud storage exposure:
    1. Pre-signed S3/GCS URLs with credential params (X-Amz-Signature, X-Goog-Signature)
    2. Direct S3 bucket access to sensitive file types (CSV, XLS, SQL, JSON, ZIP)

    Pre-signed URLs with signature params in the URL are always worth reporting —
    they grant time-limited but direct unauthenticated access to private objects.
    """
    lower_url = url.lower()

    # Pre-signed S3 URL — credentials in the URL itself
    if 's3.amazonaws.com' in lower_url or 's3-' in lower_url:
        params_lower = {k.lower() for k in params}
        if 'x-amz-signature' in params_lower or 'x-amz-credential' in params_lower:
            bucket_match = re.search(r'https?://([a-z0-9.-]+)\.s3(?:[.-])', lower_url)
            bucket = bucket_match.group(1) if bucket_match else 'unknown'
            return f'Pre-signed S3 URL (bucket: {bucket})'

    # Pre-signed GCS URL
    if 'storage.googleapis.com' in lower_url:
        if 'x-goog-signature' in lower_url or 'x-goog-credential' in lower_url:
            return 'Pre-signed GCS URL'

    # Direct S3 access to sensitive file types (potential misconfiguration)
    if 's3.amazonaws.com' in lower_url:
        sensitive_exts = r'\.(xlsx?|csv|sql|json|jsonl|zip|tar\.gz|bak|pem|key)(?:\?|$)'
        m = re.search(sensitive_exts, lower_url)
        if m:
            return f'S3 direct access to {m.group(0)[:20]}'

    return ''


def _check_graphql_introspection(url: str, params: dict) -> str:
    """
    Detect GraphQL introspection queries. Only flag if actual introspection keywords
    appear in the query — not just any /graphql endpoint.
    """
    if '/graphql' not in url.lower():
        return ''
    query = unquote(params.get('query', [''])[0])
    if not query:
        return ''
    if re.search(r'__schema|__type|IntrospectionQuery', query, re.I):
        return f'Introspection: {query[:80]}'
    return ''


# Common auth page names that are NOT tokens (used in /auth/<name> pattern)
_AUTH_ACTION_WORDS = {
    'login', 'logout', 'signin', 'signout', 'sign-in', 'sign-out',
    'signup', 'sign-up', 'register', 'registration',
    'forgot-password', 'forgotpassword', 'reset-password', 'resetpassword',
    'change-password', 'changepassword', 'set-password', 'setpassword',
    'verify-email', 'verifyemail', 'confirm-email', 'confirmemail',
    'two-factor', 'twofactor', '2fa', 'mfa', 'otp',
    'callback', 'redirect', 'return', 'sso', 'saml', 'oauth',
    'unauthorized', 'forbidden', 'error', 'success', 'complete', 'completed',
    # Longer auth route names seen as FPs in real scans
    'verifyandredirect', 'add_generic_auth_credentials', 'clientcertificatelogin',
    'postacceptinvitation', 'usessoauthnavigation', 'residencecountry',
    'onboardingforeu', 'onboardingforeustep', 'limitproperties',
}

# Regex to detect camelCase compound words (e.g. residenceCountry, useSsoAuthNavigation)
# These are route/function names, never random tokens
_CAMEL_CASE_WORD_RE = re.compile(r'^[a-z]+(?:[A-Z][a-z0-9]+)+$')
# Regex for snake_case compound words (e.g. add_generic_auth_credentials)
_SNAKE_COMPOUND_RE = re.compile(r'^[a-z]+(?:_[a-z]+){2,}$')


def _check_password_reset_token(url: str, params: dict) -> str:
    """
    Detect password reset / account verification links with real tokens.
    These are CRITICAL — if the token is still valid, it allows account takeover.

    Two patterns:
    1. Token in URL path: /reset-password/TOKEN or /confirm/TOKEN
    2. Token in query param on a reset/verify/confirm endpoint

    NOISE GUARDS (general, not case-by-case):
    - Skip static JS/CSS/map files — Next.js/webpack content hashes look like tokens
    - Skip /auth/<word> where word is a known auth action name (not a token)
    - Require the captured segment to contain at least some numeric or uppercase chars
      (pure lowercase alpha = route name, not a random token)
    """
    parsed = urlparse(url)
    path = parsed.path.lower()

    # Skip static assets — JS bundle hashes (32-char hex) match token patterns
    if path.endswith(('.js', '.css', '.map', '.ts', '.jsx', '.tsx')):
        return ''
    # Skip _next/static/ Next.js bundles entirely — all filenames are content hashes
    if '/_next/static/' in path or '/static/chunks/' in path or '/static/js/' in path:
        return ''

    # Pattern 1: Token in path segment — specific reset/verify/confirm keywords only
    # NOTE: /auth/ is intentionally excluded here because /auth/forgot-password,
    # /auth/sign-in, etc. match any 15-char auth page name as a "token".
    path_patterns = [
        r'/(?:reset-?password|password-?reset|forgot-?password)/([a-f0-9a-zA-Z_-]{15,})',
        r'/(?:verify|confirm|activate|validation)/([a-f0-9a-zA-Z_-]{15,})',
        r'/(?:magic-?link|one-?click|auto-?login|autologin)/([a-f0-9a-zA-Z_-]{15,})',
    ]
    for pattern in path_patterns:
        m = re.search(pattern, path)
        if m:
            token_candidate = m.group(1)
            # Skip known auth action words that look like tokens (e.g. forgot-password = 15 chars)
            if token_candidate.lower().rstrip('/') in _AUTH_ACTION_WORDS:
                continue
            # Require at least some non-lowercase-alpha chars (digits, uppercase, special)
            # Pure lowercase alpha = a route/page name, not a random token
            if token_candidate.isalpha() and token_candidate.islower():
                continue
            return f'Reset/verify token in path: {token_candidate[:40]}'

    # Pattern 2: Token in query param on reset/verify path
    is_reset_path = bool(re.search(
        r'/(?:reset|verify|confirm|activate|validation|change-password|set-password)',
        path, re.I
    ))
    if is_reset_path:
        for tok_key in ('token', 'reset_token', 'verification_token', 'key', 'code'):
            val = (params.get(tok_key, params.get(tok_key.capitalize(), ['']))[0])
            if val and TOKEN_REGEX.match(val) and len(val) > 12 and val.lower() not in JUNK_VALUES:
                return f'{tok_key}={val[:40]}'

    return ''



# -- Strict UUID: 8-4-4-4-12 hex. Cannot be a route name. -------------------
_UUID_FULL_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I
)


def _check_password_reset_uuid(url: str, params: dict) -> str:
    '''Detect UUID-format tokens in password reset / activation paths.

    UUIDs (8-4-4-4-12 hex) are system-generated -- cannot be confused with
    route names, page names, or camelCase function names. Zero FP risk.
    Confirmed real: auth.ripio.com/api/users/reset-password/be1e2273-...'''
    if _is_static_asset(url) or _is_noise_domain(url):
        return ''
    path = urlparse(url).path
    path_lower = path.lower()
    if '/_next/static/' in path_lower or '/static/chunks/' in path_lower:
        return ''
    reset_uuid_re = re.compile(
        r'/(?:reset-?password|password-?reset|forgot-?password'
        r'|confirm|verify|activate|validate|validation|invitation|invite)'
        r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
        re.I
    )
    m = reset_uuid_re.search(path)
    if m:
        return f'UUID reset token in path: {m.group(1)}'
    is_reset = bool(re.search(
        r'/(?:reset|verify|confirm|activate|validate|forgot)', path_lower
    ))
    if is_reset:
        for k in ('token', 'reset_token', 'key', 'code', 't'):
            v = (params.get(k, params.get(k.capitalize(), ['']))[0])
            if v and _UUID_FULL_RE.match(v.strip()):
                return f'{k}={v} (UUID reset token)'
    return ''


def _check_api_spec_exposed(url: str, params: dict) -> str:
    '''Detect exposed API spec files (openapi.yaml/swagger.json) on production.
    Confirmed real: trip.com/ai-resource/trip/openapi.yaml'''
    if _is_noise_domain(url) or _is_static_asset(url):
        return ''
    parsed = urlparse(url)
    host, path = parsed.netloc.lower(), parsed.path.lower()
    if host.startswith(('docs.', 'developer.', 'dev.', 'swagger.', 'api-docs.')):
        return ''
    if any(seg in path for seg in DOC_PATH_SEGMENTS):
        return ''
    spec_re = re.compile(
        r'/(?:openapi|swagger)\.(?:yaml|yml|json)(?:\?|$)'
        r'|/api-docs(?:/v\d+)?(?:\?|$)'
        r'|/swagger-ui(?:\.html|/index\.html)?(?:\?|$)',
        re.I
    )
    m = spec_re.search(path)
    if m:
        return f'API spec exposed: {m.group(0)}'
    return ''


def _check_metrics_endpoint(url: str, params: dict) -> str:
    '''Detect Prometheus /metrics or Spring Boot Actuator on production.
    Leaks topology, error rates, KPIs, possibly env var values.
    Confirmed real: tripgenie-openclaw-prod.trip.com/metrics'''
    if _is_noise_domain(url) or _is_static_asset(url):
        return ''
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower().rstrip('/')
    non_prod = ('dev.', 'development.', 'staging.', 'stage.', 'sandbox.',
                'test.', 'qa.', 'uat.', 'local.', 'preview.', 'canary.')
    if any(host.startswith(p) or f'.{p[:-1]}.' in host for p in non_prod):
        return ''
    if path in ('/metrics', '/metrics/json'):
        return '/metrics (Prometheus -- may expose topology/secrets)'
    if re.search(r'/actuator(?:/(?:env|heapdump|configprops|mappings|beans|loggers))?$', path):
        return f'Spring Boot Actuator: {path}'
    return ''

# ══════════════════════════════════════════════════════════════════════════════
# HEURISTIC REGISTRY
# Each entry: severity, description, check function
# ══════════════════════════════════════════════════════════════════════════════

def _is_8x8_meeting_jwt(url: str) -> bool:
    """
    Return True for 8x8/Jitsi public video conference room guest JWTs.
    Pattern: *.8x8.vc/vpaas-magic-cookie-<hex>/<RoomName>?jwt=...
    These are short-lived PUBLIC GUEST TOKENS for anyone to join a meeting room.
    They are intentionally embedded in meeting invite URLs. Not a secret.
    Found: 1030 false positive Token_Leak / JWT_In_URL hits in real scans.
    """
    lower = url.lower()
    return 'vpaas-magic-cookie' in lower and ('8x8.vc' in lower or '.vc/' in lower)


HEURISTICS: Dict[str, dict] = {

    # ══════════════════════════════════════════════════════════════════════════
    # UNIVERSAL FINDINGS — accepted by ALL bug bounty programs
    # ══════════════════════════════════════════════════════════════════════════

    # ── CRITICAL: Keycloak SSO action tokens (CONFIRMED REPORTABLE) ────────
    'Keycloak_Action_Token': {
        'severity': 'CRITICAL',
        'universal': True,
        'description': (
            'Keycloak SSO action token (password reset or account linking) indexed on '
            'VirusTotal/Wayback Machine. If still valid (5-min TTL), allows direct '
            'account takeover. Confirmed reportable against Keycloak-based SSO portals.'
        ),
        'check': _check_keycloak_action_token,
    },

    # ── CRITICAL/HIGH: Signed document URLs with time-limited tokens ────────
    'Signed_Document_URL': {
        'severity': 'HIGH',  # overridden to CRITICAL when still valid
        'universal': True,
        'description': (
            'Signed invoice/document URL (s=issued, e=expiry, c=HMAC) indexed by a URL scanner. '
            'When still valid, grants direct unauthenticated access to the document — '
            'exposing customer name, address, and financial data. '
            'Confirmed reportable: store.malwarebytes.com invoice PDFs on VirusTotal.'
        ),
        'check': _check_signed_document_url,
        '_get_severity': lambda url, params: (
            'CRITICAL' if 'STILL VALID' in (_check_signed_document_url(url, params) or '')
            else 'HIGH'
        ),
    },

    # ── CRITICAL: Password reset token in query params ──────────────────────
    'Password_Reset_Param': {
        'severity': 'CRITICAL',
        'universal': True,
        'description': (
            'Password reset token in query param on a reset/forgot-password endpoint. '
            'If still valid, allows direct account takeover without knowing the password. '
            'Confirmed real: neo-account.grindr.com/v3/user/password/reset?resetToken=...'
        ),
        'check': _check_password_reset_token_params,
    },

    # ── CRITICAL: Credentials ──────────────────────────────────────────────
    'Credential_In_URL': {
        'severity': 'CRITICAL',
        'universal': True,
        'description': 'Plaintext username:password in URL — immediate ATO risk. '
                       'Common in VirusTotal submissions of authenticated sessions.',
        'check': _check_credential_in_url,
    },

    # ── CRITICAL: JWT anywhere in URL ─────────────────────────────────────
    'JWT_In_URL': {
        'severity': 'CRITICAL',
        'universal': True,
        'description': 'JWT token found in URL path/query — gets logged in access logs, '
                       'browser history, and Referer headers. Claims decoded for triage.',
        # Skip 8x8 vpaas-magic-cookie: public meeting room guest tokens (not secrets)
        'check': lambda url, params: (
            '' if _is_8x8_meeting_jwt(url) else _check_jwt_in_url(url, params)
        ),
    },

    # ── CRITICAL: Auth token leaks ─────────────────────────────────────────
    'Token_Leak': {
        'severity': 'CRITICAL',
        'universal': True,  # service-specific keys (Stripe, GitHub) are universal
        'description': 'Authentication token/API key leaked in URL — session hijack or '
                       'API abuse risk. Classified by type: autologin, OAuth, session+expiry, '
                       'service-specific (Stripe sk_live_, GitHub ghp_, GitLab glpat-, etc.).',
        # Skip known analytics/ad/noise domains, and 8x8 public meeting room JWTs
        'check': lambda url, params: (
            '' if (_is_noise_domain(url) or _is_8x8_meeting_jwt(url)
                   or _is_oauth_callback_jwt(url, params))
            else _classify_token(url, params)[1]
        ),
        '_get_severity': lambda url, params: (
            '' if (_is_noise_domain(url) or _is_8x8_meeting_jwt(url)
                   or _is_oauth_callback_jwt(url, params))
            else (_classify_token(url, params)[0] or 'HIGH')
        ),
    },

    # ── CRITICAL: SSRF ────────────────────────────────────────────────────
    'SSRF_Param': {
        'severity': 'CRITICAL',
        'universal': True,
        'description': 'Server-side request forgery: param causes server to fetch external URL. '
                       'Test for internal network access, cloud metadata (169.254.169.254).',
        'check': _check_ssrf_param,
    },

    # -- CRITICAL: Password reset with UUID token --------------------------------
    'Password_Reset_UUID': {
        'severity': 'CRITICAL',
        'universal': True,
        'description': 'UUID token in password reset/activation path -- '
                       'if still valid allows direct account takeover. '
                       'UUIDs are system-generated; zero FP risk.',
        'check': _check_password_reset_uuid,
    },

    # ══════════════════════════════════════════════════════════════════════════
    # PROGRAM-SPECIFIC FINDINGS — only some programs accept these
    # (e.g., Wix, eBay, Remitify accept PII leaks; others don't)
    # ══════════════════════════════════════════════════════════════════════════

    # ── HIGH: PII email in URL ─────────────────────────────────────────────
    'PII_Email_Leak': {
        'severity': 'HIGH',
        'universal': False,
        'description': 'Real email address in URL params — privacy violation (GDPR/CCPA). '
                       'Reportable only to programs that accept PII disclosure findings.',
        'check': lambda url, params: (
            '' if _is_invitation_link(url, params) else _has_real_email(params, url)
        ),
    },

    # ── HIGH: Cloud storage exposure ──────────────────────────────────────
    'Cloud_Storage_Exposure': {
        'severity': 'HIGH',
        'universal': True,
        'description': 'Pre-signed S3/GCS URL or direct access to sensitive cloud file — '
                       'may expose private data, backups, or internal documents.',
        'check': _check_cloud_storage,
    },

    # ── HIGH: Other PII in URL ─────────────────────────────────────────────
    'PII_Data_Leak': {
        'severity': 'HIGH',
        'universal': False,
        'description': 'Non-email PII (SSN, card number, phone, DOB) in URL params — '
                       'serious privacy violation. Report only to programs accepting PII.',
        'check': lambda url, params: _has_real_pii(params),
    },

    # -- HIGH: API spec exposed ---------------------------------------------------
    'API_Spec_Exposed': {
        'severity': 'HIGH',
        'universal': True,
        'description': 'openapi.yaml/swagger.json on production -- reveals full '
                       'endpoint surface, parameters, and auth schemes.',
        'check': _check_api_spec_exposed,
    },

    # -- HIGH: Prometheus metrics on production -----------------------------------
    'Metrics_Endpoint': {
        'severity': 'HIGH',
        'universal': True,
        'description': 'Prometheus /metrics or Spring Actuator on production -- '
                       'leaks topology, error rates, KPIs, possibly secrets.',
        'check': _check_metrics_endpoint,
    },

    # ── MEDIUM: IDOR endpoints ─────────────────────────────────────────────
    'IDOR_Endpoint': {
        'severity': 'MEDIUM',
        'universal': False,
        'description': 'API endpoint with predictable user/order/account ID in path — '
                       'test for IDOR by accessing another user\'s object ID.',
        'check': _check_idor_endpoint,
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# FINDING GROUPING — collapse same type+host+path_prefix into one finding
# ══════════════════════════════════════════════════════════════════════════════

def _finding_group_key(vuln_id: str, url: str) -> str:
    """
    Return a grouping key for a finding. Findings with the same key are the same
    "class" of issue on the same host and are collapsed with a count.

    Group by: vuln_id + host + first path segment
    e.g. all PII_Email_Leak on push-notification.playtika.com/suppression/ = one group
    """
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        parts = [p for p in parsed.path.split('/') if p]
        # Use first 2 path segments as the group prefix
        path_prefix = '/' + '/'.join(parts[:2]) if parts else '/'
        return f'{vuln_id}::{host}{path_prefix}'
    except Exception:
        return f'{vuln_id}::{url[:80]}'


# ══════════════════════════════════════════════════════════════════════════════
# SCANNER
# ══════════════════════════════════════════════════════════════════════════════

class BountyScanner:

    # Checks where we dedup on path (strip query string) not full URL
    # — avoids N findings for N different query-param variants of the same endpoint
    PATH_DEDUP_CHECKS = {
        'Password_Reset_UUID', 'API_Spec_Exposed', 'Metrics_Endpoint', 'IDOR_Endpoint',
        'Password_Reset_Param', 'Keycloak_Action_Token',
    }
    # Checks where we dedup on (type, evidence_prefix) — same token value on many paths = 1 finding
    TOKEN_DEDUP_CHECKS = {'Token_Leak', 'JWT_In_URL', 'Signed_Document_URL'}

    def __init__(self, urls: List[str]):
        self.urls = urls
        self.findings: List[dict] = []
        self.stats: Dict[str, int] = {k: 0 for k in HEURISTICS}
        # Dedup sets
        self._seen_full: set = set()    # full URL dedup
        self._seen_path: set = set()    # path-only dedup
        self._seen_token: set = set()   # token value dedup (first 30 chars)
        # Grouping: group_key → representative finding + count
        self._groups: Dict[str, dict] = {}

    def scan(self) -> Dict:
        start = time.time()
        banner('Passive Bounty Scanner v7.0')
        log_info(f'Scanning {len(self.urls)} unique URLs against {len(HEURISTICS)} heuristics...')

        for raw_url in self.urls:
            url = raw_url.strip()
            if not url or not url.startswith('http'):
                continue

            # ── Layer 1: Domain skip list ──────────────────────────────────
            if _is_noise_domain(url):
                continue
            if _is_seo_doorway(url):
                continue
            if _is_ip_url(url):
                continue
            if _is_http_with_port(url):
                continue

            # ── Parse once ─────────────────────────────────────────────────
            try:
                parsed   = urlparse(url)
                # Skip IPv6 URLs — rarely bounty-relevant, often parse errors
                if parsed.netloc.startswith('['):
                    continue
                params   = parse_qs(parsed.query, keep_blank_values=True)
                url_path = f'{parsed.netloc}{parsed.path}'
            except Exception:
                params   = {}
                url_path = url

            # ── Layer 2: URL-level guards (computed once per URL) ──────────
            is_http      = url.startswith('http://') and not url.startswith('https://')
            is_saml      = _is_saml_url(params)
            is_ir_feed   = _is_ir_feed_apikey(url, params)
            is_notif     = _is_notification_email_url(url)
            is_sendgrid  = 'api.sendgrid.com' in url and (
                'sendgrid.com' in params.get('api_user', [''])[0] or
                (params.get('api_key', [''])[0]).lower() in JUNK_VALUES
            )
            is_zendesk_chat = (
                ('sessionid' in {k.lower() for k in params}) and
                bool({'chatid', 'conversationid', 'interactionid'} & {k.lower() for k in params})
            )

            # ── Run each heuristic ─────────────────────────────────────────
            for vuln_id, cfg in HEURISTICS.items():

                # Per-heuristic Layer 2 guards
                if vuln_id == 'Token_Leak':
                    if is_http:         continue   # real tokens are always HTTPS
                    if is_saml:         continue   # SAML flows expected
                    if is_ir_feed:      continue   # public IR platform keys
                    if is_sendgrid:     continue   # SendGrid doc examples
                    if is_zendesk_chat: continue   # Zendesk chat sessions
                    if is_notif:        continue   # marketing/unsubscribe flows

                if vuln_id == 'JWT_In_URL':
                    if is_http:     continue       # JWTs on http are usually test traffic

                if vuln_id == 'Keycloak_Action_Token':
                    if is_http:     continue       # Keycloak always uses HTTPS in prod

                if vuln_id == 'Signed_Document_URL':
                    if _is_noise_domain(url): continue

                if vuln_id == 'Password_Reset_Param':
                    if is_http:     continue       # Reset links always sent over HTTPS

                if vuln_id == 'PII_Email_Leak':
                    if is_sendgrid: continue
                    if is_notif:    continue       # marketing unsubscribe (CAN-SPAM)

                if vuln_id == 'PII_Data_Leak':
                    if _is_noise_domain(url): continue

                if vuln_id in ('SSRF_Param',):
                    if is_http:     continue       # Real SSRF/redirect vulns are on HTTPS

                # ── Run the check ──────────────────────────────────────────
                try:
                    evidence = cfg['check'](url, params)
                except Exception:
                    continue
                if not evidence:
                    continue

                # ── Dynamic severity (Token_Leak has CRITICAL/HIGH sub-types) ──
                severity = cfg.get('_get_severity', lambda u, p: cfg['severity'])(url, params) \
                           if '_get_severity' in cfg else cfg['severity']
                if not severity:
                    # _classify_token returned '' = no real token found
                    continue

                # ── Layer: Dedup ───────────────────────────────────────────
                if vuln_id in self.PATH_DEDUP_CHECKS:
                    if url_path in self._seen_path:
                        self.stats[vuln_id] += 1
                        continue
                    self._seen_path.add(url_path)
                elif vuln_id in self.TOKEN_DEDUP_CHECKS:
                    tok_key = (evidence or '')[:30]
                    if tok_key in self._seen_token:
                        self.stats[vuln_id] += 1
                        continue
                    self._seen_token.add(tok_key)
                else:
                    if url in self._seen_full:
                        self.stats[vuln_id] += 1
                        continue
                    self._seen_full.add(url)

                # ── Group findings by type + host + path prefix ────────────
                gkey = _finding_group_key(vuln_id, url)
                if gkey in self._groups:
                    self._groups[gkey]['count'] += 1
                    self.stats[vuln_id] += 1
                    continue

                finding = {
                    'type':        vuln_id,
                    'severity':    severity,
                    'universal':   cfg.get('universal', True),
                    'description': cfg['description'],
                    'url':         url,
                    'count':       1,
                }
                if evidence and evidence is not True:
                    finding['evidence'] = str(evidence)

                self._groups[gkey] = finding
                self.findings.append(finding)
                self.stats[vuln_id] += 1

        # ── Summary ────────────────────────────────────────────────────────
        total    = len(self.findings)
        critical = sum(1 for f in self.findings if f['severity'] == 'CRITICAL')
        high     = sum(1 for f in self.findings if f['severity'] == 'HIGH')
        medium   = sum(1 for f in self.findings if f['severity'] == 'MEDIUM')

        elapsed = elapsed_str(start)
        log_success(f'Bounty Scan complete in {elapsed}')
        if total:
            log_success(f'Actionable findings: {total} ({critical} CRITICAL, {high} HIGH, {medium} MEDIUM)')
        else:
            log_info('No bounty-worthy findings detected — clean scan.')

        return {
            'findings':    self.findings,
            'stats':       self.stats,
            'total_urls':  len(self.urls),
        }


def main():
    parser = argparse.ArgumentParser(description='Passive Bounty URL Scanner v7.0')
    parser.add_argument('-l', '--list',   required=True, help='File of URLs to scan (unique_urls.txt)')
    parser.add_argument('-o', '--output', help='Output JSON file for findings')
    args = parser.parse_args()

    urls = read_lines(args.list)
    if not urls:
        print('No URLs to scan.')
        return

    scanner = BountyScanner(urls)
    results  = scanner.scan()

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        log_success(f'Findings saved to {args.output}')


if __name__ == '__main__':
    main()
