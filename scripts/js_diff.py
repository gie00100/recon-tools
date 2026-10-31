#!/usr/bin/env python3
"""js_diff — change-monitor for the Tesco recon pipeline.

For each domain, compares the two most recent recon runs and reports what is NEW:
  * NEW / CHANGED JS bundles      (by sha256 from js_files.json; a changed bundle
                                   gets a new sha — "new code = less-tested code")
  * NEW JS endpoints              (interesting/api-ish only, from js_findings.json)
  * NEW live hosts + status flips (esp. ->200 reachable / ->403 newly walled)
  * NEW schema/API endpoints
  * NEW bounty leads

Writes a per-domain _delta.json into the newer run dir, and (for --all) an
aggregate monitor_<date>.{json,md}. With --alert, posts a concise Discord summary.
Stdlib-only for the diff; Discord/Config imported lazily and only when --alert.
"""
from __future__ import annotations
import argparse, json, os, re, sys, glob, datetime
from pathlib import Path
from urllib.parse import urlsplit

OUTPUT_DIR = Path(os.environ.get("RECON_OUTPUT", "/root/recon-tools/output"))

_INTEREST = re.compile(
    r"/(api|v\d+|graphql|gql|rest|rpc|bff|internal|admin|account|customer|user|users|"
    r"order|orders|basket|checkout|payment|invoice|document|docs?|file|files|upload|"
    r"download|search|profile|address|clubcard|voucher|token|oauth|auth|login|session|"
    r"export|report|manage|config|setting)s?(/|\?|$|\.)", re.I)
_NOISE = re.compile(r"(w3\.org|schema\.org|github\.com|\.js\.org|mui\.com|googleapis|"
                    r"gstatic|localhost|127\.0\.0\.1|sentry|newrelic|"
                    r"oasis-open\.org|openoffice\.org|purl\.org|xmlns)", re.I)
# Akamai Bot-Manager sensor telemetry embedded in the sensor JS: high-entropy random
# path segments ending in /API/start/ or /API/noticeError — they rotate every page
# load so they false-positive as NEW forever. Not app endpoints.
_SENSOR = re.compile(r"/API/(start|noticeError)(/|$)", re.I)
# iWork/Numbers/OpenOffice document-export artifacts mis-parsed as endpoints
# (btool-test.ourtesco: .iwa, META-INF, mime-type strings, boolean literals).
_DOCART = re.compile(
    r"\.iwa(/|$)|/META-INF/|"
    r"/(application|text|image|audio|video|font|multipart)/[a-z0-9.+-]+(/|$)|"
    r"/(On/Off|True/False|Yes/No)(/|$)", re.I)
# A path that is just a short fragment (e.g. /=8, /RH) — not a real route.
_FRAG = re.compile(r"^/[=A-Za-z0-9]{1,3}$")
# Third-party analytics/CDN JS loaded BY Tesco pages but not Tesco assets — they
# rotate content every fetch, so they false-positive as "changed bundles" forever.
_BUNDLE_NOISE = re.compile(
    r"(googletagmanager|google-analytics|doubleclick|googlesyndication|gstatic|googleapis|"
    r"cloudflare|hs-scripts|hsforms|hsubspot|hubspot|js-eu\d|js-na\d|facebook|fbcdn|"
    r"cookielaw|onetrust|hotjar|clarity\.ms|cdn\.cookie|segment|optimizely|qualtrics|"
    r"newrelic|nr-data|sentry|bugsnag|datadog|cdnjs\.cloudflare|jsdelivr|unpkg)", re.I)


def _clean_ep(ep: str) -> bool:
    """True if an extracted endpoint is a usable URL (not extraction garbage)."""
    if not ep.startswith(("http://", "https://")) or len(ep) > 300:
        return False
    if any(c.isspace() or c == "\\" or ord(c) < 0x20 for c in ep):
        return False
    if any(m in ep for m in ("{", "}", "${", "%{", "<", ">", "`")):
        return False
    return True


def _keep_ep(ep: str) -> bool:
    """Keep only real, interesting APP endpoints. Drops extraction garbage, noise
    hosts, Akamai sensor paths, document-export artifacts, and junk/fragment paths.
    The INTEREST match is on the PATH (+query), NOT the whole URL — otherwise
    https://admin.x.tesco.com/=8 is kept just because the HOST contains 'admin'."""
    if not _clean_ep(ep):
        return False
    try:
        sp = urlsplit(ep)
    except Exception:
        return False
    path = sp.path or ""
    pq = path + (("?" + sp.query) if sp.query else "")
    if _NOISE.search(ep) or _SENSOR.search(path) or _DOCART.search(path):
        return False
    if len(path) <= 2 or _FRAG.match(path):
        return False
    return bool(_INTEREST.search(pq))


def _jload(p, default):
    try: return json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception: return default

def _lines(p):
    try: return set(l.strip() for l in Path(p).read_text(encoding="utf-8", errors="replace").splitlines() if l.strip())
    except Exception: return set()

def find_runs(domain: str):
    """Return the two most recent run dirs for a domain (newest first), or fewer."""
    cands = [Path(d) for d in glob.glob(str(OUTPUT_DIR / f"{domain}_*")) if Path(d).is_dir()]
    # dir names end in _YYYYMMDD_HHMMSS -> lexical sort == chronological
    cands = [c for c in cands if re.search(r"_\d{8}_\d{6}$", c.name)]
    cands.sort(key=lambda p: p.name, reverse=True)
    return cands[:2]

def _manifest(run: Path):
    """url->sha and sha->[urls] from js_files/js_files.json (empty if pre-v10)."""
    m = _jload(run / "js_files" / "js_files.json", {})
    url2sha, sha2urls = {}, {}
    for e in (m.get("saved") or []):
        u, s = e.get("url"), e.get("sha256")
        if u and s:
            url2sha[u] = s
            sha2urls.setdefault(s, []).append(u)
    return url2sha, sha2urls

def _hosts(run: Path):
    out = {}
    for h in _jload(run / "live_hosts.json", []):
        if h.get("url"): out[h["url"]] = h
    return out

def _bounty(run: Path):
    d = _jload(run / "bounty_targets.json", {})
    f = (d.get("findings") if isinstance(d, dict) else d) or []
    return {(x.get("type",""), x.get("url","")): x for x in f if isinstance(x, dict)}

def _collapse_wildcards(new_hosts: list, host_map: dict):
    """Fold wildcard-DNS clusters (permutations like admin./api./dev.<parent> that all
    return the SAME response) into one entry, so they stop inflating 'new hosts'.

    Returns (distinct_hosts[], wildcards[]) where wildcards is a list of
    "*.<parent> [Nx status/len]" summaries. A cluster = >=4 new hosts sharing the same
    parent domain AND the same (status, content_length) signature.
    """
    from collections import defaultdict
    groups = defaultdict(list)
    for u in new_hosts:
        host = urlsplit(u).hostname or u
        parent = host.split(".", 1)[1] if host.count(".") >= 2 else host
        h = host_map.get(u, {})
        sig = (h.get("status"), h.get("content_length"))
        groups[(parent, sig)].append(u)
    distinct, wildcards = [], []
    for (parent, sig), members in groups.items():
        if len(members) >= 4:
            wildcards.append(f"*.{parent} [{len(members)}x status={sig[0]} len={sig[1]}]")
        else:
            distinct.extend(members)
    return sorted(distinct), sorted(wildcards)


def diff_domain(domain: str, prev: Path = None, curr: Path = None) -> dict:
    runs = find_runs(domain)
    if curr is None:
        curr = runs[0] if runs else None
    if prev is None:
        prev = runs[1] if len(runs) > 1 else None
    if curr is None:
        return {"domain": domain, "error": "no runs found"}
    first_baseline = prev is None

    # JS bundles (sha). If the previous run predates JS tracking (no manifest),
    # treat bundles as a baseline this run — don't flood with "all current = new".
    cu2s, cs2u = _manifest(curr)
    pu2s, ps2u = ({}, {}) if first_baseline else _manifest(prev)
    bundle_baseline = first_baseline or not pu2s
    new_shas = set(cs2u) - set(ps2u)
    changed = []          # same url, new sha (redeploy of a bundle we track)
    for u, s in cu2s.items():
        if u in pu2s and pu2s[u] != s:
            changed.append(u)
    new_bundles = [] if bundle_baseline else sorted({u for s in new_shas for u in cs2u[s] if u not in pu2s})
    # Drop third-party analytics/CDN bundles (googletagmanager etc.) — not Tesco assets
    # and they rotate every fetch, so they'd false-positive as "changed" forever.
    new_bundles = [u for u in new_bundles if not _BUNDLE_NOISE.search(u)]
    changed = [u for u in changed if not _BUNDLE_NOISE.search(u)]

    # JS endpoints
    cep = set(_jload(curr / "js_findings.json", {}).get("endpoints") or []) or _lines(curr / "js_endpoints.txt")
    pep = set() if first_baseline else (set(_jload(prev / "js_findings.json", {}).get("endpoints") or []) or _lines(prev / "js_endpoints.txt"))
    new_eps = sorted(e for e in (cep - pep) if _keep_ep(e))

    # live hosts
    ch, ph = _hosts(curr), ({} if first_baseline else _hosts(prev))
    raw_new = sorted(set(ch) - set(ph))
    new_hosts, wildcards = _collapse_wildcards(raw_new, ch)
    flips = []
    for u in sorted(set(ch) & set(ph)):
        a, b = ch[u].get("status"), ph[u].get("status")
        if a != b:
            flips.append({"url": u, "from": b, "to": a,
                          "reachable": (a == 200 and b in (0,401,403,404,500,502,503))})

    # schema + bounty
    new_schema = sorted(_lines(curr / "schema_endpoints.txt") - (set() if first_baseline else _lines(prev / "schema_endpoints.txt")))
    cb, pb = _bounty(curr), ({} if first_baseline else _bounty(prev))
    new_leads = [cb[k] for k in (set(cb) - set(pb))]

    delta = {
        "domain": domain,
        "curr": curr.name, "prev": (prev.name if prev else None),
        "baseline": first_baseline,
        "new_bundles": new_bundles[:200],
        "changed_bundles": sorted(changed)[:200],
        "new_js_endpoints": new_eps[:200],
        "new_hosts": new_hosts,
        "wildcards": wildcards,          # collapsed *.parent clusters (not distinct assets)
        "status_flips": flips,
        "new_schema": new_schema[:100],
        "new_leads": [{"severity": l.get("severity"), "type": l.get("type"), "url": l.get("url","")[:160]} for l in new_leads],
        "counts": {"new_bundles": len(new_bundles), "changed_bundles": len(changed),
                   "new_js_endpoints": len(new_eps), "new_hosts": len(new_hosts),
                   "wildcards": len(wildcards),
                   "status_flips": len(flips), "new_schema": len(new_schema),
                   "new_leads": len(new_leads)},
    }
    try:
        (curr / "_delta.json").write_text(json.dumps(delta, indent=2), encoding="utf-8")
    except Exception:
        pass
    return delta


def has_signal(d: dict) -> bool:
    c = d.get("counts", {})
    # bundle CHANGES (not first-run baseline floods) + hosts/leads/flips/new-endpoints are signal
    return bool(c and (c["changed_bundles"] or c["new_hosts"] or c["new_leads"]
                       or c["new_schema"] or any(f["reachable"] for f in d.get("status_flips", []))
                       or (c["new_js_endpoints"] and not d.get("baseline"))
                       or (c["new_bundles"] and not d.get("baseline"))))


def summarize(deltas: list) -> str:
    lines = [f"# Tesco monitor — {datetime.datetime.now(datetime.timezone.utc):%Y-%m-%d %H:%M UTC}"]
    sig = [d for d in deltas if has_signal(d)]
    if not sig:
        lines.append("\nNo notable changes since last run.")
        return "\n".join(lines)
    for d in sig:
        c = d["counts"]
        lines.append(f"\n## {d['domain']}  (vs {d.get('prev') or 'baseline'})")
        if d.get("baseline"):
            lines.append("  _first run with JS tracking — baseline established_")
        if c["new_hosts"]:
            lines.append(f"  NEW hosts ({c['new_hosts']}): " + ", ".join(d["new_hosts"][:10]))
        for w in d.get("wildcards", []):
            lines.append(f"  (wildcard, ignore) {w}")
        for f in d["status_flips"]:
            if f["reachable"]:
                lines.append(f"  NOW REACHABLE {f['from']}->{f['to']}: {f['url']}")
        if c["changed_bundles"]:
            lines.append(f"  CHANGED JS bundles ({c['changed_bundles']}): " + ", ".join(d["changed_bundles"][:6]))
        if c["new_bundles"] and not d.get("baseline"):
            lines.append(f"  NEW JS bundles ({c['new_bundles']}): " + ", ".join(d["new_bundles"][:6]))
        if d["new_js_endpoints"] and not d.get("baseline"):
            lines.append(f"  NEW interesting JS endpoints ({c['new_js_endpoints']}):")
            for e in d["new_js_endpoints"][:12]:
                lines.append(f"     + {e}")
        if c["new_schema"]:
            lines.append(f"  NEW schema/API ({c['new_schema']}): " + ", ".join(d["new_schema"][:6]))
        for l in d["new_leads"]:
            lines.append(f"  NEW lead [{l['severity']}] {l['type']}: {l['url']}")
    return "\n".join(lines)


def _targets(path):
    try:
        return [l.strip() for l in Path(path).read_text(encoding="utf-8").splitlines()
                if l.strip() and not l.strip().startswith("#")]
    except Exception:
        return []


def _alert(text: str):
    """Post the summary to the Discord results webhook (chunked)."""
    try:
        sys.path.insert(0, "/root/recon-tools/src")
        from recon.config import Config
        import urllib.request
        hook = Config.DISCORD_RESULTS_WEBHOOK_URL or Config.DISCORD_WEBHOOK_URL
        if not hook:
            print("[alert] no webhook configured"); return
        # Discord 2000-char content cap -> chunk
        for i in range(0, len(text), 1800):
            chunk = text[i:i+1800]
            data = json.dumps({"content": "```md\n" + chunk + "\n```"}).encode()
            # Discord blocks requests without a browser-ish User-Agent (-> 403).
            req = urllib.request.Request(hook, data=data, headers={
                "Content-Type": "application/json",
                "User-Agent": "tesco-monitor/1.0 (+recon-tools)",
            })
            urllib.request.urlopen(req, timeout=15).read()
        print("[alert] posted to Discord")
    except Exception as e:
        print(f"[alert] failed: {e}")


def main():
    ap = argparse.ArgumentParser(description="Tesco recon change-monitor (JS-first)")
    ap.add_argument("--domain")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--targets", default="/root/recon-tools/tesco_targets.txt")
    ap.add_argument("--alert", action="store_true", help="post summary to Discord")
    ap.add_argument("--prev"); ap.add_argument("--curr")
    args = ap.parse_args()

    if args.domain and not args.all:
        prev = Path(args.prev) if args.prev else None
        curr = Path(args.curr) if args.curr else None
        deltas = [diff_domain(args.domain, prev, curr)]
    else:
        deltas = [diff_domain(d) for d in _targets(args.targets)]

    text = summarize(deltas)
    print(text)
    # aggregate artifacts
    mon = OUTPUT_DIR / "_monitor"; mon.mkdir(parents=True, exist_ok=True)
    day = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
    (mon / f"monitor_{day}.json").write_text(json.dumps(deltas, indent=2), encoding="utf-8")
    (mon / f"monitor_{day}.md").write_text(text, encoding="utf-8")
    if args.alert and any(has_signal(d) for d in deltas):
        _alert(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
