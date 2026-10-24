"""Diff two Tesco recon runs — what's NEW, what DISAPPEARED, what CHANGED.

Answers "why did live hosts go up/down" concretely: it's a set diff, not a net
number. Compares in-scope subdomains and live hosts per domain between two dated
runs under output/<date>/, and flags status-code changes (e.g. 200 -> 403) for
hosts present in both.

    python -m scripts.tesco_diff                     # two most recent Tesco runs
    python -m scripts.tesco_diff 2026-09-02 2026-09-10
    python -m scripts.tesco_diff --union             # union of live hosts across ALL runs
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

from src.scope.scope_engine import ScopeEngine

OUT = Path("output")
TESCO = ["itesco.cz", "itesco.sk", "ourtesco.com", "tesco-europe.com", "tesco.com",
         "tesco.hu", "tesco.ie", "tesco.org", "tesco.sk", "tescocloud.com",
         "tescoplc.com", "www.booker.co.uk", "www.onestop.co.uk", "www.tescomobile.com"]
ENG = ScopeEngine.from_csv()


def _host(u: str) -> str:
    return (urlsplit(u).hostname or u).lower()


def _rd(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _live(date: str, dom: str) -> dict[str, int]:
    """in-scope {hostname: status} from a run's live_hosts.json."""
    out = {}
    for h in _rd(OUT / date / dom / "live_hosts.json") or []:
        u = h.get("url", "")
        if u and ENG.is_in_scope(u):
            out[_host(u)] = h.get("status", 0)
    return out


def _subs(date: str, dom: str) -> set[str]:
    p = OUT / date / dom / "subdomains.txt"
    if not p.exists():
        return set()
    return {ln.strip().lower() for ln in p.read_text(encoding="utf-8", errors="replace").splitlines()
            if ln.strip() and ENG.is_in_scope("https://" + ln.strip())}


def tesco_runs() -> list[str]:
    return sorted(d.name for d in OUT.iterdir()
                  if d.is_dir() and (d / "tesco.com").is_dir())


def diff(a: str, b: str) -> None:
    print(f"# Tesco run diff:  {a}  ->  {b}\n")
    tot = dict(sub_add=0, sub_rm=0, live_add=0, live_rm=0, changed=0)
    for dom in TESCO:
        la, lb = _live(a, dom), _live(b, dom)
        sa, sb = _subs(a, dom), _subs(b, dom)
        live_add = sorted(set(lb) - set(la))
        live_rm = sorted(set(la) - set(lb))
        sub_add, sub_rm = sorted(sb - sa), sorted(sa - sb)
        changed = {h: (la[h], lb[h]) for h in set(la) & set(lb) if la[h] != lb[h]}
        tot["sub_add"] += len(sub_add); tot["sub_rm"] += len(sub_rm)
        tot["live_add"] += len(live_add); tot["live_rm"] += len(live_rm)
        tot["changed"] += len(changed)
        if not (live_add or live_rm or sub_add or sub_rm or changed):
            continue
        print(f"## {dom}")
        print(f"   live: {len(la)} -> {len(lb)}   (+{len(live_add)} / -{len(live_rm)})   "
              f"subs: {len(sa)} -> {len(sb)}   (+{len(sub_add)} / -{len(sub_rm)})")
        if live_add:
            print(f"   + NEW live:  {', '.join(live_add[:8])}" + (" ..." if len(live_add) > 8 else ""))
        if live_rm:
            print(f"   - GONE live: {', '.join(live_rm[:8])}" + (" ..." if len(live_rm) > 8 else ""))
        if changed:
            ex = [f"{h} {o}->{n}" for h, (o, n) in list(changed.items())[:6]]
            print(f"   ~ status changed: {', '.join(ex)}" + (" ..." if len(changed) > 6 else ""))
        print()
    print("=" * 70)
    print(f"TOTALS  live +{tot['live_add']} / -{tot['live_rm']}  (net {tot['live_add']-tot['live_rm']:+d})   "
          f"subs +{tot['sub_add']} / -{tot['sub_rm']}   status-changed {tot['changed']}")
    print("Net live-host change is add MINUS gone — a small net can hide large churn.")


def union() -> None:
    runs = tesco_runs()
    print(f"# Union of in-scope live hosts across {len(runs)} Tesco runs: {', '.join(runs)}\n")
    gtot = 0
    for dom in TESCO:
        u = set()
        per = []
        for r in runs:
            hosts = set(_live(r, dom))
            per.append(f"{r.split('-',1)[1]}={len(hosts)}")
            u |= hosts
        gtot += len(u)
        best = max((len(set(_live(r, dom))) for r in runs), default=0)
        extra = len(u) - best
        if u:
            print(f"  {dom:20} union={len(u):>4}  (best single run={best}, +{extra} only-seen-in-others)  [{' '.join(per)}]")
    print(f"\n  UNION TOTAL live hosts across all runs: {gtot}")
    print("  -> testing the union covers hosts that any single run missed.")


def main() -> int:
    args = sys.argv[1:]
    if args and args[0] == "--union":
        union(); return 0
    runs = tesco_runs()
    if len(runs) < 2:
        print("need >=2 Tesco runs under output/<date>/"); return 1
    a, b = (args[0], args[1]) if len(args) >= 2 else (runs[-2], runs[-1])
    diff(a, b)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
