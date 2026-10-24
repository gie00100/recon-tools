# Tesco recon profile (`tesco` branch)

This branch tunes the generic recon-tools pipeline for the **Tesco** bug-bounty
program (HackerOne `tesco`). It exists as a branch — not a config flag — because
recon against each target is genuinely different: Tesco is a large, Akamai-walled,
multi-market estate, and the generic defaults produce noise and miss its
conventions. Keep program-specific tuning here; keep `main` generic.

## The Tesco reality (why the defaults don't fit)

- **Almost everything is Akamai-fronted and default-deny.** ~70% of live hosts
  return a 200- or 403-wrapped "Access Denied". Every *unknown* path 403s
  identically, so **unauthenticated path-probing is near-useless** — you cannot
  tell a real endpoint from a walled one by status code alone. Confirmation of
  API/GraphQL surface needs either a real browser-minted `bm_*`/`_abck` cookie or
  a different signal (JS references, schema JSON envelopes).
- **The datacenter IP is extra-penalized.** A 458 MB VPS cannot mint an Akamai
  sensor cookie (no browser fits), so the walled majority can't be fetched from
  the box. The VPS covers the ~16 reachable/non-walled hosts; walled hosts are
  covered opportunistically by reusing a cookie from your own browser session.
- **`ppe` is Tesco's dominant non-prod marker** (~290 live hosts) — far more than
  dev/sit/uat. The generic permutation list didn't include it.
- **Origin tier is Spring Boot** behind the edge (a Whitelabel error once leaked
  `/relationship-service-war/graphql`), so Spring conventions (`/v3/api-docs`,
  `/actuator/*`) matter.

## What this branch changes vs `main`

| File | Change | Why |
|------|--------|-----|
| `src/recon/live_probe.py` | Raise aiohttp `max_line_size`/`max_field_size` to 65536, split connect vs total timeout, 3-attempt retry on transient errors | Tesco hosts (e.g. `www.tescomobile.com`) ship a >8 KB CSP header; aiohttp's 8190-byte default rejected the whole response and silently dropped the live host |
| `src/recon/subdomain_enum.py` | Permutation word list leads with observed lifecycle markers (`ppe,dev,sit,pte,uat,stg,…`) | `ppe` was missing entirely, so the highest-yield non-prod tier was never permuted |
| `src/recon/schema_discovery.py` | Remove `akamaighost`/`fastly` from `API_BACKEND_SERVERS` | On an Akamai estate these flagged 73/73 hosts as "API Backend" = pure noise; an edge/CDN is not an origin API |
| `src/recon/schema_discovery.py` | GraphQL endpoint requires a JSON envelope (`data`/`errors`), not the substring "graphql" | WAF 200 "Access Denied" pages echo the path and FP'd as GraphQL endpoints |
| `src/recon/schema_discovery.py` | Add `/v3/api-docs` (springdoc) paths + Spring Boot Actuator check (`/actuator/env|configprops|heapdump` = CRITICAL) | Tesco origin runs Spring Boot; these are the real exposed-spec / secret-leak surfaces |

These three module fixes (especially the CSP and Akamai-FP ones) are good
candidates to also land on `main` later — they're correctness fixes, not just
Tesco preferences — but they live here until that's decided.

## How to run

Deploy this branch to the collection VPS under `/root/recon-tools`, then:

```bash
# Lean, idempotent deep recon (discovery + JS + schema), skips domains done today:
./run_tesco_deep.sh targets/tesco_targets.txt

# Exhaustive "don't miss a thing" run (adds waymore/crawl/urlcollect URL corpora):
./run_tesco_full.sh targets/tesco_targets.txt

# Daily JS-change monitor (new/changed bundles => new code => bugs) + Discord alert:
./monitor_tesco.sh          # wire as cron: 0 3 * * * /root/recon-tools/monitor_tesco.sh
```

Module sets are pruned for the Tesco estate (dropped `asn`/`portscan`/`credhunt`/
`backup` — they produced ~0 results and `backup --active` OOM'd the box). Helper
scripts: `scripts/js_diff.py` (bundle/endpoint diff between runs), `scripts/prune_runs.py`
(keep newest 2 runs/domain so the small box never fills), `scripts/tesco_diff.py`
(live-host/subdomain churn between dates).

## Scope (verify against the live program before reporting)

- **In-scope core (14, full subdomain enum):** `targets/tesco_targets.txt` —
  `*.tesco.com/.sk/.hu/.ie/.org`, `*.itesco.cz/.sk`, `*.tescocloud/ourtesco/
  tesco-europe/tescoplc.com`, + `www.booker/onestop/tescomobile` (subsidiaries =
  www host + subdirectories only, NOT other subdomains).
- **OOS but bounty-eligible (bonus):** `targets/tesco_oos_targets.txt`.
- **Never test:** Tesco Bank (`*.tescobank.*`), Dunnhumby, `tescoinsiderportal.com`,
  `ourtesco.com/bams/*`, `ourtesco.com/brandlibrary/*`.
