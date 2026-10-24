#!/usr/bin/env python3
"""
Schema Discovery Module — Swagger/OpenAPI, GraphQL Introspection & Feature Flags

Probes live subdomains for exposed API schemas, GraphQL endpoints,
and feature flag configurations. Finding these is often CRITICAL
because they map the entire attack surface instantly.

Ported from BugBounty_Toolkit schema_mapper.py, converted to async.
"""

import argparse
import asyncio
import json
import re
import ssl
import sys
import time
from pathlib import Path
from typing import Dict, List, Set

import aiohttp

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.config import Config
from recon.utils import (
    banner, log_info, log_success, log_warning, log_error, log_finding,
    RateLimiter, read_lines, write_lines, elapsed_str
)


# ── Probe Paths ──────────────────────────────────────────────

SWAGGER_PATHS = [
    '/swagger.json', '/api/swagger.json', '/v1/swagger.json',
    '/v2/swagger.json', '/v3/swagger.json',
    '/openapi.json', '/api/openapi.json',
    '/api-docs', '/v1/api-docs', '/v2/api-docs',
    # tesco branch: Spring / springdoc default is /v3/api-docs. The old list
    # stopped at v2, so Spring Boot services (common in Tesco's origin tier —
    # a Whitelabel error leaked /relationship-service-war/graphql) were missed.
    '/v3/api-docs', '/api/v3/api-docs', '/v3/api-docs/swagger-config',
    '/swagger/v1/swagger.json', '/swagger/v2/swagger.json',
    '/api/v1/swagger.json', '/api/v2/swagger.json',
    '/_swagger', '/swagger-ui/swagger.json',
    # v9.0 BruteCat-inspired: Google Discovery Documents & REST Catalogs
    '/$discovery/rest', '/$discovery/rest?version=v1',
    '/$discovery/rest?version=v2', '/$discovery/rpc',
    '/_catalog', '/v1/_catalog', '/v2/_catalog',
    # WADL (XML-based API description)
    '/application.wadl',
    # OpenAPI v3 YAML & JSON variants
    '/openapi.yaml', '/api/openapi.yaml', '/v1/openapi.json', '/v2/openapi.json',
    '/api/v1/openapi.json', '/api/v2/openapi.json', '/api/v3/openapi.json',
]

GRAPHQL_PATHS = [
    '/graphql', '/graphiql', '/v1/graphql',
    '/api/graphql', '/graphql/v1', '/gql',
    # v9.0: Additional GraphQL paths
    '/api/v1/graphql', '/api/v2/graphql',
    '/query', '/api/query',
]

# v9.0 BruteCat-inspired: OIDC & Auth discovery
OIDC_PATHS = [
    '/.well-known/openid-configuration',
    '/.well-known/oauth-authorization-server',
    '/.well-known/jwks.json',
]

# v9.0 BruteCat-inspired: gRPC service reflection
GRPC_PATHS = [
    '/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo',
    '/grpc.health.v1.Health/Check',
]

FEATURE_FLAG_PATHS = [
    '/api/feature-flags', '/config', '/flags',
    '/api/config', '/api/v1/flags', '/api/v1/config',
    # v9.0: LaunchDarkly / Unleash / Flagsmith common paths
    '/api/client/features', '/api/frontend',
]

# tesco branch: Spring Boot Actuator. env/configprops/heapdump leak secrets
# (CRITICAL); mappings/beans/loggers map internals (HIGH). Tesco's origin tier
# runs Spring Boot services, so an exposed actuator is a direct, high-value find.
ACTUATOR_PATHS = {
    '/actuator/env': 'CRITICAL',
    '/actuator/configprops': 'CRITICAL',
    '/actuator/heapdump': 'CRITICAL',
    '/actuator/mappings': 'HIGH',
    '/actuator/beans': 'HIGH',
    '/actuator/loggers': 'HIGH',
    '/actuator': 'INFO',
}

# v9.0 BruteCat-inspired: Server headers indicating Google/Cloud API backends & API gateways
# Finding these means the host is a live API service worth deeper testing
API_BACKEND_SERVERS = {
    'esf', 'gse', 'scaffolding on httpserver2', 'envoy', 'openresty',
    'kong', 'apigee', 'traefik', 'istio-envoy',
    # 'akamaighost' / 'fastly' REMOVED on the tesco branch: on a CDN/WAF-fronted
    # estate EVERY edge host returns these Server headers, so they flagged 73/73
    # Tesco hosts as "API Backend Server" = pure noise. An edge/CDN is not a
    # dedicated origin API backend, so it must not be treated as a lead.
}

# Infrastructure subdomains that never host real apps
INFRA_PREFIXES = (
    'mta-sts.', 'autoconfig.', 'autodiscover.',
    '_dmarc.', 'mail.', 'smtp.', 'pop.', 'imap.',
    'ns1.', 'ns2.', 'ns3.', 'ns4.',
    'cpanel.', 'whm.', 'webmail.', 'ftp.', 'localhost.',
)

GRAPHQL_INTROSPECTION = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          kind
          name
          fields(includeDeprecated: true) {
            name
            args { name type { kind name ofType { kind name } } }
            type { kind name ofType { kind name ofType { kind name } } }
          }
        }
      }
    }
    """
}


class SchemaDiscovery:
    """Discover exposed API schemas across live subdomains."""

    def __init__(self, live_domains: List[str], output_dir: Path = None, concurrency: int = 20):
        self.live_domains = live_domains
        self.output_dir = output_dir or Path(".")
        self.concurrency = concurrency
        self.findings: List[Dict] = []
        self.api_endpoints: Set[str] = set()
        self._session = None
        self.rate_limiter = RateLimiter(Config.RATE_LIMIT_DEFAULT)

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=self.concurrency)
            timeout = aiohttp.ClientTimeout(total=10)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    "User-Agent": Config.USER_AGENT,
                    "Accept": "application/json, text/html, */*",
                },
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    def _is_infra_subdomain(self, domain: str) -> bool:
        """Skip infrastructure subdomains that never host real apps."""
        d = domain.lower()
        for prefix in INFRA_PREFIXES:
            if d.startswith(prefix) or f'.{prefix}' in d:
                return True
        return False

    async def _check_swagger(self, domain: str) -> List[Dict]:
        """Probe for Swagger/OpenAPI schema files."""
        results = []
        session = await self._get_session()
        base = f"https://{domain}"

        for path in SWAGGER_PATHS:
            url = f"{base}{path}"
            try:
                await self.rate_limiter.acquire()
                async with session.get(url) as resp:
                    if resp.status == 200:
                        ct = resp.headers.get("Content-Type", "").lower()
                        if "json" in ct or "yaml" in ct:
                            text = await resp.text(encoding="utf-8", errors="ignore")
                            text = text[:1_000_000]
                            try:
                                data = json.loads(text)
                                if "swagger" in data or "openapi" in data or "paths" in data:
                                    log_finding(f"[🔥 SWAGGER] {url}")
                                    results.append({
                                        "type": "Swagger/OpenAPI",
                                        "severity": "HIGH",
                                        "url": url,
                                        "domain": domain,
                                        "paths_count": len(data.get("paths", {})),
                                    })
                                    # Extract all API endpoints from the schema
                                    for api_path in data.get("paths", {}).keys():
                                        self.api_endpoints.add(f"{base}{api_path}")
                                    return results  # Found one, no need to check more paths
                            except json.JSONDecodeError:
                                pass
            except Exception:
                continue
        return results

    @staticmethod
    def _looks_like_graphql_json(text: str) -> bool:
        """tesco branch: FP-resistant GraphQL confirmation. A real GraphQL
        response is JSON with a top-level 'data' or 'errors' key (the response
        envelope). On an Akamai/WAF-fronted estate a /graphql GET/POST often
        returns a 200 'Access Denied' HTML page whose body happens to contain
        the word 'graphql' (echoed path) — the old substring check flagged those
        as endpoints. Requiring the JSON envelope kills that false-positive class
        while still catching introspection-disabled endpoints (they return
        {'errors': [...]})."""
        try:
            obj = json.loads(text)
        except Exception:
            return False
        return isinstance(obj, dict) and ("data" in obj or "errors" in obj)

    async def _check_graphql(self, domain: str) -> List[Dict]:
        """Probe for GraphQL endpoints and attempt introspection."""
        results = []
        session = await self._get_session()
        base = f"https://{domain}"

        for path in GRAPHQL_PATHS:
            url = f"{base}{path}"
            try:
                await self.rate_limiter.acquire()
                # First check if endpoint exists
                async with session.get(url) as resp:
                    if resp.status not in [200, 400, 405]:
                        continue

                # Attempt introspection
                await self.rate_limiter.acquire()
                async with session.post(
                    url,
                    json=GRAPHQL_INTROSPECTION,
                    headers={"Content-Type": "application/json"},
                ) as post_resp:
                    if post_resp.status == 200:
                        text = await post_resp.text(encoding="utf-8", errors="ignore")
                        if '"data"' in text and '"__schema"' in text:
                            log_finding(f"[🚨 GRAPHQL INTROSPECTION] {url}")
                            results.append({
                                "type": "GraphQL Introspection",
                                "severity": "CRITICAL",
                                "url": url,
                                "domain": domain,
                            })
                            # Save the schema dump
                            safe_name = domain.replace(".", "_")
                            schema_file = self.output_dir / f"graphql_schema_{safe_name}.json"
                            schema_file.write_text(text[:5_000_000], encoding="utf-8")
                            
                            # Extract type/field names as potential API paths
                            try:
                                gql_data = json.loads(text)
                                types = gql_data.get("data", {}).get("__schema", {}).get("types", [])
                                for t in types:
                                    if t.get("name", "").startswith("__"):
                                        continue
                                    for field in (t.get("fields") or []):
                                        self.api_endpoints.add(f"{url}?query={{{t['name']}{{{field['name']}}}}}")
                            except Exception:
                                pass
                            return results
                        elif self._looks_like_graphql_json(text):
                            log_finding(f"[+] GraphQL endpoint (no introspection): {url}")
                            results.append({
                                "type": "GraphQL Endpoint",
                                "severity": "INFO",
                                "url": url,
                                "domain": domain,
                            })
                            self.api_endpoints.add(url)
                            return results
            except Exception:
                continue
        return results

    async def _check_feature_flags(self, domain: str) -> List[Dict]:
        """Probe for exposed feature flag configurations."""
        results = []
        session = await self._get_session()
        base = f"https://{domain}"

        for path in FEATURE_FLAG_PATHS:
            url = f"{base}{path}"
            try:
                await self.rate_limiter.acquire()
                async with session.get(url) as resp:
                    if resp.status == 200:
                        ct = resp.headers.get("Content-Type", "").lower()
                        if "json" in ct:
                            text = await resp.text(encoding="utf-8", errors="ignore")
                            text = text[:500_000]
                            try:
                                data = json.loads(text)
                                data_str = str(data).lower()
                                if "feature" in data_str or "flag" in data_str or "enable" in data_str:
                                    log_finding(f"[🚩 FEATURE FLAGS] {url}")
                                    results.append({
                                        "type": "Feature Flag Config",
                                        "severity": "MEDIUM",
                                        "url": url,
                                        "domain": domain,
                                    })
                                    return results
                            except json.JSONDecodeError:
                                pass
            except Exception:
                continue
        return results

    async def _check_oidc(self, domain: str) -> List[Dict]:
        """v9.0: Probe for OpenID Connect / OAuth discovery documents."""
        results = []
        session = await self._get_session()
        base = f"https://{domain}"

        for path in OIDC_PATHS:
            url = f"{base}{path}"
            try:
                await self.rate_limiter.acquire()
                async with session.get(url) as resp:
                    if resp.status == 200:
                        ct = resp.headers.get("Content-Type", "").lower()
                        if "json" in ct:
                            text = await resp.text(encoding="utf-8", errors="ignore")
                            try:
                                data = json.loads(text)
                                if any(k in data for k in ('issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri')):
                                    log_finding(f"[🔐 OIDC DISCOVERY] {url}")
                                    results.append({
                                        "type": "OIDC Discovery",
                                        "severity": "INFO",
                                        "url": url,
                                        "domain": domain,
                                        "issuer": data.get("issuer", ""),
                                    })
                                    # Extract token/auth endpoints
                                    for ep_key in ('authorization_endpoint', 'token_endpoint',
                                                   'userinfo_endpoint', 'revocation_endpoint',
                                                   'introspection_endpoint', 'jwks_uri'):
                                        if data.get(ep_key):
                                            self.api_endpoints.add(data[ep_key])
                                    return results
                            except json.JSONDecodeError:
                                pass
            except Exception:
                continue
        return results

    async def _check_server_fingerprint(self, domain: str) -> List[Dict]:
        """v9.0 BruteCat-inspired: Check if domain runs a Google-style API backend.
        Server headers like ESF, GSE, scaffolding on HTTPServer2 indicate live
        internal API services that are often misconfigured."""
        results = []
        session = await self._get_session()
        url = f"https://{domain}/"
        try:
            await self.rate_limiter.acquire()
            async with session.get(url) as resp:
                server = resp.headers.get('Server', '').lower().strip()
                if server in API_BACKEND_SERVERS:
                    log_finding(f"[🔧 API BACKEND] {domain} (Server: {server})")
                    results.append({
                        "type": "API Backend Server",
                        "severity": "INFO",
                        "url": url,
                        "domain": domain,
                        "server_header": server,
                        "note": f"Server: {server} — likely a dedicated API service, worth deeper endpoint fuzzing",
                    })
        except Exception:
            pass
        return results

    async def _check_actuator(self, domain: str) -> List[Dict]:
        """tesco branch: Spring Boot Actuator exposure. A 200 + JSON body on
        /actuator/env|configprops|heapdump is a CRITICAL secret leak; mappings/
        beans/loggers are HIGH (internal map). Requires a JSON content-type and,
        for the bare /actuator index, the HAL '_links' envelope — so a generic
        JSON 200 or a WAF page is not mistaken for an actuator."""
        results = []
        session = await self._get_session()
        base = f"https://{domain}"
        for path, sev in ACTUATOR_PATHS.items():
            url = f"{base}{path}"
            try:
                await self.rate_limiter.acquire()
                async with session.get(url) as resp:
                    if resp.status != 200:
                        continue
                    ct = resp.headers.get("Content-Type", "").lower()
                    if "json" not in ct:
                        continue
                    text = await resp.text(encoding="utf-8", errors="ignore")
                    if path == '/actuator' and '"_links"' not in text:
                        continue
                    log_finding(f"[🔧 SPRING ACTUATOR {sev}] {url}")
                    results.append({
                        "type": "Spring Boot Actuator",
                        "severity": sev,
                        "url": url,
                        "domain": domain,
                        "note": "Exposed actuator — env/configprops/heapdump leak "
                                "secrets; mappings/beans map internal routes.",
                    })
            except Exception:
                continue
        return results

    async def _scan_domain(self, domain: str):
        """Run all schema checks against a single domain."""
        if self._is_infra_subdomain(domain):
            return

        results = []
        results.extend(await self._check_swagger(domain))
        results.extend(await self._check_graphql(domain))
        results.extend(await self._check_feature_flags(domain))
        results.extend(await self._check_oidc(domain))
        results.extend(await self._check_server_fingerprint(domain))
        results.extend(await self._check_actuator(domain))
        self.findings.extend(results)

    async def discover(self) -> Dict:
        """Run schema discovery across all live domains."""
        start = time.time()
        banner("API & Schema Discovery")
        log_info(f"Probing {len(self.live_domains)} live domains for Swagger, GraphQL & Feature Flags...")

        # Process domains with bounded concurrency
        sem = asyncio.Semaphore(self.concurrency)

        async def bounded_scan(domain):
            async with sem:
                await self._scan_domain(domain)

        tasks = [bounded_scan(d) for d in self.live_domains]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Summary
        swagger_count = len([f for f in self.findings if f["type"] == "Swagger/OpenAPI"])
        gql_count = len([f for f in self.findings if "GraphQL" in f["type"]])
        flag_count = len([f for f in self.findings if f["type"] == "Feature Flag Config"])
        oidc_count = len([f for f in self.findings if f["type"] == "OIDC Discovery"])
        backend_count = len([f for f in self.findings if f["type"] == "API Backend Server"])
        actuator_count = len([f for f in self.findings if f["type"] == "Spring Boot Actuator"])

        if self.findings:
            parts = []
            if swagger_count: parts.append(f"{swagger_count} Swagger")
            if gql_count: parts.append(f"{gql_count} GraphQL")
            if flag_count: parts.append(f"{flag_count} Feature Flags")
            if oidc_count: parts.append(f"{oidc_count} OIDC")
            if backend_count: parts.append(f"{backend_count} API Backends")
            if actuator_count: parts.append(f"{actuator_count} Spring Actuator")
            log_success(f"Schema discovery complete: {', '.join(parts)}")
            log_success(f"Extracted {len(self.api_endpoints)} API endpoints from schemas")
        else:
            log_info("No exposed schemas or GraphQL endpoints found.")

        # Save findings
        if self.findings:
            findings_file = self.output_dir / "schema_findings.json"
            findings_file.write_text(json.dumps(self.findings, indent=2), encoding="utf-8")

        if self.api_endpoints:
            ep_file = self.output_dir / "schema_endpoints.txt"
            write_lines(str(ep_file), sorted(self.api_endpoints))

        await self.close()

        log_info(f"Schema discovery completed in {elapsed_str(start)}")

        return {
            "findings": self.findings,
            "api_endpoints": list(self.api_endpoints),
            "swagger_count": swagger_count,
            "graphql_count": gql_count,
            "feature_flag_count": flag_count,
        }


# ── CLI ──────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(description="Schema Discovery — Swagger, GraphQL & Feature Flags")
    parser.add_argument("-i", "--input", required=True, help="File with live domains (one per line)")
    parser.add_argument("-o", "--output", default="./output", help="Output directory")
    parser.add_argument("--concurrency", type=int, default=20)
    args = parser.parse_args()

    domains = read_lines(args.input)
    if not domains:
        log_error("No domains to scan.")
        return

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    scanner = SchemaDiscovery(domains, output_dir, args.concurrency)
    await scanner.discover()


if __name__ == "__main__":
    asyncio.run(main())
