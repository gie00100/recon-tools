#!/usr/bin/env python3
"""
Module 7: HTML/JSON Report Generator
Generates a beautiful interactive HTML report and structured JSON
summary of all reconnaissance findings.
"""

import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.utils import banner, log_info, log_success, log_error


def _render_secret_row(s: dict) -> str:
    """Render a single secret finding as an HTML table row."""
    sev = s.get('severity', 'INFO')
    stype = s.get('type', '')
    match_val = s.get('match', '')[:60]
    source_name = s.get('source', '').split('/')[-1][:30]
    return (
        f'<tr>'
        f'<td><span class="badge {sev.lower()}">{sev}</span></td>'
        f'<td>{stype}</td>'
        f'<td>{match_val}</td>'
        f'<td>{source_name}</td>'
        f'</tr>'
    )


def _render_phase_row(p: dict) -> str:
    """Render a single pipeline phase as an HTML timeline item."""
    name = p.get('name', '')
    duration = p.get('duration', '')
    count = p.get('result_count', 0)
    return (
        f'<li>'
        f'<span class="dot"></span>'
        f'<span class="phase-name">{name}</span>'
        f'<span class="phase-duration">{duration}</span>'
        f'<span class="phase-count">{count} results</span>'
        f'</li>'
    )

class ReportGenerator:
    """Generate HTML and JSON reports from recon data."""

    def __init__(self, target: str, output_dir: str):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.data = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "subdomains": [],
            "live_hosts": [],
            "js_findings": {"endpoints": [], "secrets": []},
            "backup_wordlist_count": 0,
            "unique_urls": [],
            "phases": [],
        }

    def set_subdomains(self, subs: list):
        self.data["subdomains"] = sorted(subs)

    def set_live_hosts(self, hosts: list):
        self.data["live_hosts"] = hosts

    def set_js_findings(self, findings: dict):
        self.data["js_findings"] = findings

    def set_backup_count(self, count: int):
        self.data["backup_wordlist_count"] = count

    def set_unique_urls(self, urls: list):
        self.data["unique_urls"] = sorted(urls)

    def add_phase(self, name: str, duration: str, result_count: int):
        self.data["phases"].append({
            "name": name,
            "duration": duration,
            "result_count": result_count,
        })

    def _generate_html(self) -> str:
        """Generate the full HTML report."""
        subs = self.data["subdomains"]
        hosts = self.data["live_hosts"]
        secrets = self.data["js_findings"].get("secrets", [])
        endpoints = self.data["js_findings"].get("endpoints", [])
        phases = self.data["phases"]

        # Count severities
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
        for s in secrets:
            sev = s.get("severity", "INFO")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        # Tech distribution
        tech_counts = {}
        for h in hosts:
            for t in h.get("technologies", []):
                tech_counts[t] = tech_counts.get(t, 0) + 1

        # Status distribution
        status_counts = {}
        for h in hosts:
            st = h.get("status", 0)
            status_counts[st] = status_counts.get(st, 0) + 1

        # WAF distribution
        waf_counts = {}
        for h in hosts:
            waf = h.get("waf", "")
            if waf:
                waf_counts[waf] = waf_counts.get(waf, 0) + 1

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recon Report — {self.target}</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-card: #1c2333;
            --border: #30363d;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
            --accent-purple: #bc8cff;
            --accent-orange: #f0883e;
            --gradient-1: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --gradient-2: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            --gradient-3: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
            --gradient-4: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}

        .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}

        /* Header */
        .header {{
            text-align: center;
            padding: 3rem 2rem;
            background: linear-gradient(180deg, rgba(88,166,255,0.08) 0%, transparent 100%);
            border-bottom: 1px solid var(--border);
            margin-bottom: 2rem;
        }}
        .header h1 {{
            font-size: 2.5rem;
            background: var(--gradient-3);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}
        .header .target {{
            font-size: 1.2rem;
            color: var(--accent-blue);
            font-family: monospace;
        }}
        .header .meta {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }}

        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.2rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            transition: transform 0.2s, border-color 0.2s;
        }}
        .stat-card:hover {{
            transform: translateY(-2px);
            border-color: var(--accent-blue);
        }}
        .stat-card .number {{
            font-size: 2.5rem;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 0.3rem;
        }}
        .stat-card .label {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .stat-card.blue .number {{ color: var(--accent-blue); }}
        .stat-card.green .number {{ color: var(--accent-green); }}
        .stat-card.red .number {{ color: var(--accent-red); }}
        .stat-card.yellow .number {{ color: var(--accent-yellow); }}
        .stat-card.purple .number {{ color: var(--accent-purple); }}
        .stat-card.orange .number {{ color: var(--accent-orange); }}

        /* Sections */
        .section {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-bottom: 1.5rem;
            overflow: hidden;
        }}
        .section-header {{
            padding: 1rem 1.5rem;
            background: var(--bg-card);
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
            cursor: pointer;
        }}
        .section-header h2 {{
            font-size: 1.1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .section-header .count {{
            background: var(--accent-blue);
            color: white;
            padding: 0.15rem 0.6rem;
            border-radius: 10px;
            font-size: 0.8rem;
        }}
        .section-body {{ padding: 1rem 1.5rem; max-height: 500px; overflow-y: auto; }}

        /* Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }}
        th {{
            text-align: left;
            padding: 0.6rem 0.8rem;
            border-bottom: 2px solid var(--border);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.5px;
            position: sticky;
            top: 0;
            background: var(--bg-secondary);
        }}
        td {{
            padding: 0.5rem 0.8rem;
            border-bottom: 1px solid var(--border);
            font-family: monospace;
            font-size: 0.8rem;
        }}
        tr:hover td {{ background: rgba(88,166,255,0.05); }}

        /* Severity Badges */
        .badge {{
            display: inline-block;
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge.critical {{ background: #f8514922; color: #f85149; border: 1px solid #f8514944; }}
        .badge.high {{ background: #f0883e22; color: #f0883e; border: 1px solid #f0883e44; }}
        .badge.medium {{ background: #d2992222; color: #d29922; border: 1px solid #d2992244; }}
        .badge.info {{ background: #58a6ff22; color: #58a6ff; border: 1px solid #58a6ff44; }}

        /* Status Badges */
        .status {{ font-weight: 600; }}
        .status.s2xx {{ color: var(--accent-green); }}
        .status.s3xx {{ color: var(--accent-yellow); }}
        .status.s4xx {{ color: var(--accent-orange); }}
        .status.s5xx {{ color: var(--accent-red); }}

        /* Search */
        .search-box {{
            width: 100%;
            padding: 0.7rem 1rem;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: var(--bg-primary);
            color: var(--text-primary);
            font-size: 0.9rem;
            margin-bottom: 1rem;
            outline: none;
        }}
        .search-box:focus {{ border-color: var(--accent-blue); }}

        /* Timeline */
        .timeline {{
            padding: 0;
            list-style: none;
        }}
        .timeline li {{
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 0.6rem 0;
            border-bottom: 1px solid var(--border);
        }}
        .timeline .phase-name {{ flex: 1; }}
        .timeline .phase-duration {{ color: var(--text-secondary); font-family: monospace; }}
        .timeline .phase-count {{
            background: var(--bg-card);
            padding: 0.2rem 0.6rem;
            border-radius: 6px;
            font-size: 0.8rem;
            color: var(--accent-green);
        }}
        .timeline .dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--accent-green);
            flex-shrink: 0;
        }}

        /* Footer */
        .footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            font-size: 0.8rem;
        }}

        /* Scrollbar */
        ::-webkit-scrollbar {{ width: 6px; }}
        ::-webkit-scrollbar-track {{ background: var(--bg-primary); }}
        ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: var(--text-secondary); }}
    </style>
</head>
<body>

<div class="header">
    <h1>🔍 Recon Report</h1>
    <div class="target">{self.target}</div>
    <div class="meta">Generated: {self.data['timestamp']}</div>
</div>

<div class="container">

    <!-- Stats Cards -->
    <div class="stats-grid">
        <div class="stat-card blue">
            <div class="number">{len(subs)}</div>
            <div class="label">Subdomains</div>
        </div>
        <div class="stat-card green">
            <div class="number">{len(hosts)}</div>
            <div class="label">Live Hosts</div>
        </div>
        <div class="stat-card purple">
            <div class="number">{len(endpoints)}</div>
            <div class="label">JS Endpoints</div>
        </div>
        <div class="stat-card red">
            <div class="number">{sev_counts['CRITICAL'] + sev_counts['HIGH']}</div>
            <div class="label">Critical/High Secrets</div>
        </div>
        <div class="stat-card yellow">
            <div class="number">{self.data['backup_wordlist_count']}</div>
            <div class="label">Backup Paths</div>
        </div>
        <div class="stat-card orange">
            <div class="number">{len(tech_counts)}</div>
            <div class="label">Technologies</div>
        </div>
    </div>

    <!-- Secrets Section -->
    {"" if not secrets else f'''
    <div class="section">
        <div class="section-header">
            <h2>🔑 Secrets & Sensitive Data <span class="count">{len(secrets)}</span></h2>
        </div>
        <div class="section-body">
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>Match</th>
                        <th>Source</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(_render_secret_row(s) for s in sorted(secrets, key=lambda x: ['CRITICAL','HIGH','MEDIUM','INFO'].index(x.get('severity','INFO'))))}
                </tbody>
            </table>
        </div>
    </div>
    '''}

    <!-- Live Hosts Section -->
    <div class="section">
        <div class="section-header">
            <h2>🌐 Live Hosts <span class="count">{len(hosts)}</span></h2>
        </div>
        <div class="section-body">
            <input type="text" class="search-box" placeholder="Filter hosts..." onkeyup="filterTable(this, 'hosts-table')">
            <table id="hosts-table">
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Status</th>
                        <th>Title</th>
                        <th>Tech</th>
                        <th>WAF</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(f'''
                    <tr>
                        <td><a href="{h.get('url','')}" target="_blank" style="color:var(--accent-blue);text-decoration:none">{h.get('url','')[:55]}</a></td>
                        <td><span class="status s{str(h.get('status',0))[0]}xx">{h.get('status','')}</span></td>
                        <td>{(h.get('title','') or '-')[:40]}</td>
                        <td>{', '.join(h.get('technologies',[])[:3]) or '-'}</td>
                        <td>{h.get('waf','') or '-'}</td>
                        <td>{h.get('response_time_ms','')}ms</td>
                    </tr>''' for h in sorted(hosts, key=lambda x: x.get('status', 999)))}
                </tbody>
            </table>
        </div>
    </div>

    <!-- Subdomains Section -->
    <div class="section">
        <div class="section-header">
            <h2>📋 Subdomains <span class="count">{len(subs)}</span></h2>
        </div>
        <div class="section-body">
            <input type="text" class="search-box" placeholder="Filter subdomains..." onkeyup="filterTable(this, 'subs-table')">
            <table id="subs-table">
                <thead><tr><th>Subdomain</th></tr></thead>
                <tbody>
                    {"".join(f'<tr><td>{s}</td></tr>' for s in subs[:500])}
                    {"<tr><td><em>... and " + str(len(subs)-500) + " more</em></td></tr>" if len(subs) > 500 else ""}
                </tbody>
            </table>
        </div>
    </div>

    <!-- JS Endpoints Section -->
    {"" if not endpoints else f'''
    <div class="section">
        <div class="section-header">
            <h2>📡 JS Endpoints <span class="count">{len(endpoints)}</span></h2>
        </div>
        <div class="section-body">
            <input type="text" class="search-box" placeholder="Filter endpoints..." onkeyup="filterTable(this, 'ep-table')">
            <table id="ep-table">
                <thead><tr><th>Endpoint</th></tr></thead>
                <tbody>
                    {"".join(f'<tr><td>{ep}</td></tr>' for ep in endpoints[:300])}
                    {"<tr><td><em>... and " + str(len(endpoints)-300) + " more</em></td></tr>" if len(endpoints) > 300 else ""}
                </tbody>
            </table>
        </div>
    </div>
    '''}

    <!-- Pipeline Timeline -->
    {"" if not phases else f'''
    <div class="section">
        <div class="section-header">
            <h2>⏱️ Pipeline Timeline</h2>
        </div>
        <div class="section-body">
            <ul class="timeline">
                {"".join(_render_phase_row(p) for p in phases)}
            </ul>
        </div>
    </div>
    '''}

</div>

<div class="footer">
    Recon Toolkit v1.0 — Automated Bug Bounty Reconnaissance Suite<br>
    Report generated at {self.data['timestamp']}
</div>

<script>
function filterTable(input, tableId) {{
    const filter = input.value.toLowerCase();
    const table = document.getElementById(tableId);
    const rows = table.getElementsByTagName('tr');
    for (let i = 1; i < rows.length; i++) {{
        const cells = rows[i].getElementsByTagName('td');
        let match = false;
        for (let j = 0; j < cells.length; j++) {{
            if (cells[j].textContent.toLowerCase().includes(filter)) {{
                match = true;
                break;
            }}
        }}
        rows[i].style.display = match ? '' : 'none';
    }}
}}
</script>

</body>
</html>"""
        return html

    def generate(self) -> Dict[str, str]:
        """Generate both HTML and JSON reports."""
        banner("Report Generator")

        # Generate HTML
        html_path = self.output_dir / "report.html"
        html_content = self._generate_html()
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        log_success(f"HTML report → {html_path}")

        # Generate JSON
        json_path = self.output_dir / "report.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, default=str)
        log_success(f"JSON report → {json_path}")

        return {"html": str(html_path), "json": str(json_path)}


if __name__ == "__main__":
    # Standalone test
    gen = ReportGenerator("example.com", "output/test")
    gen.set_subdomains(["api.example.com", "dev.example.com", "staging.example.com"])
    gen.set_live_hosts([
        {"url": "https://api.example.com", "status": 200, "title": "API", "technologies": ["nginx"], "waf": "", "response_time_ms": 120},
    ])
    gen.add_phase("Subdomain Enumeration", "12.3s", 3)
    gen.add_phase("Live Probing", "5.1s", 1)
    gen.generate()
