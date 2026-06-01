#!/usr/bin/env python3
"""
Module: Infrastructure Port Scanner
Asynchronously scans IPs for exposed sensitive infrastructure ports.
"""

import argparse
import asyncio
import json
import socket
import sys
import time
import re
from pathlib import Path
from typing import Dict, List, Set

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.utils import log_info, log_success, log_warning, log_error, banner, elapsed_str, RICH_AVAILABLE

if RICH_AVAILABLE:
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
    from rich.console import Console
    console = Console()
else:
    console = None

HIGH_VALUE_PORTS = {
    9090: "Prometheus",
    9200: "Elasticsearch",
    2375: "Docker API (Unauthenticated)",
    6379: "Redis",
    27017: "MongoDB",
    11211: "Memcached",
    8500: "Consul",
    5601: "Kibana",
    8080: "Tomcat / Web",
    8443: "Tomcat / Web SSL",
    8888: "Jupyter Notebook",
    5432: "PostgreSQL",
    3306: "MySQL"
}

class PortScanner:
    def __init__(self, ips: List[str], concurrency: int = 150, timeout: int = 2):
        self.ips = list(set(ips))  # deduplicate
        self.concurrency = concurrency
        self.timeout = timeout
        self.results = []

    async def _check_port(self, ip: str, port: int, sem: asyncio.Semaphore):
        async with sem:
            try:
                # Use asyncio.open_connection to check if port is open
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                
                # Check for basic HTTP title if it's a web-based service
                http_title = ""
                if port in [9090, 9200, 5601, 8500, 8080, 8443, 8888]:
                    http_title = await self._grab_http_title(ip, port)
                
                service = HIGH_VALUE_PORTS.get(port, "Unknown")
                result = {
                    "ip": ip,
                    "port": port,
                    "service": service,
                    "title": http_title
                }
                self.results.append(result)
                return result
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            except Exception:
                return None

    async def _grab_http_title(self, ip: str, port: int) -> str:
        """Attempt a simple HTTP GET to grab the title/server header."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            
            resp_str = response.decode(errors="ignore")
            # Extract title
            match = re.search(r"<title[^>]*>(.*?)</title>", resp_str, re.IGNORECASE)
            if match:
                return match.group(1).strip()
                
            # If no title, maybe return the Server header or HTTP status
            lines = resp_str.split('\r\n')
            if lines:
                return lines[0]
            return ""
        except Exception:
            return ""

    async def scan(self) -> List[Dict]:
        start = time.time()
        banner("Infrastructure Port Scanner")
        total_checks = len(self.ips) * len(HIGH_VALUE_PORTS)
        log_info(f"Scanning {len(self.ips)} IPs across {len(HIGH_VALUE_PORTS)} sensitive ports (Total: {total_checks} checks)...")
        
        sem = asyncio.Semaphore(self.concurrency)
        tasks = []
        
        for ip in self.ips:
            for port in HIGH_VALUE_PORTS.keys():
                tasks.append(self._check_port(ip, port, sem))
                
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
            ) as progress:
                task_id = progress.add_task("[cyan]Scanning Ports...", total=len(tasks))
                for coro in asyncio.as_completed(tasks):
                    await coro
                    progress.advance(task_id)
        else:
            await asyncio.gather(*tasks)

        log_success(f"Port scan completed in {elapsed_str(start)}")
        log_success(f"Found {len(self.results)} exposed sensitive services!")
        
        return self.results

def resolve_hostnames(hostnames: List[str]) -> List[str]:
    """Helper to resolve hostnames to IPs synchronously."""
    ips = set()
    for host in hostnames:
        try:
            ip = socket.gethostbyname(host)
            ips.add(ip)
        except Exception:
            pass
    return list(ips)
