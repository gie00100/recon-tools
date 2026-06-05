#!/usr/bin/env python3
"""
Module 6: Smart URL Deduplication
Inspired by Nishantbhagat57's uniqueurls tool.

Intelligent URL deduplication using path similarity analysis.
Not just exact string matching — compares path structure and parameter patterns.
"""

import argparse
import re
import sys
from collections import defaultdict
from difflib import SequenceMatcher
from pathlib import Path
from typing import List, Set
from urllib.parse import urlparse, parse_qs, urlencode

# Maximum URLs to process in memory — prevents OOM on 512MB VPS
MAX_URLS = 500_000

# Pre-compiled regexes for path signature (avoid recompiling per URL)
_RE_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
_RE_NUMERIC_ID = re.compile(r"/\d+(/|$)")
_RE_HEX_HASH = re.compile(r"/[0-9a-f]{16,}(/|$)", re.IGNORECASE)

sys.path.insert(0, str(Path(__file__).parent.parent))
from recon.utils import (
    banner, log_info, log_success, log_warning,
    read_lines, write_lines, console, RICH_AVAILABLE
)


class URLDeduplicator:
    """Smart URL deduplication using path similarity analysis."""

    def __init__(self, threshold: float = 0.7, keep_params: bool = True):
        """
        Args:
            threshold: Similarity threshold (0.0 - 1.0). URLs above this
                       threshold are considered duplicates. Default 0.7.
            keep_params: If True, keep one representative URL per unique
                         parameter set even if paths are similar.
        """
        self.threshold = threshold
        self.keep_params = keep_params

    def _normalize_url(self, url: str) -> str:
        """Normalize a URL for comparison."""
        url = url.strip().rstrip("/")
        # Ensure scheme
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url

    def _get_path_signature(self, url: str) -> str:
        """
        Create a structural signature of a URL path.
        Replaces numeric/uuid segments with placeholders to group similar paths.
        """
        parsed = urlparse(url)
        path = parsed.path

        # Replace UUIDs
        path = _RE_UUID.sub("{UUID}", path)
        # Replace numeric IDs
        path = _RE_NUMERIC_ID.sub("/{ID}\\1", path)
        # Replace hex hashes
        path = _RE_HEX_HASH.sub("/{HASH}\\1", path)

        return path

    def _get_param_keys(self, url: str) -> frozenset:
        """Get the set of query parameter keys."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return frozenset(params.keys())

    def _path_similarity(self, path1: str, path2: str) -> float:
        """Calculate similarity between two URL paths."""
        # Split paths into segments
        segs1 = [s for s in path1.split("/") if s]
        segs2 = [s for s in path2.split("/") if s]

        if not segs1 and not segs2:
            return 1.0
        if not segs1 or not segs2:
            return 0.0

        # Use SequenceMatcher for segment-level comparison
        return SequenceMatcher(None, segs1, segs2).ratio()

    def deduplicate(self, urls: List[str]) -> List[str]:
        """
        Deduplicate URLs using path similarity analysis.

        Strategy:
        1. Group URLs by host
        2. Within each host, group by path signature
        3. Within similar paths, keep one per unique param set
        """
        banner("Smart URL Deduplicator")
        log_info(f"Input URLs: {len(urls)}")

        # [MEMORY SAFEGUARD] Cap input URLs to prevent OOM on low-memory VPS
        if len(urls) > MAX_URLS:
            log_warning(f"URL count ({len(urls)}) exceeds MAX_URLS ({MAX_URLS}). Sampling to fit in memory.")
            # Keep a diverse sample: first 100K + evenly spaced remainder
            step = len(urls) // MAX_URLS
            urls = urls[:100_000] + urls[100_000::step][:MAX_URLS - 100_000]
            log_info(f"Sampled down to {len(urls)} URLs")

        # Normalize all URLs
        normalized = [self._normalize_url(u) for u in urls if u.strip()]

        # Remove exact duplicates first
        unique_exact = list(dict.fromkeys(normalized))
        # Free memory from normalized list immediately
        del normalized
        log_info(f"After exact dedup: {len(unique_exact)}")

        # Group by host
        host_groups = defaultdict(list)
        for url in unique_exact:
            try:
                parsed = urlparse(url)
                host = parsed.netloc
                host_groups[host].append(url)
            except ValueError:
                # Catch malformed IPv6 bracket formats like '@@unscopables'
                continue

        # Deduplicate within each host
        kept = []
        for host, host_urls in host_groups.items():
            # Group by path signature
            sig_groups = defaultdict(list)
            for url in host_urls:
                sig = self._get_path_signature(url)
                sig_groups[sig].append(url)

            for sig, sig_urls in sig_groups.items():
                if self.keep_params:
                    # Keep one URL per unique parameter key set
                    param_seen = {}
                    for url in sig_urls:
                        param_keys = self._get_param_keys(url)
                        if param_keys not in param_seen:
                            param_seen[param_keys] = url
                    kept.extend(param_seen.values())
                else:
                    # Just keep one representative URL per signature
                    kept.append(sig_urls[0])

        # Second pass: fuzzy dedup across signatures within same host
        # [HIGH-SCALE SAFEGUARD] Skip slow SequenceMatcher O(N^2) comparisons if URL volume is high
        if len(kept) > 1000:
            log_warning(f"High URL volume ({len(kept)}). Bypassing slow SequenceMatcher fuzzy pass to prevent OOM/lockup.")
            final = kept
        else:
            final = []
            host_final = defaultdict(list)

            for url in kept:
                parsed = urlparse(url)
                host = parsed.netloc
                path = parsed.path

                is_dup = False
                for existing_url in host_final[host]:
                    existing_path = urlparse(existing_url).path
                    sim = self._path_similarity(path, existing_path)
                    if sim >= self.threshold:
                        # Check if params make it unique
                        if self.keep_params:
                            if self._get_param_keys(url) != self._get_param_keys(existing_url):
                                continue  # Different params = keep both
                        is_dup = True
                        break

                if not is_dup:
                    host_final[host].append(url)
                    final.append(url)

        final.sort()
        reduction = len(urls) - len(final)
        pct = (reduction / len(urls) * 100) if urls else 0

        log_success(f"After smart dedup: {len(final)} (removed {reduction}, {pct:.1f}% reduction)")

        return final


# ── CLI Entry Point ──────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Smart URL Deduplication (inspired by uniqueurls)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python url_dedup.py -i urls.txt -o unique.txt
  python url_dedup.py -i urls.txt -t 0.8
  cat urls.txt | python url_dedup.py -
  python url_dedup.py -i urls.txt --no-params
        """
    )
    parser.add_argument("input_file", nargs="?", help="Input file with URLs (- for stdin)")
    parser.add_argument("-i", "--input", help="Alternative: input file path")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-t", "--threshold", type=float, default=0.7,
                        help="Similarity threshold 0.0-1.0 (default: 0.7)")
    parser.add_argument("--no-params", action="store_true",
                        help="Don't preserve URLs with unique parameter sets")

    args = parser.parse_args()

    # Read input
    input_file = args.input_file or args.input
    if input_file == "-":
        urls = [line.strip() for line in sys.stdin if line.strip()]
    elif input_file:
        urls = read_lines(input_file)
    else:
        parser.error("Provide input via file or stdin (-)")

    deduplicator = URLDeduplicator(
        threshold=args.threshold,
        keep_params=not args.no_params,
    )
    results = deduplicator.deduplicate(urls)

    if args.output:
        write_lines(args.output, results, deduplicate=False)
    else:
        for url in results:
            print(url)


if __name__ == "__main__":
    main()
