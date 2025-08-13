from __future__ import annotations

import argparse
import json
import sys
import logging
from pathlib import Path
from typing import Dict, List
from collections import Counter
from urllib.parse import urlsplit, urlunsplit

from rich.console import Console
from rich.table import Table
from rich.logging import RichHandler

from .reporter import print_results
from .scanner import run_scan
from .models import Category
from .candidates import generate_candidates


def normalize_url(u: str, *, keep_query: bool = False, keep_fragment: bool = False) -> str:
    u = u.strip()
    if not u or u.startswith("#"):
        return ""
    sp = urlsplit(u)
    if not sp.scheme:
        # default to http
        sp = sp._replace(scheme="http")
    if not sp.netloc and sp.path:
        # user might have provided domain only
        return f"http://{sp.path}"
    # Preserve or strip query/fragment depending on flags
    if not keep_query:
        sp = sp._replace(query="")
    if not keep_fragment:
        sp = sp._replace(fragment="")
    return urlunsplit(sp)


def load_targets(path: Path, *, mode: str) -> List[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    exact = mode == "exact"
    urls = [
        normalize_url(
            l,
            keep_query=exact,  # In exact mode we keep query
            keep_fragment=False,  # Fragment is never sent to server; keep for display isn't useful
        )
        for l in lines
    ]
    return [u for u in urls if u]


def _extract_extension_label(url: str) -> str:
    """Extract a human-readable extension label from a URL path.

    Rules:
    - Compound extensions like .tar.gz and .sql.gz are preserved.
    - Dot-directories or dot-files like /.git/ or /.env are labeled as '.git' or '.env'.
    - If no extension exists, returns 'none'.
    """
    sp = urlsplit(url)
    path = sp.path or ""
    if not path or path.endswith("/"):
        # Directory path; try to detect dot-directory
        parts = [p for p in path.split('/') if p]
        if parts and parts[-1].startswith('.'):
            return parts[-1]
        return "none"
    # File path
    name = path.rsplit('/', 1)[-1]
    # Dot-file without further extension
    if name.startswith('.') and name.count('.') == 1:
        return name
    # Compound extensions
    lower = name.lower()
    for comp in ('.tar.gz', '.tar.bz2', '.sql.gz', '.tgz'):
        if lower.endswith(comp):
            return comp.lstrip('.')
    # Regular extension
    if '.' in name:
        return name.rsplit('.', 1)[-1].lower()
    return "none"


def _summarize_extensions(urls: List[str]) -> Dict[str, int]:
    counts: Counter[str] = Counter()
    for u in urls:
        ext = _extract_extension_label(u)
        counts[ext] += 1
    # Sort by count desc then name asc
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def _print_extensions_summary(ext_counts: Dict[str, int]) -> None:
    if not ext_counts:
        return
    console = Console()
    table = Table(title="Extensions overview", expand=False)
    table.add_column("Extension", no_wrap=True)
    table.add_column("Count", justify="right")
    for ext, cnt in ext_counts.items():
        table.add_row(ext, str(cnt))
    console.print(table)


def _print_precandidates(urls: List[str]) -> None:
    # Classify provided URLs (exact mode) and show those that look sensitive by path
    cands = []
    for u in urls:
        cands.extend(generate_candidates(u, mode="exact"))
    cands = [c for c in cands if c.category != Category.OTHER]
    console = Console()
    if not cands:
        console.print("[green]No sensitive-looking URLs detected in input.[/green]")
        return
    # Summary by category
    by_cat: Dict[str, int] = {}
    for c in cands:
        by_cat[c.category.value] = by_cat.get(c.category.value, 0) + 1
    table = Table(title="Sensitive-looking URLs (by category)", expand=False)
    table.add_column("Category", no_wrap=True)
    table.add_column("Count", justify="right")
    for cat, cnt in sorted(by_cat.items(), key=lambda kv: (-kv[1], kv[0])):
        table.add_row(cat, str(cnt))
    console.print(table)
    # List URLs
    list_table = Table(title="Sensitive-looking URLs", expand=True)
    list_table.add_column("Category", no_wrap=True)
    list_table.add_column("URL")
    for c in cands:
        list_table.add_row(c.category.value, c.url)
    console.print(list_table)


def _configure_logging(debug: bool, verbose: bool) -> None:
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=debug, markup=True, show_time=False, show_path=False)],
    )


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sensiurl",
        description="Scan URLs for exposed sensitive files and directories. Use --mode exact to scan URLs as-is (default).",
    )
    parser.add_argument("--input", required=True, help="Path to file with base URLs (one per line)")
    parser.add_argument("--mode", choices=["fast", "standard", "extended", "exact"], default="exact")
    parser.add_argument("--concurrency", type=int, default=50)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    parser.add_argument("--no-follow-redirects", action="store_true")
    parser.add_argument("--user-agent", default="SensiURL/0.1 (+https://github.com/)")
    parser.add_argument("--json-output", help="Write findings as JSON to the given path")
    parser.add_argument("--rate-limit", type=float, default=None, help="Max requests per second (RPS)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--tui", action="store_true", help="Launch Textual TUI instead of Rich CLI")

    args = parser.parse_args(argv)

    _configure_logging(args.debug, args.verbose)
    input_path = Path(args.input)
    if not input_path.exists():
        Console().print(f"[red]Input file not found:[/red] {input_path}")
        return 1

    targets = load_targets(input_path, mode=args.mode)
    if not targets:
        Console().print("[yellow]No valid targets found in input file.[/yellow]")
        return 1

    # Pre-scan: show extensions overview (mainly useful in exact mode)
    if args.mode == "exact":
        _print_extensions_summary(_summarize_extensions(targets))
        _print_precandidates(targets)

    if args.tui:
        from .tui import SensitiveScannerApp

        app = SensitiveScannerApp(
            targets,
            mode=args.mode,
            concurrency=args.concurrency,
            timeout=args.timeout,
            retries=args.retries,
            follow_redirects=not args.no_follow_redirects,
            insecure=args.insecure,
            user_agent=args.user_agent,
            rate_limit=args.rate_limit,
        )
        app.run()
        return 0

    # Rich CLI path
    findings = run_scan(
        targets,
        mode=args.mode,
        concurrency=args.concurrency,
        timeout=args.timeout,
        retries=args.retries,
        follow_redirects=not args.no_follow_redirects,
        insecure=args.insecure,
        user_agent=args.user_agent,
        rate_limit=args.rate_limit,
    )

    from .candidates import generate_candidates
    total_candidates = sum(len(generate_candidates(t, mode=args.mode)) for t in targets)
    print_results(findings, base_count=len(targets), total_candidates=total_candidates)

    if args.json_output:
        out_path = Path(args.json_output)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(
                [
                    {
                        "url": x.url,
                        "category": x.category.value,
                        "severity": x.severity.value,
                        "status_code": x.status_code,
                        "content_type": x.content_type,
                        "content_length": x.content_length,
                        "reason": x.reason,
                        "evidence": x.evidence,
                    }
                    for x in findings
                ],
                f,
                indent=2,
                ensure_ascii=False,
            )
        Console().print(f"[green]JSON results written to[/green] {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
