from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List
from urllib.parse import urlsplit, urlunsplit

from rich.console import Console

from .reporter import print_results
from .scanner import run_scan


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
    parser.add_argument("--tui", action="store_true", help="Launch Textual TUI instead of Rich CLI")

    args = parser.parse_args(argv)

    input_path = Path(args.input)
    if not input_path.exists():
        Console().print(f"[red]Input file not found:[/red] {input_path}")
        return 1

    targets = load_targets(input_path, mode=args.mode)
    if not targets:
        Console().print("[yellow]No valid targets found in input file.[/yellow]")
        return 1

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
