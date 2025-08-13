# SensiURL - Sensitive URL Filter & Scanner (Exact URLs)

SensiURL focuses on one job: given a large list of URLs (from crawlers, logs, sitemaps, archives), quickly surface those that look potentially sensitive: exposed documents, backups/archives, database dumps, VCS directories, debug endpoints, or admin panels. It does not brute‑force or append paths — it only validates and analyzes the exact URLs you provide.

## What it does (exact‑only)
- Exact‑only: no path enumeration; the URL is scanned as‑is (query is preserved; fragment is ignored).
- Input hygiene: ignores comments/blank lines, normalizes missing schemes, and skips invalid entries with a warning that includes line numbers.
- Pre‑scan overview: extension histogram and a list of “sensitive‑looking URLs” by category based on the provided path.
- Targeted fetching: async HEAD followed by a small ranged GET sample to avoid large downloads, with concurrency and optional rate limiting.
- Clear output: Rich CLI tables with severity coloring and OSC‑8 clickable links; optional Textual TUI.
- Export: write findings to JSON for post‑processing.

## Installation
Install via pipx (recommended):

```bash
pipx install git+https://github.com/ADScanPro/sensiurl.git
```

Quick run after install:

```bash
sensiurl --input targets.txt
```

Install via pip from Git:

```bash
pip install git+https://github.com/ADScanPro/sensiurl.git
```

From source (dev):

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Alternatively, without installing the package:

```bash
pip install -r requirements.txt
python -m sensiurl --input targets.txt
```

## Usage
Prepare a file `targets.txt` with one URL per line, for example:
```
https://example.com/.env
https://example.com/wp-admin/
http://test.local/backups/site.zip
https://host.tld/report.pdf?id=123
```
Notes:
- Lines starting with `#` and blank lines are ignored.
- Scheme defaults to `http://` if missing; query is kept; fragment (`#...`) is dropped.
- Invalid URLs are skipped with a warning that includes their line number.

Run the scanner (Rich CLI):
```bash
sensiurl --input targets.txt
```

Useful options:
- `--concurrency 50` number of concurrent requests
- `--rate-limit 5` cap average RPS
- `--timeout 10` per‑request timeout in seconds
- `--retries 1` retry attempts per request
- `--user-agent "My UA"` custom User‑Agent (quote if it contains spaces)
- `--insecure` disable TLS verification
- `--no-follow-redirects` do not follow redirects
- `--json-output results.json` write findings as JSON
- `--tui` launch the Textual TUI instead of the Rich CLI

Example:
```bash
sensiurl --input targets.txt --concurrency 100 --rate-limit 5 --user-agent "MyScanner/1.0"
```

### Output
- Extensions overview table (quick sense of what’s in your list).
- “Sensitive‑looking URLs” by category (classified from the provided path).
- Findings table with severity, category, status, URL (clickable), reason, and short evidence.

Tip: For fully clickable multi‑line URLs, use a terminal that supports OSC‑8 hyperlinks (Kitty, iTerm2, WezTerm, GNOME Terminal, Windows Terminal). Under tmux, enable passthrough: `set -g allow-passthrough on`.

## Library Use
```python
from sensiurl.scanner import run_scan

# Exact‑only: pass the URLs you want to validate
results = run_scan([
    "https://example.com/.env",
    "https://example.com/backups/site.zip",
])

for finding in results:
    print(finding.severity, finding.url, finding.reason)
```

## Scope & limits
- Bring‑your‑own‑URLs: SensiURL does not crawl or enumerate; it filters and validates what you pass.
- Lightweight sampling: avoids downloading large contents unless necessary for detection.
- Legal & ethical use only, with authorization.

## Breaking changes (0.2.x)
- Exact‑only: all other modes removed; `--mode` CLI flag no longer exists.
- Candidate generation no longer appends paths; classification is based on the provided URL path.
