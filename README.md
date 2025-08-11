# SensiURL - Sensitive URL Scanner

SensiURL is a modular Python tool to scan base URLs for exposed sensitive files and directories (e.g., .git, .svn, .env, backups, dumps, logs). It provides elegant, structured output using Rich (CLI) and an optional Textual TUI.

## Features
- Detects common exposures: VCS folders, backups, archives, database dumps, logs, temp files, secrets, and debug endpoints.
- Asynchronous scanning with concurrency control.
- HEAD then ranged GET sampling to avoid downloading large files.
- Rich CLI output with severity coloring and table summaries.
- Optional Textual TUI (`--tui`) to visualize results.
- Designed to be used as a script or imported as a library.

## Installation
Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
Prepare a file `targets.txt` with one base URL per line, e.g.:
```
https://example.com
http://test.local
```
Comments starting with `#` and blank lines are ignored.

Run the scanner (Rich CLI):
```bash
python -m sensiurl --input targets.txt
```

Run with Textual TUI:
```bash
python -m sensiurl --input targets.txt --tui
```

Common options:
- `--mode {fast,standard,extended}`: candidate coverage (default: standard)
- `--concurrency 50`: number of concurrent requests
- `--timeout 10`: per-request timeout seconds
- `--retries 1`: retry attempts per request
- `--insecure`: disable TLS verification
- `--no-follow-redirects`: do not follow redirects
- `--json-output results.json`: write findings as JSON

## Library Use
```python
from sensiurl.scanner import run_scan
results = run_scan(["https://example.com"], mode="standard")
for finding in results:
    print(finding.severity, finding.url, finding.reason)
```

## Notes
- Keep all code and outputs in English.
- Intended for authorized security testing and auditing only.
- Use responsibly and comply with the target's policies and laws.
