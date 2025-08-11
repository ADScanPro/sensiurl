from __future__ import annotations

import re
from typing import Optional

from .models import Candidate, Category, Finding, FetchResult, Severity


def analyze(candidate: Candidate, res: FetchResult) -> Optional[Finding]:
    """Analyze a FetchResult and decide if it is a sensitive exposure.

    Returns a Finding or None.
    """
    status = res.status_code or 0
    snippet_text = _safe_decode(res.content_snippet)
    ct = (res.content_type or "").lower()

    # 404 or network error: not interesting
    if status == 0 or status == 404:
        return None

    # Directory listing heuristic
    if candidate.is_directory:
        if status in (200, 206):
            if _looks_like_directory_listing(snippet_text):
                return _mk(
                    candidate,
                    res,
                    severity=max(candidate.severity_hint, Severity.HIGH, key=_sev_key),
                    reason="Directory listing enabled",
                    evidence=_cap(snippet_text),
                )
        # 401/403 for directory can still indicate presence
        if status in (401, 403):
            return _mk(
                candidate,
                res,
                severity=max(candidate.severity_hint, Severity.MEDIUM, key=_sev_key),
                reason=f"Directory exists but access is {status}",
                evidence=None,
            )

    # VCS specific
    if candidate.category == Category.VCS:
        if ".git/HEAD" in candidate.path and "ref: refs/heads/" in snippet_text:
            return _mk(candidate, res, Severity.CRITICAL, "Exposed .git HEAD", _cap(snippet_text))
        if ".git/config" in candidate.path and "[core]" in snippet_text and "repositoryformatversion" in snippet_text:
            return _mk(candidate, res, Severity.CRITICAL, "Exposed .git config", _cap(snippet_text))
        if ".git/index" in candidate.path and status in (200, 206):
            return _mk(candidate, res, Severity.CRITICAL, "Exposed .git index", None)
        if ".svn/" in candidate.path and ("SQLite format 3" in snippet_text or "dir" in snippet_text):
            return _mk(candidate, res, Severity.HIGH, "Exposed .svn metadata", _cap(snippet_text))
        if ".hg/" in candidate.path and status in (200, 206):
            return _mk(candidate, res, Severity.HIGH, "Exposed Mercurial metadata", None)

    # Secrets / keys
    if candidate.category == Category.SECRETS:
        if _looks_like_env(snippet_text):
            return _mk(candidate, res, Severity.CRITICAL, ".env with secrets", _cap(snippet_text))
        if _looks_like_private_key(snippet_text):
            return _mk(candidate, res, Severity.CRITICAL, "Private key exposed", _cap(snippet_text))
        if ".htpasswd" in candidate.path and ":" in snippet_text:
            return _mk(candidate, res, Severity.HIGH, ".htpasswd exposed", _cap(snippet_text))

    # Config
    if candidate.category == Category.CONFIG:
        if "wp-config.php" in candidate.path:
            if "define('DB_NAME'" in snippet_text or "DB_PASSWORD" in snippet_text:
                return _mk(candidate, res, Severity.CRITICAL, "wp-config contents exposed", _cap(snippet_text))
            # Even if not readable, 200 on wp-config.php is unusual
            if status in (200, 206) and "<?php" in snippet_text:
                return _mk(candidate, res, Severity.HIGH, "wp-config readable", _cap(snippet_text))
        if candidate.path.endswith(('.bak', '.old', '.orig', '~')) and status in (200, 206):
            return _mk(candidate, res, Severity.HIGH, "Backup of config exposed", _cap(snippet_text))

    # Dumps
    if candidate.category == Category.DUMPS:
        if _looks_like_sql(snippet_text) or ct.startswith("application/zip") or "application/x-gzip" in ct or "application/gzip" in ct:
            return _mk(candidate, res, Severity.CRITICAL, "Database dump or archive exposed", _cap(snippet_text))
        if "SQLite format 3" in snippet_text:
            return _mk(candidate, res, Severity.CRITICAL, "SQLite database exposed", _cap(snippet_text))

    # Logs
    if candidate.category == Category.LOGS:
        if _looks_like_log(snippet_text):
            return _mk(candidate, res, Severity.MEDIUM, "Log file exposed", _cap(snippet_text))

    # Archives
    if candidate.category == Category.ARCHIVES:
        if any(x in ct for x in ("zip", "x-7z-compressed", "x-tar", "x-gzip")) or status == 206:
            return _mk(candidate, res, Severity.HIGH, "Archive available", None)

    # Debug endpoints
    if candidate.category == Category.DEBUG:
        if "phpinfo()" in snippet_text or "PHP Version" in snippet_text:
            return _mk(candidate, res, Severity.HIGH, "phpinfo exposed", None)

    # Heuristic: 403 on very sensitive paths -> noteworthy
    if status in (401, 403) and candidate.severity_hint in (Severity.CRITICAL, Severity.HIGH):
        return _mk(
            candidate,
            res,
            severity=max(candidate.severity_hint, Severity.MEDIUM, key=_sev_key),
            reason=f"{status} on sensitive path (likely exists)",
            evidence=None,
        )

    return None


def _mk(candidate: Candidate, res: FetchResult, severity: Severity, reason: str, evidence: Optional[str]) -> Finding:
    return Finding(
        candidate=candidate,
        url=res.url,
        final_url=res.final_url,
        status_code=res.status_code,
        content_type=res.content_type,
        content_length=res.content_length,
        severity=severity,
        reason=reason,
        evidence=evidence,
    )


def _cap(text: Optional[str], n: int = 200) -> Optional[str]:
    if not text:
        return None
    text = text.strip()
    return text[:n] + ("…" if len(text) > n else "")


def _sev_key(s: Severity) -> int:
    order = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
    return order[s]


def _safe_decode(b: Optional[bytes]) -> str:
    if b is None:
        return ""
    for enc in ("utf-8", "latin-1", "utf-16"):
        try:
            return b.decode(enc, errors="ignore")
        except Exception:
            continue
    return ""


def _looks_like_directory_listing(text: str) -> bool:
    markers = [
        "Index of /", "Directory listing for", "<title>Index of", "<h1>Index of",
    ]
    return any(m in text for m in markers)


def _looks_like_env(text: str) -> bool:
    keys = [
        "DATABASE_URL=", "DB_PASSWORD=", "SECRET_KEY=", "JWT_SECRET", "AWS_SECRET_ACCESS_KEY=",
        "AWS_ACCESS_KEY_ID=", "MAIL_PASSWORD=", "REDIS_URL=", "API_KEY=", "TOKEN=",
    ]
    return any(k in text for k in keys)


def _looks_like_private_key(text: str) -> bool:
    return (
        "BEGIN RSA PRIVATE KEY" in text
        or "BEGIN OPENSSH PRIVATE KEY" in text
        or "BEGIN DSA PRIVATE KEY" in text
        or "BEGIN EC PRIVATE KEY" in text
    )


def _looks_like_sql(text: str) -> bool:
    return (
        "-- MySQL dump" in text
        or "-- PostgreSQL database dump" in text
        or "SQLite format 3" in text
        or bool(re.search(r"CREATE TABLE\s+", text))
    )


def _looks_like_log(text: str) -> bool:
    patterns = [
        r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}",  # timestamps
        r"\[(error|warn|info|debug)\]",
        r"HTTP\/1\.[01]\"\s\d{3}",
    ]
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)
