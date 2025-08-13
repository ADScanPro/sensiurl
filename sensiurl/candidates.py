from __future__ import annotations

from typing import Iterable, List, Tuple
from urllib.parse import urlsplit

from .models import Candidate, Category, Severity


def generate_candidates(base_url: str) -> List[Candidate]:
    """Generate a single candidate for the provided URL (exact-only mode).

    No paths are appended; the URL is treated as-is.
    """
    try:
        path = urlsplit(base_url).path or ""
    except ValueError:
        # Base URL not parseable (e.g., invalid bracketed host) -> skip
        return []
    category, severity, is_dir, desc = _classify_exact_path(path)
    return [
        Candidate(
            base_url=base_url,
            path=path,
            category=category,
            description=desc,
            severity_hint=severity,
            is_directory=is_dir,
            is_full_url=True,
        )
    ]


def _classify_exact_path(path: str) -> Tuple[Category, Severity, bool, str]:
    """Best-effort classification of a provided URL path for exact mode.

    Returns (category, severity, is_directory, description)
    """
    p = path or ""
    is_dir = p.endswith("/")

    # VCS
    if ".git/HEAD" in p:
        return Category.VCS, Severity.CRITICAL, False, ".git HEAD"
    if ".git/config" in p:
        return Category.VCS, Severity.CRITICAL, False, ".git config"
    if ".git/index" in p or p.endswith("/.git/") or p.endswith("/.git"):
        return Category.VCS, Severity.CRITICAL, is_dir, ".git"
    if ".svn" in p:
        return Category.VCS, Severity.HIGH, is_dir, ".svn"
    if ".hg" in p:
        return Category.VCS, Severity.HIGH, is_dir, ".hg"

    # Secrets / keys
    if p.endswith("/.env") or p.endswith("/.env.local") or p.endswith(".env"):
        return Category.SECRETS, Severity.CRITICAL, False, ".env file"
    if ".git-credentials" in p:
        return Category.SECRETS, Severity.CRITICAL, False, "git credentials"
    if p.endswith("/id_rsa") or p.endswith(".ssh/id_rsa") or p.endswith("id_rsa"):
        return Category.SECRETS, Severity.CRITICAL, False, "SSH private key"
    if p.endswith(".htpasswd"):
        return Category.SECRETS, Severity.HIGH, False, ".htpasswd"

    # Config
    if p.endswith("wp-config.php"):
        return Category.CONFIG, Severity.CRITICAL, False, "WordPress config"
    if p.endswith("wp-config.php.bak"):
        return Category.CONFIG, Severity.CRITICAL, False, "WordPress config backup"
    if p.endswith("config.php~"):
        return Category.CONFIG, Severity.HIGH, False, "config.php tilde backup"
    if p.endswith("config.php.bak"):
        return Category.CONFIG, Severity.HIGH, False, "config.php backup"
    if p.endswith("settings.py"):
        return Category.CONFIG, Severity.HIGH, False, "Django settings"
    if p.endswith("local_settings.py"):
        return Category.CONFIG, Severity.HIGH, False, "Django local settings"
    if p.endswith(".htaccess"):
        return Category.CONFIG, Severity.MEDIUM, False, ".htaccess"

    # Dumps
    if p.endswith("dump.sql") or p.endswith("database.sql") or p.endswith("backup.sql"):
        return Category.DUMPS, Severity.CRITICAL, False, "SQL dump"
    if p.endswith("dump.sql.gz"):
        return Category.DUMPS, Severity.CRITICAL, False, "Compressed SQL dump"
    if p.endswith("db.sqlite") or p.endswith("database.sqlite3"):
        return Category.DUMPS, Severity.CRITICAL, False, "SQLite DB"

    # Logs
    if p.endswith("access.log"):
        return Category.LOGS, Severity.MEDIUM, False, "Access log"
    if p.endswith("error.log"):
        return Category.LOGS, Severity.MEDIUM, False, "Error log"
    if p.endswith("debug.log") or p.endswith("laravel.log"):
        return Category.LOGS, Severity.MEDIUM, False, "Log file"

    # Archives
    if p.endswith("backup.zip") or p.endswith("site.zip") or p.endswith("source.zip") or p.endswith("www.zip"):
        return Category.ARCHIVES, Severity.HIGH, False, "ZIP archive"
    if p.endswith("backup.tar.gz"):
        return Category.ARCHIVES, Severity.HIGH, False, "TGZ archive"

    # Documents (potentially sensitive office/PDF files)
    doc_exts_high = (".pst",)  # Outlook mail stores
    doc_exts_medium = (
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".pdf", ".rtf", ".odt", ".ods", ".odp",
    )
    for ext in doc_exts_high:
        if p.lower().endswith(ext):
            return Category.DOCUMENTS, Severity.HIGH, False, f"Document ({ext.lstrip('.')})"
    for ext in doc_exts_medium:
        if p.lower().endswith(ext):
            return Category.DOCUMENTS, Severity.MEDIUM, False, f"Document ({ext.lstrip('.')})"

    # Temporary / misc
    if p.endswith(".DS_Store"):
        return Category.TEMP, Severity.LOW, False, "macOS DS_Store"
    if p.endswith("Thumbs.db"):
        return Category.TEMP, Severity.LOW, False, "Windows Thumbs.db"
    if p.endswith("index.php~"):
        return Category.TEMP, Severity.MEDIUM, False, "tilde backup"
    if p.endswith("config.php.old") or p.endswith("config.old"):
        return Category.TEMP, Severity.MEDIUM, False, "old config"
    if p.endswith(".idea/workspace.xml") or p.endswith(".vscode/settings.json"):
        return Category.TEMP, Severity.LOW, False, "IDE config"
    if p.endswith(".bak") or p.endswith(".orig"):
        return Category.TEMP, Severity.MEDIUM, False, "file backup marker"

    # Directory listings
    if is_dir and any(seg in p for seg in ("backup/", "private/", "logs/", "tmp/")):
        # Severity based on common sensitive directory name
        if "/backup/" in p:
            return Category.DIRECTORY, Severity.HIGH, True, "backup directory"
        if "/private/" in p:
            return Category.DIRECTORY, Severity.HIGH, True, "private directory"
        if "/logs/" in p:
            return Category.DIRECTORY, Severity.MEDIUM, True, "logs directory"
        if "/tmp/" in p:
            return Category.DIRECTORY, Severity.LOW, True, "tmp directory"

    # Debug endpoints
    if p.endswith("phpinfo.php") or p.endswith("info.php"):
        return Category.DEBUG, Severity.HIGH, False, "phpinfo"

    # Default fallback
    return Category.OTHER, Severity.MEDIUM, is_dir, (p.strip("/") or "Exact URL")
