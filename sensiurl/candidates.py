from __future__ import annotations

from typing import Iterable, List, Tuple
from urllib.parse import urlsplit

from .models import Candidate, Category, Severity


def generate_candidates(base_url: str, mode: str = "standard") -> List[Candidate]:
    """Generate candidate sensitive paths for a given base URL.

    mode: "fast" | "standard" | "extended" | "exact"
    """
    # New exact mode: do NOT append any paths; treat provided URL as-is
    if mode == "exact":
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

    fast_only = mode == "fast"
    extended = mode == "extended"

    c: List[Candidate] = []

    # VCS exposures
    c += [
        Candidate(base_url, ".git/HEAD", Category.VCS, ".git HEAD", Severity.CRITICAL),
        Candidate(base_url, ".git/config", Category.VCS, ".git config", Severity.CRITICAL),
        Candidate(base_url, ".git/index", Category.VCS, ".git index", Severity.CRITICAL),
        Candidate(base_url, ".svn/entries", Category.VCS, ".svn entries", Severity.HIGH),
        Candidate(base_url, ".svn/wc.db", Category.VCS, ".svn wc.db", Severity.HIGH),
        Candidate(base_url, ".hg/dirstate", Category.VCS, ".hg dirstate", Severity.HIGH),
    ]

    # Secrets / keys
    c += [
        Candidate(base_url, ".env", Category.SECRETS, ".env file", Severity.CRITICAL),
        Candidate(base_url, ".env.local", Category.SECRETS, ".env.local file", Severity.HIGH),
        Candidate(base_url, ".git-credentials", Category.SECRETS, "git credentials", Severity.CRITICAL),
        Candidate(base_url, "id_rsa", Category.SECRETS, "SSH private key", Severity.CRITICAL),
        Candidate(base_url, ".ssh/id_rsa", Category.SECRETS, "SSH private key in .ssh", Severity.CRITICAL),
        Candidate(base_url, ".htpasswd", Category.SECRETS, ".htpasswd", Severity.HIGH),
    ]

    # Config
    c += [
        Candidate(base_url, "wp-config.php", Category.CONFIG, "WordPress config", Severity.CRITICAL),
        Candidate(base_url, "wp-config.php.bak", Category.CONFIG, "WordPress config backup", Severity.CRITICAL),
        Candidate(base_url, "config.php~", Category.CONFIG, "config.php tilde backup", Severity.HIGH),
        Candidate(base_url, "config.php.bak", Category.CONFIG, "config.php backup", Severity.HIGH),
        Candidate(base_url, "settings.py", Category.CONFIG, "Django settings", Severity.HIGH),
        Candidate(base_url, "local_settings.py", Category.CONFIG, "Django local settings", Severity.HIGH),
        Candidate(base_url, ".htaccess", Category.CONFIG, ".htaccess", Severity.MEDIUM),
    ]

    # Database dumps
    c += [
        Candidate(base_url, "dump.sql", Category.DUMPS, "SQL dump", Severity.CRITICAL),
        Candidate(base_url, "database.sql", Category.DUMPS, "SQL dump", Severity.CRITICAL),
        Candidate(base_url, "backup.sql", Category.DUMPS, "SQL dump", Severity.CRITICAL),
        Candidate(base_url, "dump.sql.gz", Category.DUMPS, "Compressed SQL dump", Severity.CRITICAL),
        Candidate(base_url, "db.sqlite", Category.DUMPS, "SQLite DB", Severity.CRITICAL),
        Candidate(base_url, "database.sqlite3", Category.DUMPS, "SQLite DB", Severity.CRITICAL),
    ]

    # Logs
    c += [
        Candidate(base_url, "access.log", Category.LOGS, "Access log", Severity.MEDIUM),
        Candidate(base_url, "error.log", Category.LOGS, "Error log", Severity.MEDIUM),
        Candidate(base_url, "debug.log", Category.LOGS, "Debug log", Severity.MEDIUM),
        Candidate(base_url, "laravel.log", Category.LOGS, "Laravel log", Severity.MEDIUM),
    ]

    # Archives and backups
    c += [
        Candidate(base_url, "backup.zip", Category.ARCHIVES, "ZIP backup", Severity.HIGH),
        Candidate(base_url, "backup.tar.gz", Category.ARCHIVES, "TGZ backup", Severity.HIGH),
        Candidate(base_url, "site.zip", Category.ARCHIVES, "Site ZIP", Severity.HIGH),
        Candidate(base_url, "source.zip", Category.ARCHIVES, "Source ZIP", Severity.HIGH),
        Candidate(base_url, "www.zip", Category.ARCHIVES, "www ZIP", Severity.HIGH),
    ]

    # Temporary / editor / misc
    c += [
        Candidate(base_url, ".DS_Store", Category.TEMP, "macOS DS_Store", Severity.LOW),
        Candidate(base_url, "Thumbs.db", Category.TEMP, "Windows Thumbs.db", Severity.LOW),
        Candidate(base_url, "index.php~", Category.TEMP, "tilde backup", Severity.MEDIUM),
        Candidate(base_url, "config.php.old", Category.TEMP, "old config", Severity.MEDIUM),
        Candidate(base_url, ".idea/workspace.xml", Category.TEMP, "IDE config", Severity.LOW),
        Candidate(base_url, ".vscode/settings.json", Category.TEMP, "IDE config", Severity.LOW),
    ]

    # Directory listings and debug endpoints
    c += [
        Candidate(base_url, ".git/", Category.DIRECTORY, ".git directory", Severity.CRITICAL, is_directory=True),
        Candidate(base_url, "backup/", Category.DIRECTORY, "backup directory", Severity.HIGH, is_directory=True),
        Candidate(base_url, "private/", Category.DIRECTORY, "private directory", Severity.HIGH, is_directory=True),
        Candidate(base_url, "logs/", Category.DIRECTORY, "logs directory", Severity.MEDIUM, is_directory=True),
        Candidate(base_url, "tmp/", Category.DIRECTORY, "tmp directory", Severity.LOW, is_directory=True),
        Candidate(base_url, "phpinfo.php", Category.DEBUG, "phpinfo", Severity.HIGH),
        Candidate(base_url, "info.php", Category.DEBUG, "phpinfo/info.php", Severity.HIGH),
    ]

    if fast_only:
        # Keep only the most impactful items for speed
        priority = {
            (".git/HEAD", Category.VCS),
            (".git/config", Category.VCS),
            (".env", Category.SECRETS),
            ("wp-config.php", Category.CONFIG),
            ("dump.sql", Category.DUMPS),
            ("database.sql", Category.DUMPS),
            ("backup.zip", Category.ARCHIVES),
            ("phpinfo.php", Category.DEBUG),
        }
        c = [x for x in c if (x.path, x.category) in priority]

    if extended:
        # Additional patterns for thorough scans
        c += [
            Candidate(base_url, "db.sql", Category.DUMPS, "SQL dump", Severity.CRITICAL),
            Candidate(base_url, "dump.tar.gz", Category.ARCHIVES, "dump TGZ", Severity.HIGH),
            Candidate(base_url, "backup.7z", Category.ARCHIVES, "7z backup", Severity.HIGH),
            Candidate(base_url, "config.old", Category.TEMP, "old config", Severity.MEDIUM),
            Candidate(base_url, ".bak", Category.TEMP, "file backup marker", Severity.MEDIUM),
            Candidate(base_url, ".orig", Category.TEMP, "file backup marker", Severity.MEDIUM),
        ]

    return c


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
