from __future__ import annotations

from typing import Iterable, List

from .models import Candidate, Category, Severity


def generate_candidates(base_url: str, mode: str = "standard") -> List[Candidate]:
    """Generate candidate sensitive paths for a given base URL.

    mode: "fast" | "standard" | "extended"
    """
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
