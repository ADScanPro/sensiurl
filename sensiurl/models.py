from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict
from urllib.parse import urljoin, urlsplit, urlunsplit


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Category(str, Enum):
    VCS = "VCS"
    CONFIG = "CONFIG"
    SECRETS = "SECRETS"
    DUMPS = "DUMPS"
    LOGS = "LOGS"
    ARCHIVES = "ARCHIVES"
    DOCUMENTS = "DOCUMENTS"
    TEMP = "TEMP"
    DIRECTORY = "DIRECTORY"
    DEBUG = "DEBUG"
    OTHER = "OTHER"


@dataclass(frozen=True)
class Candidate:
    base_url: str
    path: str
    category: Category
    description: str
    severity_hint: Severity
    method: str = "auto"  # auto | head | get
    is_directory: bool = False
    is_full_url: bool = False

    @property
    def url(self) -> str:
        # In exact mode, the base_url already contains the full URL (including path/query)
        if self.is_full_url:
            return self.base_url
        base = self.base_url.rstrip("/") + "/"
        # Ensure path has no leading double slashes
        path = self.path.lstrip("/")
        return urljoin(base, path)

    @property
    def origin(self) -> str:
        sp = urlsplit(self.base_url)
        return urlunsplit((sp.scheme or "http", sp.netloc, "", "", ""))


@dataclass
class FetchResult:
    url: str
    final_url: Optional[str]
    status_code: Optional[int]
    headers: Dict[str, str]
    content_snippet: Optional[bytes]
    content_type: Optional[str]
    content_length: Optional[int]
    error: Optional[str]


@dataclass
class Finding:
    candidate: Candidate
    url: str
    final_url: Optional[str]
    status_code: Optional[int]
    content_type: Optional[str]
    content_length: Optional[int]
    severity: Severity
    reason: str
    evidence: Optional[str]  # small text snippet

    @property
    def category(self) -> Category:
        return self.candidate.category
