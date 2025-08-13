from __future__ import annotations

import asyncio
from typing import List, Optional

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, Label, LoadingIndicator, Static

from .scanner import scan_async
from .models import Finding


class SensitiveScannerApp(App):
    CSS = """
    Screen {
        align: center middle;
    }
    # Minimal styling for clarity
    # DataTable will expand
    """

    def __init__(
        self,
        base_urls: List[str],
        mode: str = "standard",
        concurrency: int = 50,
        timeout: float = 10.0,
        retries: int = 1,
        follow_redirects: bool = True,
        insecure: bool = False,
        user_agent: str = "SensiURL/0.1",
        rate_limit: Optional[float] = None,
    ) -> None:
        super().__init__()
        self.base_urls = base_urls
        self.mode = mode
        self.concurrency = concurrency
        self.timeout = timeout
        self.retries = retries
        self.follow_redirects = follow_redirects
        self.insecure = insecure
        self.user_agent = user_agent
        self.rate_limit = rate_limit
        self.progress_label = Label("Preparing scan…")
        self.table = DataTable(zebra_stripes=True)
        self.spinner = LoadingIndicator()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Vertical(
            Label("SensiURL - Sensitive URL Scanner", id="title"),
            self.progress_label,
            self.spinner,
            self.table,
        )
        yield Footer()

    async def on_mount(self) -> None:
        self.table.add_columns("Severity", "Category", "Status", "URL", "Reason")
        self.spinner.display = True
        await self.run_scan()
        self.spinner.display = False

    async def run_scan(self) -> None:
        total = 0

        def on_progress(done: int, tot: int) -> None:
            self.call_from_thread(self._update_progress, done, tot)

        findings = await scan_async(
            self.base_urls,
            mode=self.mode,
            concurrency=self.concurrency,
            timeout=self.timeout,
            retries=self.retries,
            follow_redirects=self.follow_redirects,
            insecure=self.insecure,
            user_agent=self.user_agent,
            rate_limit=self.rate_limit,
            progress_cb=on_progress,
        )
        self._populate_table(findings)

    def _update_progress(self, done: int, tot: int) -> None:
        self.progress_label.update(f"Scanning candidates: {done}/{tot}")

    def _populate_table(self, findings: List[Finding]) -> None:
        for f in findings:
            self.table.add_row(str(f.severity), str(f.category), str(f.status_code or ""), f.url, f.reason)
