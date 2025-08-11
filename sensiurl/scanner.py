from __future__ import annotations

import asyncio
from typing import Callable, Iterable, List, Optional

import httpx

from .candidates import generate_candidates
from .detectors import analyze
from .models import Candidate, Finding, Severity


class _RateLimiter:
    def __init__(self, concurrency: int):
        self._sem = asyncio.Semaphore(concurrency)

    async def __aenter__(self):
        await self._sem.acquire()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self._sem.release()


async def scan_async(
    base_urls: List[str],
    mode: str = "standard",
    concurrency: int = 50,
    timeout: float = 10.0,
    retries: int = 1,
    follow_redirects: bool = True,
    insecure: bool = False,
    user_agent: str = "SensiURL/0.1 (+https://github.com/)",
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> List[Finding]:
    """Scan base URLs asynchronously and return findings.

    progress_cb: optional callback invoked with (completed, total)
    """
    from .fetcher import fetch_candidate

    candidates: List[Candidate] = []
    for base in base_urls:
        candidates.extend(generate_candidates(base, mode=mode))

    total = len(candidates)
    completed = 0

    findings: List[Finding] = []
    limiter = _RateLimiter(concurrency)

    headers = {"User-Agent": user_agent}

    async with httpx.AsyncClient(
        follow_redirects=follow_redirects,
        verify=not insecure,
        headers=headers,
    ) as client:
        async def worker(cand: Candidate):
            nonlocal completed
            attempts = 0
            res = None
            while attempts <= retries:
                try:
                    res = await fetch_candidate(cand, client, timeout=timeout)
                    break
                except Exception:
                    attempts += 1
                    if attempts > retries:
                        break
                    await asyncio.sleep(0.2 * attempts)
            if res is not None:
                finding = analyze(cand, res)
                if finding:
                    findings.append(finding)
            completed += 1
            if progress_cb:
                progress_cb(completed, total)

        tasks = []
        for cand in candidates:
            tasks.append(asyncio.create_task(_guarded(worker, cand, limiter)))
        if tasks:
            await asyncio.gather(*tasks)

    # Sort findings by severity descending
    sev_order = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1}
    findings.sort(key=lambda f: (sev_order.get(f.severity, 0), str(f.category), f.url), reverse=True)
    return findings


async def _guarded(fn, cand: Candidate, limiter: _RateLimiter):
    async with limiter:
        await fn(cand)


def run_scan(
    base_urls: List[str],
    mode: str = "standard",
    concurrency: int = 50,
    timeout: float = 10.0,
    retries: int = 1,
    follow_redirects: bool = True,
    insecure: bool = False,
    user_agent: str = "SensiURL/0.1 (+https://github.com/)",
) -> List[Finding]:
    """Synchronous wrapper to run the async scanner."""
    return asyncio.run(
        scan_async(
            base_urls,
            mode=mode,
            concurrency=concurrency,
            timeout=timeout,
            retries=retries,
            follow_redirects=follow_redirects,
            insecure=insecure,
            user_agent=user_agent,
        )
    )
