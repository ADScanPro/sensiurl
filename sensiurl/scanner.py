from __future__ import annotations

import asyncio
import logging
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


class _RateGate:
    """Simple leaky-bucket style gate to cap requests per second.

    Ensures average rate <= rate_limit by spacing request starts by 1/rate seconds.
    """

    def __init__(self, rate_limit: Optional[float]):
        self._rate = rate_limit if (rate_limit is not None and rate_limit > 0) else None
        self._lock = asyncio.Lock()
        self._next_time = 0.0
        self._interval = (1.0 / self._rate) if self._rate else 0.0

    async def acquire(self) -> None:
        if not self._rate:
            return
        async with self._lock:
            now = asyncio.get_event_loop().time()
            if self._next_time <= now:
                self._next_time = now + self._interval
                return
            delay = self._next_time - now
            self._next_time += self._interval
        await asyncio.sleep(delay)


async def scan_async(
    base_urls: List[str],
    mode: str = "standard",
    concurrency: int = 50,
    timeout: float = 10.0,
    retries: int = 1,
    follow_redirects: bool = True,
    insecure: bool = False,
    user_agent: str = "SensiURL/0.1 (+https://github.com/)",
    rate_limit: Optional[float] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> List[Finding]:
    """Scan base URLs asynchronously and return findings.

    progress_cb: optional callback invoked with (completed, total)
    """
    from .fetcher import fetch_candidate

    log = logging.getLogger(__name__)
    candidates: List[Candidate] = []
    for base in base_urls:
        candidates.extend(generate_candidates(base, mode=mode))

    total = len(candidates)
    completed = 0

    findings: List[Finding] = []
    limiter = _RateLimiter(concurrency)
    rate_gate = _RateGate(rate_limit)

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
                    res = await fetch_candidate(
                        cand,
                        client,
                        timeout=timeout,
                        before_request=rate_gate.acquire,
                    )
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
                    log.info("[%s] %s -> %s %s", finding.severity.value, finding.category.value, finding.status_code, finding.url)
                else:
                    log.debug("No finding: %s -> %s", cand.path or cand.base_url, res.status_code)
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
    rate_limit: Optional[float] = None,
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
            rate_limit=rate_limit,
        )
    )
