from __future__ import annotations

import asyncio
import logging
from typing import Optional, Callable, Awaitable

import httpx

from .models import Candidate, FetchResult


async def fetch_candidate(
    candidate: Candidate,
    client: httpx.AsyncClient,
    timeout: float = 10.0,
    max_bytes: int = 2048,
    before_request: Optional[Callable[[], Awaitable[None]]] = None,
) -> FetchResult:
    """Fetch a candidate URL. Try HEAD first, then GET with range or streamed partial body.

    Returns a FetchResult with small content snippet for analysis.
    """
    url = candidate.url
    headers = {"Accept": "*/*"}
    log = logging.getLogger(__name__)

    # Attempt HEAD first
    try:
        if before_request:
            await before_request()
        log.debug("HEAD %s", url)
        r = await client.head(url, timeout=timeout)
        status_code = r.status_code
        content_type = r.headers.get("Content-Type")
        content_length = _parse_int(r.headers.get("Content-Length"))
        # Some servers return 405/403 for HEAD; fall back to GET
        if status_code in (200, 206, 403, 401, 405):
            # We'll still do a small GET to sample content to help detection
            if before_request:
                await before_request()
            log.debug("GET %s [sample]", url)
            snippet_info = await _sample_get(client, url, timeout=timeout, max_bytes=max_bytes)
            final_url = snippet_info[0] if snippet_info else str(r.request.url)
            snippet = snippet_info[1] if snippet_info else None
            return FetchResult(
                url=url,
                final_url=final_url,
                status_code=status_code,
                headers=dict(r.headers),
                content_snippet=snippet,
                content_type=content_type,
                content_length=content_length,
                error=None,
            )
        # For other statuses, return HEAD info only
        return FetchResult(
            url=url,
            final_url=str(r.request.url),
            status_code=status_code,
            headers=dict(r.headers),
            content_snippet=None,
            content_type=content_type,
            content_length=content_length,
            error=None,
        )
    except Exception as e:
        # Try GET directly if HEAD failed
        try:
            if before_request:
                await before_request()
            log.debug("GET %s [direct]", url)
            snippet_info = await _sample_get(client, url, timeout=timeout, max_bytes=max_bytes)
            return FetchResult(
                url=url,
                final_url=snippet_info[0] if snippet_info else url,
                status_code=snippet_info[2] if snippet_info else None,
                headers=snippet_info[3] if snippet_info else {},
                content_snippet=snippet_info[1] if snippet_info else None,
                content_type=snippet_info[4] if snippet_info else None,
                content_length=snippet_info[5] if snippet_info else None,
                error=None,
            )
        except Exception as e2:
            return FetchResult(
                url=url,
                final_url=None,
                status_code=None,
                headers={},
                content_snippet=None,
                content_type=None,
                content_length=None,
                error=f"{type(e2).__name__}: {e2}",
            )


async def _sample_get(
    client: httpx.AsyncClient, url: str, timeout: float, max_bytes: int
) -> Optional[tuple[str, bytes, int, dict, Optional[str], Optional[int]]]:
    """Stream a small snippet via GET with Range header.

    Returns tuple: (final_url, snippet, status_code, headers, content_type, content_length)
    """
    headers = {"Range": f"bytes=0-{max_bytes - 1}"}
    async with client.stream("GET", url, timeout=timeout, headers=headers) as r:
        status_code = r.status_code
        hdrs = dict(r.headers)
        content_type = r.headers.get("Content-Type")
        content_length = _parse_int(r.headers.get("Content-Length"))
        buf = bytearray()
        async for chunk in r.aiter_bytes():
            if not chunk:
                break
            remaining = max_bytes - len(buf)
            if remaining <= 0:
                break
            buf.extend(chunk[:remaining])
            if len(buf) >= max_bytes:
                break
        final_url = str(r.request.url)
        return final_url, bytes(buf), status_code, hdrs, content_type, content_length


def _parse_int(x: Optional[str]) -> Optional[int]:
    try:
        return int(x) if x is not None else None
    except Exception:
        return None
