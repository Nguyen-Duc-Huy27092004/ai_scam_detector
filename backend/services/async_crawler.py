"""
SecureCrawler — Production-hardened async HTML crawler.

Security:
  - SSRF protection via IP validation (private/loopback/link-local blocked)
  - Manual redirect chain tracking with SSRF check on every hop
  - HTML size limit (1 MB) to prevent memory exhaustion
  - Content-Type guard (only text/html accepted)
  - Configurable DNS-cache TTL and connection limit

Usage (async):
    result = await SecureCrawler.crawl(url)

Usage (sync, from threads/sync code):
    result = SecureCrawler.crawl_sync(url)
"""

import asyncio
import random
import socket
import ipaddress
import ssl as ssl_module
from typing import Optional, Dict, Any
from urllib.parse import urlparse, urljoin

import aiohttp
from bs4 import BeautifulSoup

from utils.logger import logger

_SSL_CONTEXT = ssl_module.create_default_context()


class SecureCrawler:
    MAX_HTML_SIZE = 1_000_000   # 1 MB hard cap
    MAX_TEXT_LENGTH = 5_000     # truncate extracted text
    MAX_REDIRECTS = 3

    TIMEOUT = aiohttp.ClientTimeout(
        total=25,
        connect=10,
        sock_read=10,
    )

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
    ]

    # ========================
    # SSRF PROTECTION
    # ========================

    @staticmethod
    def _resolve_and_validate(hostname: str) -> bool:
        """Return True only if hostname resolves to a globally routable IP."""
        try:
            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)
            return not any([
                ip_obj.is_private,
                ip_obj.is_loopback,
                ip_obj.is_link_local,
                ip_obj.is_reserved,
                ip_obj.is_multicast,
            ])
        except Exception:
            return False

    @classmethod
    def is_safe_url(cls, url: str) -> bool:
        """Return True if the URL is safe to fetch (scheme + SSRF check)."""
        try:
            parsed = urlparse(url)
            return (
                parsed.scheme in ("http", "https")
                and bool(parsed.hostname)
                and cls._resolve_and_validate(parsed.hostname)
            )
        except Exception:
            return False

    # ========================
    # INTERNAL FETCH
    # ========================

    @classmethod
    async def _fetch(cls, session: aiohttp.ClientSession, url: str, depth: int = 0) -> Optional[str]:
        """Recursively follow up to MAX_REDIRECTS hops, SSRF-checking each."""
        if depth > cls.MAX_REDIRECTS:
            logger.debug("max_redirects_exceeded | url=%s", url[:80])
            return None

        if not cls.is_safe_url(url):
            logger.debug("ssrf_blocked | url=%s", url[:80])
            return None

        headers = {"User-Agent": random.choice(cls.USER_AGENTS)}

        try:
            async with session.get(url, headers=headers, allow_redirects=False) as resp:

                # Manual redirect — re-validate destination
                if 300 <= resp.status < 400:
                    loc = resp.headers.get("Location")
                    if loc:
                        next_url = urljoin(url, loc)
                        if cls.is_safe_url(next_url):
                            return await cls._fetch(session, next_url, depth + 1)
                    return None

                if resp.status != 200:
                    logger.debug("non_200 | status=%d | url=%s", resp.status, url[:80])
                    return None

                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type:
                    logger.debug("non_html | content_type=%s | url=%s", content_type, url[:80])
                    return None

                # Stream with size cap
                size = 0
                chunks: list[bytes] = []
                async for chunk in resp.content.iter_chunked(4096):
                    size += len(chunk)
                    if size > cls.MAX_HTML_SIZE:
                        logger.debug("html_too_large | url=%s", url[:80])
                        return None
                    chunks.append(chunk)

                return b"".join(chunks).decode(errors="ignore")

        except asyncio.TimeoutError:
            logger.debug("fetch_timeout | url=%s", url[:80])
            return None
        except aiohttp.ClientError as e:
            logger.debug("fetch_client_error | url=%s | %s", url[:80], str(e))
            return None
        except Exception as e:
            logger.debug("fetch_error | url=%s | %s", url[:80], str(e))
            return None

    # ========================
    # TEXT EXTRACTION
    # ========================

    @classmethod
    def extract_text(cls, html: str) -> str:
        """Extract visible text from HTML, truncated to MAX_TEXT_LENGTH chars."""
        try:
            soup = BeautifulSoup(html, "html.parser")

            for tag in ("script", "style", "noscript"):
                for el in soup.find_all(tag):
                    el.decompose()

            text = soup.get_text(" ", strip=True)
            text = " ".join(text.split())

            if len(text) > 200:
                return text[:cls.MAX_TEXT_LENGTH]

            # Fallback: collect structured metadata
            parts: list[str] = []
            if soup.title:
                parts.append(soup.title.get_text(strip=True))
            desc = soup.find("meta", attrs={"name": "description"})
            if desc and desc.get("content"):
                parts.append(desc["content"])
            for h in soup.find_all(["h1", "h2"], limit=5):
                t = h.get_text(strip=True)
                if t:
                    parts.append(t)
            for form in soup.find_all("form"):
                for inp in form.find_all("input"):
                    ph = inp.get("placeholder")
                    if ph:
                        parts.append(ph)

            fallback = " | ".join(parts)
            return fallback[:cls.MAX_TEXT_LENGTH] if fallback else ""

        except Exception:
            return ""

    # ========================
    # ASYNC ENTRY POINT
    # ========================

    @classmethod
    async def crawl(cls, url: str) -> Dict[str, Any]:
        """Crawl a URL and return structured result dict."""
        connector = aiohttp.TCPConnector(
            ssl=_SSL_CONTEXT,
            limit=10,
            ttl_dns_cache=300,
        )

        async with aiohttp.ClientSession(
            timeout=cls.TIMEOUT,
            connector=connector,
        ) as session:
            try:
                html = await asyncio.wait_for(
                    cls._fetch(session, url),
                    timeout=30,
                )
            except asyncio.TimeoutError:
                logger.debug("crawl_global_timeout | url=%s", url[:80])
                return cls._fail(url)

        if not html:
            return cls._fail(url)

        return {
            "success": True,
            "html": html,
            "text": cls.extract_text(html),
            "final_url": url,
        }

    # ========================
    # SYNC WRAPPER (thread-safe)
    # ========================

    @classmethod
    def crawl_sync(cls, url: str) -> Dict[str, Any]:
        """
        Synchronous wrapper — safe to call from threads (creates its own event loop).
        Do NOT call this from within an already-running async context; use crawl() instead.
        """
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(cls.crawl(url))
            finally:
                loop.close()
        except Exception as e:
            logger.debug("crawl_sync_error | url=%s | %s", url[:80], str(e))
            return cls._fail(url)

    # ========================
    # FAIL SAFE
    # ========================

    @staticmethod
    def _fail(url: str) -> Dict[str, Any]:
        return {
            "success": False,
            "html": "",
            "text": "",
            "final_url": url,
        }