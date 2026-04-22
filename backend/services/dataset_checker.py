"""
Dataset Checker Service.

Verifies URLs against external phishing feeds and internal blacklists:
- PhishTank API (requires free API key in PHISHTANK_API_KEY env var)
- OpenPhish daily feed (local file, auto-refreshed)
- Internal SQLite blacklist (admin-managed)

This should be called as STEP 1 in the URL analysis pipeline
(fast, cheap check before any slow OSINT operations).
"""

import os
import sqlite3
import hashlib
import time
import threading
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional

import requests

from utils.logger import logger
from utils.config import PHISHTANK_API_KEY, OPENPHISH_FEED_PATH, BLACKLIST_DB_PATH


# How often to refresh the OpenPhish feed (seconds) — 24h
_OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
_OPENPHISH_REFRESH_INTERVAL = 86400  # 24 hours


class DatasetChecker:
    """
    Multi-source URL blocklist checker.

    Usage:
        checker = DatasetChecker()
        result = checker.check_url("https://suspicious-site.com")
    """

    def __init__(self):
        self._openphish_feed: Optional[set] = None
        self._openphish_loaded_at: float = 0.0
        self._refresh_lock = threading.Lock()
        self._ensure_blacklist_db()

    # =============================
    # Public API
    # =============================

    def check_url(self, url: str) -> dict:
        """
        Check URL against all available blocklists.

        Returns:
            dict with keys:
                is_blacklisted (bool)
                source (str | None)  — which feed caught it
                details (str)
        """
        # 1. Internal blacklist (fastest — local SQLite)
        if self._check_internal_blacklist(url):
            return {
                "is_blacklisted": True,
                "source": "internal_blacklist",
                "details": "Domain found in internal blacklist"
            }

        # 2. OpenPhish feed (local file)
        if self._check_openphish(url):
            return {
                "is_blacklisted": True,
                "source": "openphish",
                "details": "URL found in OpenPhish phishing feed"
            }

        # 3. PhishTank API (requires API key, slower)
        if PHISHTANK_API_KEY:
            result = self._check_phishtank(url)
            if result.get("is_phishing"):
                return {
                    "is_blacklisted": True,
                    "source": "phishtank",
                    "details": result.get("detail", "URL found in PhishTank database")
                }

        return {
            "is_blacklisted": False,
            "source": None,
            "details": "URL not found in any blocklist"
        }

    # =============================
    # PhishTank
    # =============================

    def _check_phishtank(self, url: str) -> dict:
        """Call PhishTank API to verify URL."""
        try:
            resp = requests.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={
                    "url": url,
                    "format": "json",
                    "app_key": PHISHTANK_API_KEY,
                },
                timeout=5,
                verify=True,
                headers={"User-Agent": "phishtank/ai-scam-detector"}
            )
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", {})
            return {
                "is_phishing": results.get("in_database", False) and results.get("valid", False),
                "detail": results.get("phish_detail_page", "")
            }
        except requests.HTTPError as e:
            logger.warning("phishtank_http_error | status=%s", getattr(e.response, "status_code", "unknown"))
            return {"is_phishing": False}
        except (ValueError, KeyError) as e:
            logger.warning("phishtank_parse_error | error=%s", str(e))
            return {"is_phishing": False}
        except Exception as e:
            logger.warning("phishtank_check_failed | error=%s", str(e))
            return {"is_phishing": False}

    # =============================
    # OpenPhish
    # =============================

    def _check_openphish(self, url: str) -> bool:
        """
        Check URL against locally cached OpenPhish feed.
        Refreshes feed if older than 24 hours.
        """
        self._maybe_refresh_openphish()

        if self._openphish_feed is None:
            return False

        # Exact match
        if url in self._openphish_feed:
            return True

        # Domain suffix match
        domain = urlparse(url).netloc.lower()
        if not domain:
            return False
        return any(
            entry_domain == domain or entry_domain.endswith("." + domain) or domain.endswith("." + entry_domain)
            for entry_domain in (urlparse(entry).netloc.lower() for entry in self._openphish_feed)
            if entry_domain
        )

    def _maybe_refresh_openphish(self) -> None:
        """Download fresh OpenPhish feed if needed."""
        feed_path = Path(OPENPHISH_FEED_PATH)
        now = time.time()

        # Load from disk if in-memory cache is stale or empty
        if self._openphish_feed is not None and now - self._openphish_loaded_at <= _OPENPHISH_REFRESH_INTERVAL:
            return
        with self._refresh_lock:
            now = time.time()
            if self._openphish_feed is not None and now - self._openphish_loaded_at <= _OPENPHISH_REFRESH_INTERVAL:
                return
            if feed_path.exists() and (now - feed_path.stat().st_mtime < _OPENPHISH_REFRESH_INTERVAL):
                # Feed file is fresh — load from disk
                try:
                    with open(feed_path, encoding="utf-8") as f:
                        self._openphish_feed = {
                            line.strip().lower()
                            for line in f
                            if line.strip()
                        }
                    self._openphish_loaded_at = now
                    logger.info("openphish_feed_loaded | entries=%d", len(self._openphish_feed))
                except Exception as e:
                    logger.warning("openphish_feed_read_error | %s", str(e))
            else:
                # Download fresh feed
                self._download_openphish_feed(feed_path)

    def _download_openphish_feed(self, feed_path: Path) -> None:
        """Download OpenPhish feed to disk."""
        try:
            resp = requests.get(_OPENPHISH_FEED_URL, timeout=15)
            if resp.status_code == 200:
                feed_path.parent.mkdir(parents=True, exist_ok=True)
                feed_path.write_text(resp.text, encoding="utf-8")
                self._openphish_feed = {
                    line.strip().lower()
                    for line in resp.text.splitlines()
                    if line.strip()
                }
                self._openphish_loaded_at = time.time()
                logger.info("openphish_feed_downloaded | entries=%d", len(self._openphish_feed))
            else:
                logger.warning("openphish_download_failed | status=%d", resp.status_code)
        except Exception as e:
            logger.warning("openphish_download_error | %s", str(e))

    # =============================
    # Internal SQLite blacklist
    # =============================

    def _ensure_blacklist_db(self) -> None:
        """Create blacklist table if it doesn't exist."""
        try:
            db_path = Path(BLACKLIST_DB_PATH)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(str(db_path)) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS blacklist (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT NOT NULL UNIQUE,
                        reason TEXT,
                        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
        except Exception as e:
            logger.warning("blacklist_db_init_error | %s", str(e))

    def _check_internal_blacklist(self, url: str) -> bool:
        """Query internal SQLite blacklist by domain."""
        try:
            # FIX: lstrip("www.") strips any leading chars in the SET {'w','.'} — not the literal prefix.
            # e.g. "wwwevil.com" → "evil.com" (wrong), "www.evil.com" → "evil.com" (correct by accident)
            # Use explicit startswith() check instead.
            netloc = urlparse(url).netloc.lower()
            domain = netloc[4:] if netloc.startswith("www.") else netloc
            if not domain:
                return False
            with sqlite3.connect(str(BLACKLIST_DB_PATH)) as conn:
                row = conn.execute(
                    "SELECT 1 FROM blacklist WHERE domain = ?", (domain,)
                ).fetchone()
                return row is not None
        except Exception as e:
            logger.warning("internal_blacklist_check_error | %s", str(e))
            return False

    def add_to_blacklist(self, domain: str, reason: str = "") -> bool:
        """Add a domain to the internal blacklist (admin use)."""
        try:
            domain = domain.lower().strip()
            if domain.startswith("www."):
                domain = domain[4:]
            with sqlite3.connect(str(BLACKLIST_DB_PATH)) as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO blacklist (domain, reason) VALUES (?, ?)",
                    (domain, reason)
                )
                conn.commit()
            logger.info("blacklist_domain_added | domain=%s", domain)
            return True
        except Exception as e:
            logger.error("blacklist_add_error | domain=%s | %s", domain, str(e))
            return False


# Module-level singleton
_checker_instance: Optional[DatasetChecker] = None
_checker_lock = threading.Lock()


def get_dataset_checker() -> DatasetChecker:
    """Get or create the singleton DatasetChecker instance."""
    global _checker_instance
    if _checker_instance is not None:
        return _checker_instance
    with _checker_lock:
        if _checker_instance is None:
            _checker_instance = DatasetChecker()
    return _checker_instance


def check_url_against_datasets(url: str) -> dict:
    """Convenience function for pipeline use."""
    return get_dataset_checker().check_url(url)
