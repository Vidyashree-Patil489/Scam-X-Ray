"""
ScamXRay Reputation Intelligence Service.
Handles reputation feed lookups (OpenPhish feed with disk/memory caching and fallback).
"""

import os
import time
import json
import logging
from urllib.parse import urlparse
import requests

logger = logging.getLogger(__name__)

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
DEFAULT_TIMEOUT = 4.0
REFRESH_INTERVAL_SECONDS = 12 * 3600  # 12 hours

# Base cache path in backend/cache/
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR = os.path.join(_BACKEND_DIR, "cache")
FEED_CACHE_FILE = os.path.join(CACHE_DIR, "openphish_feed.txt")
META_CACHE_FILE = os.path.join(CACHE_DIR, "openphish_meta.json")

# In-memory feed cache
_mem_feed_urls = set()
_mem_feed_hosts = set()
_mem_last_fetched = 0.0


def _ensure_cache_dir():
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
    except Exception as e:
        logger.warning(f"Could not create cache directory {CACHE_DIR}: {e}")


def _normalize_feed_url(raw_url: str) -> str:
    """Normalize URL from feed or query for exact matching."""
    u = (raw_url or "").strip()
    if not u:
        return ""
    try:
        parsed = urlparse(u if "://" in u else "http://" + u)
        scheme = (parsed.scheme or "http").lower()
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{host}{path}{query}".rstrip("/")
    except Exception:
        return u.strip().lower().rstrip("/")


def _parse_and_store_feed_content(text: str):
    """Parse feed text and update in-memory sets."""
    global _mem_feed_urls, _mem_feed_hosts
    urls = set()
    hosts = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        norm = _normalize_feed_url(line)
        if norm:
            urls.add(norm)
            try:
                h = (urlparse(norm).hostname or "").lower()
                if h:
                    hosts.add(h)
            except Exception:
                pass
    _mem_feed_urls = urls
    _mem_feed_hosts = hosts


def _load_disk_cache() -> bool:
    """Attempt to load existing feed from disk into memory."""
    global _mem_last_fetched
    if not os.path.exists(FEED_CACHE_FILE):
        return False
    try:
        mtime = os.path.getmtime(FEED_CACHE_FILE)
        if os.path.exists(META_CACHE_FILE):
            try:
                with open(META_CACHE_FILE, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                    mtime = meta.get("last_fetched", mtime)
            except Exception:
                pass

        with open(FEED_CACHE_FILE, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        _parse_and_store_feed_content(content)
        _mem_last_fetched = mtime
        return len(_mem_feed_urls) > 0
    except Exception as e:
        logger.warning(f"Failed to read OpenPhish disk cache: {e}")
        return False


def _save_disk_cache(text: str, timestamp: float):
    """Save downloaded feed text to disk cache."""
    _ensure_cache_dir()
    try:
        with open(FEED_CACHE_FILE, "w", encoding="utf-8") as f:
            f.write(text)
        with open(META_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({"last_fetched": timestamp, "count": len(_mem_feed_urls)}, f)
    except Exception as e:
        logger.warning(f"Failed to write OpenPhish disk cache: {e}")


def load_or_refresh_openphish_feed(force_refresh: bool = False, timeout: float = DEFAULT_TIMEOUT) -> tuple[bool, str]:
    """
    Load or refresh the OpenPhish feed.
    - If memory/disk cache is fresh (< 12 hours), use it.
    - Otherwise, attempt to fetch from OPENPHISH_FEED_URL.
    - If fetch fails, use stale cache.
    - If no cache exists, return (False, 'not_checked').
    """
    global _mem_last_fetched
    now = time.time()

    # 1. Check in-memory freshness
    if not force_refresh and _mem_feed_urls and (now - _mem_last_fetched < REFRESH_INTERVAL_SECONDS):
        return True, "in_memory"

    # 2. Check disk cache freshness
    if not force_refresh and not _mem_feed_urls and _load_disk_cache():
        if now - _mem_last_fetched < REFRESH_INTERVAL_SECONDS:
            return True, "disk_cache"

    # 3. Attempt download
    try:
        resp = requests.get(
            OPENPHISH_FEED_URL,
            timeout=timeout,
            headers={"User-Agent": "ScamXRay-Reputation/1.0"}
        )
        if resp.status_code == 200 and resp.text:
            _parse_and_store_feed_content(resp.text)
            _mem_last_fetched = now
            _save_disk_cache(resp.text, now)
            return True, "downloaded"
    except Exception as e:
        logger.info(f"OpenPhish feed refresh failed ({e}); falling back to cache.")

    # 4. Fallback to existing stale memory cache
    if _mem_feed_urls:
        return True, "stale_memory"

    # 5. Fallback to existing stale disk cache
    if _load_disk_cache():
        return True, "stale_disk"

    # 6. No cache available
    return False, "no_cache"


def check_openphish(url: str, force_refresh: bool = False, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """
    Lookup a URL in the OpenPhish community feed.
    Returns:
        {
            "source": "OpenPhish",
            "status": "match" | "no_match" | "not_checked",
            "detail": str
        }
    """
    raw = (url or "").strip()
    if not raw:
        return {
            "source": "OpenPhish",
            "status": "not_checked",
            "detail": "Empty URL provided"
        }

    has_cache, cache_mode = load_or_refresh_openphish_feed(force_refresh=force_refresh, timeout=timeout)
    if not has_cache:
        return {
            "source": "OpenPhish",
            "status": "not_checked",
            "detail": "OpenPhish feed unavailable and no local cache exists",
            "failed": True
        }

    norm_url = _normalize_feed_url(raw)
    try:
        parsed = urlparse(raw if "://" in raw else "http://" + raw)
        host = (parsed.hostname or "").lower()
    except Exception:
        host = ""

    # Match 1: Exact URL match
    if norm_url and norm_url in _mem_feed_urls:
        return {
            "source": "OpenPhish",
            "status": "match",
            "detail": f"Exact URL matched active phishing entry in OpenPhish feed ({norm_url})"
        }

    # Match 2: Host match
    if host and host in _mem_feed_hosts:
        return {
            "source": "OpenPhish",
            "status": "match",
            "detail": f"Hostname '{host}' matched active phishing host entry in OpenPhish feed"
        }

    return {
        "source": "OpenPhish",
        "status": "no_match",
        "detail": f"URL and host '{host}' not listed in OpenPhish feed ({cache_mode})"
    }
