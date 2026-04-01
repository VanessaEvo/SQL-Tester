"""
proxy.py - Proxy management for scan traffic routing.
Supports HTTP/HTTPS/SOCKS5 proxies with rotation and health checking.
"""

import logging
import random
import time
from typing import Optional, Dict, List
import requests

logger = logging.getLogger("sqltester.proxy")


class ProxyManager:
    """Manages proxy configuration, rotation, and health checking."""

    def __init__(self):
        self.proxies: List[Dict[str, str]] = []
        self.current_index: int = 0
        self.enabled: bool = False
        self.rotation_mode: str = "round_robin"  # round_robin | random | sticky
        self.failed_proxies: Dict[str, int] = {}  # proxy_url -> fail_count
        self.max_failures: int = 3
        self._sticky_proxy: Optional[Dict[str, str]] = None
        self._test_url: str = "https://httpbin.org/ip"

    # ═══════════════════════════════════════════════════
    # Proxy Configuration
    # ═══════════════════════════════════════════════════

    def add_proxy(self, proxy_url: str) -> None:
        """Add a single proxy.
        Formats:
            http://host:port
            https://host:port
            socks5://user:pass@host:port
            socks5h://host:port  (DNS through proxy)
        """
        proxy_dict = self._parse_proxy_url(proxy_url)
        if proxy_dict and proxy_dict not in self.proxies:
            self.proxies.append(proxy_dict)
            self.enabled = True
            logger.info(f"Added proxy: {proxy_url}")

    def add_proxies(self, proxy_urls: List[str]) -> None:
        """Add multiple proxies at once."""
        for url in proxy_urls:
            self.add_proxy(url.strip())

    def load_from_file(self, filepath: str) -> int:
        """Load proxy list from a file (one proxy per line).
        Returns number of proxies loaded.
        """
        count = 0
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.add_proxy(line)
                        count += 1
            logger.info(f"Loaded {count} proxies from {filepath}")
        except (IOError, OSError) as e:
            logger.error(f"Failed to load proxy file: {e}")
        return count

    def set_single_proxy(self, proxy_url: str) -> None:
        """Set a single proxy (replaces all existing)."""
        self.proxies.clear()
        self.failed_proxies.clear()
        self.add_proxy(proxy_url)
        self.rotation_mode = "sticky"

    def clear(self) -> None:
        """Remove all proxies and disable."""
        self.proxies.clear()
        self.failed_proxies.clear()
        self.current_index = 0
        self.enabled = False
        self._sticky_proxy = None
        logger.info("Cleared all proxies")

    # ═══════════════════════════════════════════════════
    # Proxy Selection & Rotation
    # ═══════════════════════════════════════════════════

    def get_proxy(self) -> Optional[Dict[str, str]]:
        """Get the next proxy based on rotation mode.
        Returns None if no proxies available or disabled.
        """
        if not self.enabled or not self.proxies:
            return None

        # Filter out failed proxies
        available = [p for p in self.proxies
                     if self._proxy_key(p) not in self.failed_proxies
                     or self.failed_proxies[self._proxy_key(p)] < self.max_failures]

        if not available:
            logger.warning("All proxies have exceeded max failures. Resetting failure counts.")
            self.failed_proxies.clear()
            available = self.proxies

        if self.rotation_mode == "sticky":
            if self._sticky_proxy and self._sticky_proxy in available:
                return self._sticky_proxy
            self._sticky_proxy = available[0]
            return self._sticky_proxy

        elif self.rotation_mode == "random":
            return random.choice(available)

        else:  # round_robin
            proxy = available[self.current_index % len(available)]
            self.current_index += 1
            return proxy

    def report_failure(self, proxy: Optional[Dict[str, str]]) -> None:
        """Report a proxy failure to track unreliable proxies."""
        if proxy is None:
            return
        key = self._proxy_key(proxy)
        self.failed_proxies[key] = self.failed_proxies.get(key, 0) + 1
        count = self.failed_proxies[key]
        logger.warning(f"Proxy failure #{count}: {key}")
        if count >= self.max_failures:
            logger.warning(f"Proxy disabled after {self.max_failures} failures: {key}")

    def report_success(self, proxy: Optional[Dict[str, str]]) -> None:
        """Report successful use — resets failure count."""
        if proxy is None:
            return
        key = self._proxy_key(proxy)
        if key in self.failed_proxies:
            del self.failed_proxies[key]

    def set_rotation_mode(self, mode: str) -> None:
        """Set rotation mode: 'round_robin', 'random', or 'sticky'."""
        if mode in ("round_robin", "random", "sticky"):
            self.rotation_mode = mode
            logger.info(f"Proxy rotation mode set to: {mode}")
        else:
            logger.warning(f"Unknown rotation mode: {mode}")

    # ═══════════════════════════════════════════════════
    # Health Checking
    # ═══════════════════════════════════════════════════

    def check_proxy(self, proxy: Dict[str, str], timeout: int = 10) -> bool:
        """Test if a single proxy is working."""
        try:
            response = requests.get(
                self._test_url, proxies=proxy, timeout=timeout
            )
            return response.status_code == 200
        except requests.RequestException:
            return False

    def check_all(self, timeout: int = 10) -> Dict[str, bool]:
        """Test all proxies and return health status.
        Returns dict of proxy_key -> is_working.
        """
        results: Dict[str, bool] = {}
        for proxy in self.proxies:
            key = self._proxy_key(proxy)
            working = self.check_proxy(proxy, timeout)
            results[key] = working
            if not working:
                self.report_failure(proxy)
            else:
                self.report_success(proxy)
            logger.info(f"Proxy check: {key} -> {'OK' if working else 'FAIL'}")
        return results

    # ═══════════════════════════════════════════════════
    # Session Integration
    # ═══════════════════════════════════════════════════

    def apply_to_session(self, session: requests.Session) -> None:
        """Apply current proxy to a requests session."""
        proxy = self.get_proxy()
        if proxy:
            session.proxies.update(proxy)

    # ═══════════════════════════════════════════════════
    # Internal Helpers
    # ═══════════════════════════════════════════════════

    @staticmethod
    def _parse_proxy_url(proxy_url: str) -> Optional[Dict[str, str]]:
        """Parse proxy URL into requests-compatible proxy dict."""
        proxy_url = proxy_url.strip()
        if not proxy_url:
            return None

        # Add scheme if missing
        if "://" not in proxy_url:
            proxy_url = "http://" + proxy_url

        scheme = proxy_url.split("://")[0].lower()

        if scheme in ("http", "https"):
            return {"http": proxy_url, "https": proxy_url}
        elif scheme in ("socks5", "socks5h", "socks4"):
            return {"http": proxy_url, "https": proxy_url}
        else:
            logger.warning(f"Unsupported proxy scheme: {scheme}")
            return None

    @staticmethod
    def _proxy_key(proxy: Dict[str, str]) -> str:
        """Get a unique key for a proxy dict."""
        return proxy.get("http", proxy.get("https", "unknown"))

    # ═══════════════════════════════════════════════════
    # Status
    # ═══════════════════════════════════════════════════

    def get_status(self) -> Dict[str, object]:
        """Return current proxy status for UI display."""
        return {
            "enabled": self.enabled,
            "total_proxies": len(self.proxies),
            "failed_proxies": len(self.failed_proxies),
            "rotation_mode": self.rotation_mode,
            "current_proxy": self._proxy_key(self.get_proxy()) if self.enabled and self.proxies else None
        }
