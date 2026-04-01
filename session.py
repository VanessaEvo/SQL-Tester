"""
session.py - Advanced HTTP session management for authenticated scanning.
Handles CSRF tokens, cookies, and authentication flows.
"""

import re
import logging
import requests
from typing import Optional, Dict, List
from urllib.parse import urlparse

logger = logging.getLogger("sqltester.session")


class SessionManager:
    """Manages HTTP sessions with authentication, CSRF, and cookie support."""

    def __init__(self):
        self.session: requests.Session = requests.Session()
        self.csrf_token: Optional[str] = None
        self.csrf_field_name: str = "csrf_token"
        self.auth_cookies: Dict[str, str] = {}
        self.custom_headers: Dict[str, str] = {}
        self.authenticated: bool = False
        self._login_url: Optional[str] = None

    # ═══════════════════════════════════════════════════
    # Cookie Management
    # ═══════════════════════════════════════════════════

    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """Set cookies on the session manually."""
        for name, value in cookies.items():
            self.session.cookies.set(name, value)
        self.auth_cookies.update(cookies)
        logger.info(f"Set {len(cookies)} cookie(s) on session")

    def set_cookie_string(self, cookie_string: str) -> None:
        """Parse and set cookies from a raw cookie header string.
        Example: 'session=abc123; token=xyz789'
        """
        cookies: Dict[str, str] = {}
        for pair in cookie_string.split(";"):
            pair = pair.strip()
            if "=" in pair:
                name, value = pair.split("=", 1)
                cookies[name.strip()] = value.strip()
        self.set_cookies(cookies)

    def get_cookies(self) -> Dict[str, str]:
        """Return current session cookies as a dictionary."""
        return dict(self.session.cookies)

    def clear_cookies(self) -> None:
        """Clear all session cookies."""
        self.session.cookies.clear()
        self.auth_cookies.clear()
        logger.info("Cleared all session cookies")

    # ═══════════════════════════════════════════════════
    # Custom Headers
    # ═══════════════════════════════════════════════════

    def set_headers(self, headers: Dict[str, str]) -> None:
        """Set custom headers on the session."""
        self.custom_headers.update(headers)
        self.session.headers.update(headers)
        logger.info(f"Set {len(headers)} custom header(s)")

    def set_authorization(self, auth_type: str, token: str) -> None:
        """Set Authorization header.
        Args:
            auth_type: 'Bearer', 'Basic', 'Token', etc.
            token: The authentication token/credential.
        """
        self.set_headers({"Authorization": f"{auth_type} {token}"})
        self.authenticated = True
        logger.info(f"Set {auth_type} authorization")

    # ═══════════════════════════════════════════════════
    # CSRF Token Management
    # ═══════════════════════════════════════════════════

    def extract_csrf_token(self, response_text: str, field_name: Optional[str] = None) -> Optional[str]:
        """Extract CSRF token from HTML response.
        Searches for common CSRF field patterns in forms.
        """
        if field_name:
            self.csrf_field_name = field_name

        # Common CSRF token patterns
        csrf_patterns: list[tuple[str, int]] = [
            # Meta tag patterns
            (r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']', 1),
            (r'<meta\s+content=["\']([^"\']+)["\']\s+name=["\']csrf-token["\']', 1),
            (r'<meta\s+name=["\']_token["\']\s+content=["\']([^"\']+)["\']', 1),
            # Input field patterns
            (r'<input[^>]*name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', 1),
            (r'<input[^>]*name=["\']_token["\']\s+value=["\']([^"\']+)["\']', 1),
            (r'<input[^>]*name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)["\']', 1),
            (r'<input[^>]*name=["\']__RequestVerificationToken["\']\s+value=["\']([^"\']+)["\']', 1),
            (r'<input[^>]*name=["\']authenticity_token["\']\s+value=["\']([^"\']+)["\']', 1),
            (r'<input[^>]*name=["\']_csrf["\']\s+value=["\']([^"\']+)["\']', 1),
            # Custom field name
            (rf'<input[^>]*name=["\']' + re.escape(self.csrf_field_name) + rf'["\']\s+value=["\']([^"\']+)["\']', 1),
            # Value-first patterns
            (r'<input[^>]*value=["\']([^"\']{20,})["\'][^>]*name=["\'](?:csrf|_token|token)["\']', 1),
            # JavaScript variable patterns
            (r'(?:csrf|csrfToken|_token)\s*[=:]\s*["\']([^"\']{20,})["\']', 1),
        ]

        for pattern, group in csrf_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                self.csrf_token = match.group(group)
                logger.info(f"Extracted CSRF token: {self.csrf_token[:20]}...")
                return self.csrf_token

        logger.debug("No CSRF token found in response")
        return None

    def get_csrf_data(self) -> Dict[str, str]:
        """Return CSRF token as form data dict for POST requests."""
        if self.csrf_token:
            return {self.csrf_field_name: self.csrf_token}
        return {}

    # ═══════════════════════════════════════════════════
    # Authentication
    # ═══════════════════════════════════════════════════

    def login(self, login_url: str, credentials: Dict[str, str],
              csrf_field: Optional[str] = None, timeout: int = 10) -> bool:
        """Perform login and persist session cookies.
        Args:
            login_url: URL of the login form/endpoint.
            credentials: Dict with form field names and values 
                         (e.g., {'username': 'admin', 'password': 'pass'}).
            csrf_field: Optional CSRF field name to extract before login.
            timeout: Request timeout in seconds.
        Returns:
            True if login appears successful.
        """
        self._login_url = login_url

        try:
            # Step 1: GET login page to extract CSRF token
            get_response = self.session.get(login_url, timeout=timeout)
            if csrf_field:
                self.extract_csrf_token(get_response.text, csrf_field)
            else:
                self.extract_csrf_token(get_response.text)

            # Step 2: POST login with credentials + CSRF
            post_data = {**credentials, **self.get_csrf_data()}
            post_response = self.session.post(
                login_url, data=post_data, timeout=timeout, allow_redirects=True
            )

            # Step 3: Determine success
            # Check for common failure indicators
            failure_indicators = [
                "invalid", "incorrect", "wrong", "failed", "error",
                "login", "sign in", "authentication failed"
            ]
            response_lower = post_response.text.lower()

            # If redirected away from login page, likely success
            if post_response.url != login_url:
                self.authenticated = True
                self.auth_cookies = dict(self.session.cookies)
                logger.info(f"Login successful (redirected to {post_response.url})")
                return True

            # If no failure indicators and status is 200, might be success
            failure_count = sum(1 for f in failure_indicators if f in response_lower)
            if failure_count == 0 and post_response.status_code == 200:
                self.authenticated = True
                self.auth_cookies = dict(self.session.cookies)
                logger.info("Login appears successful (no failure indicators)")
                return True

            logger.warning(f"Login may have failed ({failure_count} failure indicators found)")
            return False

        except requests.RequestException as e:
            logger.error(f"Login request failed: {e}")
            return False

    # ═══════════════════════════════════════════════════
    # Request Methods (session-aware)
    # ═══════════════════════════════════════════════════

    def get(self, url: str, **kwargs) -> requests.Response:
        """Session-aware GET request."""
        kwargs.setdefault("timeout", 10)
        response = self.session.get(url, **kwargs)
        # Auto-refresh CSRF token from response
        self.extract_csrf_token(response.text)
        return response

    def post(self, url: str, data: Optional[Dict] = None, **kwargs) -> requests.Response:
        """Session-aware POST request with auto CSRF injection."""
        kwargs.setdefault("timeout", 10)
        if data is None:
            data = {}
        # Auto-inject CSRF token
        data.update(self.get_csrf_data())
        response = self.session.post(url, data=data, **kwargs)
        # Auto-refresh CSRF token from response
        self.extract_csrf_token(response.text)
        return response

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Generic session-aware request."""
        kwargs.setdefault("timeout", 10)
        return self.session.request(method, url, **kwargs)

    # ═══════════════════════════════════════════════════
    # Utility
    # ═══════════════════════════════════════════════════

    def reset(self) -> None:
        """Reset session to fresh state."""
        self.session = requests.Session()
        self.csrf_token = None
        self.auth_cookies.clear()
        self.custom_headers.clear()
        self.authenticated = False
        logger.info("Session reset to fresh state")

    def get_status(self) -> Dict[str, object]:
        """Return current session status for UI display."""
        return {
            "authenticated": self.authenticated,
            "cookies_count": len(self.session.cookies),
            "has_csrf": self.csrf_token is not None,
            "custom_headers_count": len(self.custom_headers),
            "login_url": self._login_url
        }
