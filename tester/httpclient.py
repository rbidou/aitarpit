"""HTTP client for the test tool.

A thin wrapper over ``requests`` that resolves relative paths against a fixed
target base URL and can be *origin-locked* - refusing any absolute URL outside
the target origin. The agent mode (M6) relies on the origin lock for
containment; the conformance checker uses the same client without the lock.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import requests


class ContainmentError(Exception):
    """Raised when a request would leave the target origin."""


def origin_of(url: str) -> str:
    """Return the ``scheme://host[:port]`` origin of a URL.

    Args:
        url: An absolute URL.

    Returns:
        The origin string.
    """
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


@dataclass
class TargetClient:
    """A requests-backed client bound to one target origin."""

    base_url: str
    timeout: float = 10.0
    origin_lock: bool = False
    session: requests.Session = field(default_factory=requests.Session)
    requests_made: int = 0

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        self.origin = origin_of(self.base_url)

    def resolve(self, path_or_url: str) -> str:
        """Resolve a path or absolute URL to a full URL, enforcing the origin lock.

        Args:
            path_or_url: A path (``/foo``) or an absolute URL.

        Returns:
            The absolute URL to request.

        Raises:
            ContainmentError: When the origin lock is on and the URL is off-origin.
        """
        if path_or_url.startswith(("http://", "https://")):
            if self.origin_lock and origin_of(path_or_url) != self.origin:
                raise ContainmentError(f"refused off-origin request to {origin_of(path_or_url)} (target {self.origin})")
            return path_or_url
        return f"{self.base_url}/{path_or_url.lstrip('/')}"

    def request(self, method: str, path_or_url: str, *, stream: bool = False, **kwargs: Any) -> requests.Response:
        """Issue a request, resolving the path and counting it.

        Args:
            method: HTTP method.
            path_or_url: Path or absolute URL.
            stream: Pass through to requests for streaming responses.
            **kwargs: Extra requests arguments (headers, json, data, params).

        Returns:
            The requests Response.
        """
        url = self.resolve(path_or_url)
        self.requests_made += 1
        kwargs.setdefault("timeout", self.timeout)
        return self.session.request(method, url, stream=stream, **kwargs)

    def get(self, path_or_url: str, **kwargs: Any) -> requests.Response:
        return self.request("GET", path_or_url, **kwargs)

    def post(self, path_or_url: str, **kwargs: Any) -> requests.Response:
        return self.request("POST", path_or_url, **kwargs)

    def first_chunk(self, path_or_url: str, max_bytes: int = 64, read_timeout: float = 3.0) -> bytes:
        """Open a streamed response and return its first bytes, then close it.

        Used to verify slow-drip / endless responses without downloading them.

        Args:
            path_or_url: Path or absolute URL.
            max_bytes: How many bytes to read.
            read_timeout: Per-request timeout.

        Returns:
            The first bytes received (possibly empty).
        """
        resp = self.request("GET", path_or_url, stream=True, timeout=read_timeout)
        try:
            for chunk in resp.iter_content(chunk_size=max_bytes):
                return chunk or b""
            return b""
        finally:
            resp.close()
