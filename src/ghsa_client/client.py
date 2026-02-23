"""GitHub Security Advisory (GHSA) API client."""

import asyncio
import logging
import os
import re
from collections.abc import AsyncGenerator, Generator
from time import sleep, time
from typing import Any, cast

import httpx

from .exceptions import RateLimitExceeded
from .models import GHSA_ID, Advisory

_NEXT_PAGE_RE = re.compile(r'<(.*)>; rel="next"')


class _BaseGHSAClient:
    """Shared configuration and logic for sync/async GHSA clients."""

    session: httpx.Client | httpx.AsyncClient

    def __init__(
        self,
        api_key: str | None = None,
        *,
        blocking_rate_limit: bool = True,
        logger: logging.Logger = logging.getLogger(__name__),
        base_url: str = "https://api.github.com",
    ) -> None:
        """Initialize the GHSA client.

        Args:
            api_key: Optional GitHub API key. If provided, enables much higher rate limits
                (5000 requests/hour vs 60 requests/hour for unauthenticated requests).
                Falls back to GITHUB_TOKEN environment variable if not provided.
            blocking_rate_limit: If True, automatically waits for rate limit reset before
                making requests. If False, raises RateLimitExceeded when rate limited.
            logger: Logger instance for debug and error messages.
            base_url: Base URL for GitHub API. Defaults to production API.
        """
        self.base_url = base_url
        self.logger = logger
        self.blocking_rate_limit = blocking_rate_limit
        self._headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"
        elif GITHUB_TOKEN := os.getenv("GITHUB_TOKEN"):
            self._headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

        self.session = self._create_session()

    def _create_session(self) -> httpx.Client | httpx.AsyncClient:
        raise NotImplementedError

    @staticmethod
    def _parse_next_page_url(headers: httpx.Headers) -> str | None:
        if "link" not in headers:
            return None
        url_match = _NEXT_PAGE_RE.match(headers["link"])
        return url_match.group(1) if url_match else None

    @staticmethod
    def _validate_advisories(
        data_list: list[dict[str, Any]],
        strict: bool,
        logger: logging.Logger,
    ) -> Generator[Advisory, None, None]:
        if strict:
            yield from (Advisory.model_validate(data) for data in data_list)
        else:
            for data in data_list:
                try:
                    yield Advisory.model_validate(data)
                except Exception as e:
                    logger.warning(f"Skipping advisory due to validation error: {e}")

    def _should_retry_rate_limit(self, error: httpx.HTTPStatusError, url: str) -> bool:
        if error.response.status_code == 403 and error.response.text.startswith(
            "rate limit exceeded"
        ):
            return True
        if error.response.status_code == 422:
            self.logger.exception(
                f"Unprocessable entity error for URL: {url}. body: {error.response.text}"
            )
        return False

    def _log_advisory_error(self, ghsa_id: GHSA_ID, error: httpx.HTTPError) -> None:
        if isinstance(error, httpx.HTTPStatusError):
            if error.response.status_code == 404:
                self.logger.exception(f"Advisory {ghsa_id} not found")
            else:
                self.logger.exception(
                    f"HTTP error retrieving advisory {ghsa_id}: {error}"
                )
        else:
            self.logger.exception(f"Network error retrieving advisory {ghsa_id}")

    def _ratelimit_sleep_time(self, ratelimit: dict[str, Any]) -> float | None:
        if ratelimit["resources"]["core"]["remaining"] > 0:
            return None
        return ratelimit["resources"]["core"]["reset"] - time()


class GHSAClient(_BaseGHSAClient):
    """Client for querying GitHub Security Advisory database via REST API."""

    session: httpx.Client

    def _create_session(self) -> httpx.Client:
        return httpx.Client(headers=self._headers, timeout=30.0)

    def close(self) -> None:
        """Close the HTTP client session."""
        self.session.close()

    def __enter__(self) -> "GHSAClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _get_with_rate_limit_retry(
        self, url: str, *args: Any, **kwargs: Any
    ) -> httpx.Response:
        for _ in range(3):
            try:
                if self.blocking_rate_limit:
                    self.wait_for_ratelimit()
                response = self.session.get(url, *args, **kwargs)
                response.raise_for_status()
                return response
            except httpx.HTTPStatusError as e:
                if self._should_retry_rate_limit(e, url):
                    sleep(1)
                    continue
                raise

        raise RateLimitExceeded("Rate limit exceeded for advisory")

    def get_advisory(self, ghsa_id: GHSA_ID) -> Advisory:
        url = f"{self.base_url}/advisories/{ghsa_id}"
        self.logger.debug(f"Requesting advisory from URL: {url}")
        try:
            response = self._get_with_rate_limit_retry(url)
            return Advisory.model_validate(response.json())
        except httpx.HTTPError as e:
            self._log_advisory_error(ghsa_id, e)
            raise

    def search_advisories(
        self, per_page: int = 100, strict: bool = True, **filters: Any
    ) -> Generator[Advisory, None, None]:
        """Search for advisories with pagination support.

        Args:
            per_page: Number of advisories per page (default: 100)
            strict: If True (default), raises ValidationError on invalid advisories.
                   If False, skips invalid advisories and continues.
            **filters: Additional filters to pass to the API (e.g., ecosystem, cwes)
        """
        url = f"{self.base_url}/advisories"
        params: dict[str, Any] | None = filters

        while True:
            response = self._get_with_rate_limit_retry(url, params=params)
            advisories = response.json()

            if not advisories:
                break

            yield from self._validate_advisories(advisories, strict, self.logger)

            next_url = self._parse_next_page_url(response.headers)
            if next_url is None:
                break
            url = next_url
            params = None  # Pagination URL already includes all params

    def get_all_advisories_for_year(self, year: int) -> list[Advisory]:
        """Get all advisories for a given year."""
        return list(self.search_advisories(published=f"{year}-01-01..{year}-12-31"))

    def get_ratelimit_remaining(self) -> dict[str, Any]:
        """Get remaining rate limit requests."""
        response = self.session.get(f"{self.base_url}/rate_limit")
        response.raise_for_status()
        return cast(dict[str, Any], response.json())

    def wait_for_ratelimit(self) -> None:
        """Wait for rate limit reset."""
        ratelimit = self.get_ratelimit_remaining()
        wait = self._ratelimit_sleep_time(ratelimit)
        if wait is not None:
            sleep(wait)


class AsyncGHSAClient(_BaseGHSAClient):
    """Async client for querying GitHub Security Advisory database via REST API."""

    session: httpx.AsyncClient

    def _create_session(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(headers=self._headers, timeout=30.0)

    async def close(self) -> None:
        """Close the HTTP client session."""
        await self.session.aclose()

    async def __aenter__(self) -> "AsyncGHSAClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def _get_with_rate_limit_retry(
        self, url: str, *args: Any, **kwargs: Any
    ) -> httpx.Response:
        for _ in range(3):
            try:
                if self.blocking_rate_limit:
                    await self.wait_for_ratelimit()
                response = await self.session.get(url, *args, **kwargs)
                response.raise_for_status()
                return response
            except httpx.HTTPStatusError as e:
                if self._should_retry_rate_limit(e, url):
                    await asyncio.sleep(1)
                    continue
                raise

        raise RateLimitExceeded("Rate limit exceeded for advisory")

    async def get_advisory(self, ghsa_id: GHSA_ID) -> Advisory:
        url = f"{self.base_url}/advisories/{ghsa_id}"
        self.logger.debug(f"Requesting advisory from URL: {url}")
        try:
            response = await self._get_with_rate_limit_retry(url)
            return Advisory.model_validate(response.json())
        except httpx.HTTPError as e:
            self._log_advisory_error(ghsa_id, e)
            raise

    async def search_advisories(
        self, per_page: int = 100, strict: bool = True, **filters: Any
    ) -> AsyncGenerator[Advisory, None]:
        """Search for advisories with async pagination support.

        Args:
            per_page: Number of advisories per page (default: 100)
            strict: If True (default), raises ValidationError on invalid advisories.
                   If False, skips invalid advisories and continues.
            **filters: Additional filters to pass to the API (e.g., ecosystem, cwes)
        """
        url = f"{self.base_url}/advisories"
        params: dict[str, Any] | None = filters

        while True:
            response = await self._get_with_rate_limit_retry(url, params=params)
            advisories = response.json()

            if not advisories:
                break

            for advisory in self._validate_advisories(advisories, strict, self.logger):
                yield advisory

            next_url = self._parse_next_page_url(response.headers)
            if next_url is None:
                break
            url = next_url
            params = None  # Pagination URL already includes all params

    async def get_all_advisories_for_year(self, year: int) -> list[Advisory]:
        """Get all advisories for a given year."""
        return [
            advisory
            async for advisory in self.search_advisories(
                published=f"{year}-01-01..{year}-12-31"
            )
        ]

    async def get_ratelimit_remaining(self) -> dict[str, Any]:
        """Get remaining rate limit requests."""
        response = await self.session.get(f"{self.base_url}/rate_limit")
        response.raise_for_status()
        return cast(dict[str, Any], response.json())

    async def wait_for_ratelimit(self) -> None:
        """Wait for rate limit reset."""
        ratelimit = await self.get_ratelimit_remaining()
        wait = self._ratelimit_sleep_time(ratelimit)
        if wait is not None:
            await asyncio.sleep(wait)
