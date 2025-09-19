"""GitHub Security Advisory (GHSA) API client."""

import os
import re
import requests
import logging
from time import sleep, time
from typing import Any, Generator, Optional, cast
from .exceptions import RateLimitExceeded
from .models import Advisory, GHSA_ID


class GHSAClient:
    """Client for querying GitHub Security Advisory database via REST API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
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
        self.session = requests.Session()
        self.logger = logger
        self.blocking_rate_limit = blocking_rate_limit
        # Set up headers
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        elif GITHUB_TOKEN := os.getenv("GITHUB_TOKEN"):
            headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

        self.session.headers.update(headers)

    def _get_with_rate_limit_retry(
        self, url: str, *args: Any, **kwargs: Any
    ) -> requests.Response:
        for _ in range(3):
            try:
                if self.blocking_rate_limit:
                    self.wait_for_ratelimit()
                response = self.session.get(url, *args, **kwargs)
                response.raise_for_status()
                return response
            except requests.HTTPError as e:
                if e.response.status_code == 403 and e.response.text.startswith(
                    "rate limit exceeded"
                ):
                    sleep(1)
                    continue
                if e.response.status_code == 422:
                    self.logger.exception(f"Unprocessable entity error for URL: {url}. body: {e.response.text}")
                raise e

        raise RateLimitExceeded(f"Rate limit exceeded for advisory")

    def get_advisory(self, ghsa_id: GHSA_ID) -> Advisory:
        url = f"{self.base_url}/advisories/{ghsa_id}"
        self.logger.debug(f"Requesting advisory from URL: {url}")

        try:
            response = self._get_with_rate_limit_retry(url)
            return Advisory.model_validate(response.json())
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                self.logger.exception(f"Advisory {ghsa_id} not found")
            else:
                self.logger.exception(f"HTTP error retrieving advisory {ghsa_id}: {e}")
            raise
        except requests.RequestException:
            self.logger.exception(f"Network error retrieving advisory {ghsa_id}")
            raise

    def search_advisories(self, per_page: int = 100, **filters: Any) -> Generator[Advisory, None, None]:
        """Search for advisories with pagination support."""
        url = f"{self.base_url}/advisories"

        while True:
            response = self._get_with_rate_limit_retry(url, params=filters)
            advisories = response.json()

            if not advisories:
                break

            yield from (Advisory.model_validate(data) for data in advisories)
            if 'link' not in response.headers:
                break
            url_match = re.match(r'<(.*)>; rel="next"', response.headers['link'])
            if url_match is None:
                break
            url = url_match.group(1)

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
        # Only check rate limit if we have authentication
        if "Authorization" not in self.session.headers:
            return
            
        try:
            ratelimit = self.get_ratelimit_remaining()
            if ratelimit["resources"]["core"]["remaining"] > 0:
                return
            reset_time = ratelimit["resources"]["core"]["reset"]
            sleep(reset_time - time())
        except requests.HTTPError:
            # If we can't check rate limit, just continue
            pass
