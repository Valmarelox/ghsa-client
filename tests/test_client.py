"""Tests for GHSA client."""

import logging
from unittest.mock import MagicMock, patch

import pytest

from ghsa_client import GHSA_ID, Ecosystem, GHSAClient


class TestGHSAClient:
    def test_initialization_without_token(self) -> None:
        """Test client initialization without GitHub token."""
        logger = logging.getLogger(__name__)
        client = GHSAClient(logger=logger)
        assert client.base_url == "https://api.github.com"
        assert "Authorization" not in client.session.headers

    def test_initialization_with_token(self) -> None:
        """Test client initialization with GitHub token."""
        logger = logging.getLogger(__name__)
        with patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            client = GHSAClient(logger=logger)
            assert client.session.headers["Authorization"] == "Bearer test-token"

    def test_initialization_with_custom_url(self) -> None:
        """Test client initialization with custom base URL."""
        logger = logging.getLogger(__name__)
        client = GHSAClient(logger=logger, base_url="https://custom.github.com")
        assert client.base_url == "https://custom.github.com"

    @patch("ghsa_client.client.requests.Session.get")
    def test_get_advisory_success(self, mock_get: MagicMock) -> None:
        """Test successful advisory retrieval."""
        logger = logging.getLogger(__name__)
        client = GHSAClient(logger=logger)

        # Mock rate limit response
        mock_rate_limit_response = MagicMock()
        mock_rate_limit_response.json.return_value = {
            "resources": {"core": {"remaining": 5000, "reset": 1234567890}}
        }
        mock_rate_limit_response.raise_for_status.return_value = None

        # Mock advisory response
        mock_advisory_response = MagicMock()
        mock_advisory_response.json.return_value = {
            "ghsa_id": "GHSA-gq96-8w38-hhj2",
            "summary": "Test advisory",
            "severity": "high",
            "published_at": "2024-01-01T00:00:00Z",
            "vulnerabilities": [],
        }
        mock_advisory_response.raise_for_status.return_value = None

        # Configure mock to return different responses for different URLs
        def side_effect(*args: object, **kwargs: object) -> MagicMock:
            url = str(args[0]) if args else ""
            if "rate_limit" in url:
                return mock_rate_limit_response
            else:
                return mock_advisory_response

        mock_get.side_effect = side_effect

        # Test
        ghsa_id = GHSA_ID("GHSA-gq96-8w38-hhj2")
        advisory = client.get_advisory(ghsa_id)

        assert advisory.ghsa_id.id == "GHSA-gq96-8w38-hhj2"
        assert advisory.summary == "Test advisory"
        assert advisory.severity == "high"

    @patch("ghsa_client.client.requests.Session.get")
    def test_search_advisories_pagination(self, mock_get: MagicMock) -> None:
        """Test search_advisories with pagination support."""
        logger = logging.getLogger(__name__)
        client = GHSAClient(logger=logger)

        # Mock rate limit response
        mock_rate_limit_response = MagicMock()
        mock_rate_limit_response.json.return_value = {
            "resources": {"core": {"remaining": 5000, "reset": 1234567890}}
        }
        mock_rate_limit_response.raise_for_status.return_value = None

        # Mock first page response
        mock_page1_response = MagicMock()
        mock_page1_response.json.return_value = [
            {
                "ghsa_id": "GHSA-gq96-8w38-hhj2",
                "summary": "Test advisory 1",
                "severity": "high",
                "published_at": "2024-01-01T00:00:00Z",
                "vulnerabilities": [],
            },
            {
                "ghsa_id": "GHSA-abc1-2def-3ghi",
                "summary": "Test advisory 2",
                "severity": "medium",
                "published_at": "2024-01-02T00:00:00Z",
                "vulnerabilities": [],
            },
        ]
        mock_page1_response.raise_for_status.return_value = None
        mock_page1_response.headers = {
            "link": '<https://api.github.com/advisories?page=2>; rel="next"'
        }

        # Mock second page response (empty)
        mock_page2_response = MagicMock()
        mock_page2_response.json.return_value = []
        mock_page2_response.raise_for_status.return_value = None
        mock_page2_response.headers = {}

        # Configure mock to return different responses for different URLs
        def side_effect(*args: object, **kwargs: object) -> MagicMock:
            url = str(args[0]) if args else ""
            if "rate_limit" in url:
                return mock_rate_limit_response
            elif "page=2" in url:
                return mock_page2_response
            else:
                return mock_page1_response

        mock_get.side_effect = side_effect

        # Test pagination
        advisories = list(client.search_advisories(ecosystem="pip", per_page=2))

        assert len(advisories) == 2
        assert advisories[0].ghsa_id.id == "GHSA-gq96-8w38-hhj2"
        assert advisories[0].summary == "Test advisory 1"
        assert advisories[1].ghsa_id.id == "GHSA-abc1-2def-3ghi"
        assert advisories[1].summary == "Test advisory 2"

    @patch("ghsa_client.client.requests.Session.get")
    def test_search_advisories_generator_behavior(self, mock_get: MagicMock) -> None:
        """Test that search_advisories returns a generator."""
        logger = logging.getLogger(__name__)
        client = GHSAClient(logger=logger)

        # Mock rate limit response
        mock_rate_limit_response = MagicMock()
        mock_rate_limit_response.json.return_value = {
            "resources": {"core": {"remaining": 5000, "reset": 1234567890}}
        }
        mock_rate_limit_response.raise_for_status.return_value = None

        # Mock empty response
        mock_response = MagicMock()
        mock_response.json.return_value = []
        mock_response.raise_for_status.return_value = None

        def side_effect(*args: object, **kwargs: object) -> MagicMock:
            url = str(args[0]) if args else ""
            if "rate_limit" in url:
                return mock_rate_limit_response
            else:
                return mock_response

        mock_get.side_effect = side_effect

        # Test that it returns a generator
        result = client.search_advisories(ecosystem="pip")
        assert hasattr(result, "__iter__")
        assert hasattr(result, "__next__")

        # Test that it yields no results when empty
        advisories = list(result)
        assert len(advisories) == 0

    def test_get_specific_advisory_real(self) -> None:
        """Test getting a specific real advisory (GHSA-8r8j-xvfj-36f9)."""
        logger = logging.getLogger(__name__)
        client = GHSAClient(logger=logger)

        # Test with a real GHSA ID that was reported as problematic
        ghsa_id = GHSA_ID("GHSA-8r8j-xvfj-36f9")
        advisory = client.get_advisory(ghsa_id)

        assert advisory.ghsa_id.id == "GHSA-8r8j-xvfj-36f9"
        assert advisory.summary == "Code injection in ymlref"
        assert advisory.severity == "critical"
        assert advisory.published_at == "2018-12-19T19:25:14Z"

    def test_get_advisory_http_error(self) -> None:
        """Test advisory retrieval with HTTP error."""
        import requests

        logger = logging.getLogger(__name__)
        http_error = requests.HTTPError()
        http_error.response = MagicMock()
        http_error.response.status_code = 404

        with patch.object(
            GHSAClient, "_get_with_rate_limit_retry", side_effect=http_error
        ):
            client = GHSAClient(logger=logger)
            with pytest.raises(requests.HTTPError):
                client.get_advisory(GHSA_ID("GHSA-test-1234-5678"))

    def test_search_advisories_success(self) -> None:
        """Test successful advisory search."""
        logger = logging.getLogger(__name__)

        mock_response = MagicMock()
        mock_response.json.return_value = [
            {
                "ghsa_id": "GHSA-test-1234-5678",
                "summary": "Test advisory 1",
                "severity": "HIGH",
                "published_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z",
                "vulnerabilities": [],
                "description": "Test description",
                "cwes": [],
                "references": [],
            }
        ]

        with patch.object(
            GHSAClient, "_get_with_rate_limit_retry", return_value=mock_response
        ):
            client = GHSAClient(logger=logger)
            advisories = client.search_advisories(
                ecosystem=Ecosystem.NPM.value, severity="HIGH"
            )

            advisory = next(advisories)
            assert advisory

    def test_get_all_advisories_for_year(self) -> None:
        """Test getting advisories for a specific year."""
        logger = logging.getLogger(__name__)
        with patch.object(GHSAClient, "search_advisories") as mock_search:
            client = GHSAClient(logger=logger)
            client.get_all_advisories_for_year(2023)

            mock_search.assert_called_once_with(published="2023-01-01..2023-12-31")

    def test_rate_limit_retry_success(self) -> None:
        """Test successful rate limit retry."""
        logger = logging.getLogger(__name__)
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None

        with patch.object(GHSAClient, "wait_for_ratelimit"):
            client = GHSAClient(logger=logger)
            with patch.object(client, "session") as mock_session:
                mock_session.get.return_value = mock_response

                result = client._get_with_rate_limit_retry(
                    "https://api.github.com/test"
                )

                assert result == mock_response
                mock_session.get.assert_called_once()

    def test_get_ratelimit_remaining(self) -> None:
        """Test getting rate limit information."""
        logger = logging.getLogger(__name__)
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "resources": {"core": {"remaining": 42, "reset": 1234567890}}
        }

        client = GHSAClient(logger=logger)
        with patch.object(client, "session") as mock_session:
            mock_session.get.return_value = mock_response

            result = client.get_ratelimit_remaining()

            assert result == mock_response.json.return_value
            mock_session.get.assert_called_once_with(
                "https://api.github.com/rate_limit"
            )

    def test_wait_for_ratelimit_no_wait(self) -> None:
        """Test rate limit wait when no wait is needed."""
        logger = logging.getLogger(__name__)
        mock_ratelimit_data = {
            "resources": {"core": {"remaining": 100, "reset": 1234567890}}
        }

        client = GHSAClient(logger=logger)
        with patch.object(
            client, "get_ratelimit_remaining", return_value=mock_ratelimit_data
        ):
            # Should not raise any exception
            client.wait_for_ratelimit()
