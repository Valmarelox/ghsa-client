"""Tests for GHSA client (sync and async)."""

import inspect
import logging
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from ghsa_client import GHSA_ID, AsyncGHSAClient, Ecosystem, GHSAClient

RATE_LIMIT_OK = {"resources": {"core": {"remaining": 5000, "reset": 1234567890}}}


# --- Helpers ---


async def maybe_await(obj):
    """Await coroutines, pass through regular values."""
    if inspect.isawaitable(obj):
        return await obj
    return obj


async def collect(obj):
    """Collect sync or async iterable into a list."""
    if hasattr(obj, "__aiter__"):
        return [item async for item in obj]
    return list(obj)


def make_response(json_data, headers=None):
    """Create a mock HTTP response."""
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    resp.headers = headers or {}
    return resp


def url_router(routes, default=None):
    """Create a side_effect that dispatches by URL substring."""

    def side_effect(*args, **kwargs):
        url = str(args[0]) if args else ""
        for pattern, response in routes.items():
            if pattern in url:
                return response
        if default is not None:
            return default
        raise ValueError(f"No mock for URL: {url}")

    return side_effect


@contextmanager
def patched_session_get(client, side_effect):
    """Patch client.session.get, wrapping as async for AsyncGHSAClient."""
    if isinstance(client, AsyncGHSAClient):

        async def async_se(*args, **kwargs):
            return side_effect(*args, **kwargs)

        with patch.object(client.session, "get", side_effect=async_se):
            yield
    else:
        with patch.object(client.session, "get", side_effect=side_effect):
            yield


# --- Fixtures ---


@pytest.fixture(params=[GHSAClient, AsyncGHSAClient], ids=["sync", "async"])
def client_cls(request):
    return request.param


@pytest.fixture
def is_async(client_cls):
    return client_cls is AsyncGHSAClient


@pytest.fixture
def client(client_cls):
    return client_cls(logger=logging.getLogger("test"))


# --- Tests ---


class TestInit:
    def test_without_token(self, client) -> None:
        assert client.base_url == "https://api.github.com"
        assert "Authorization" not in client.session.headers

    def test_with_env_token(self, client_cls) -> None:
        with patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            c = client_cls(logger=logging.getLogger("test"))
            assert c.session.headers["Authorization"] == "Bearer test-token"

    def test_with_custom_url(self, client_cls) -> None:
        c = client_cls(
            logger=logging.getLogger("test"), base_url="https://custom.github.com"
        )
        assert c.base_url == "https://custom.github.com"


class TestContextManager:
    def test_sync(self) -> None:
        with GHSAClient(logger=logging.getLogger("test")) as c:
            assert isinstance(c, GHSAClient)

    @pytest.mark.asyncio
    async def test_async(self) -> None:
        async with AsyncGHSAClient(logger=logging.getLogger("test")) as c:
            assert isinstance(c, AsyncGHSAClient)


class TestGetAdvisory:
    @pytest.mark.asyncio
    async def test_success(self, client) -> None:
        routes = {
            "rate_limit": make_response(RATE_LIMIT_OK),
            "advisories": make_response(
                {
                    "ghsa_id": "GHSA-gq96-8w38-hhj2",
                    "summary": "Test advisory",
                    "severity": "high",
                    "published_at": "2024-01-01T00:00:00Z",
                    "vulnerabilities": [],
                }
            ),
        }
        with patched_session_get(client, url_router(routes)):
            advisory = await maybe_await(
                client.get_advisory(GHSA_ID("GHSA-gq96-8w38-hhj2"))
            )
            assert advisory.ghsa_id.id == "GHSA-gq96-8w38-hhj2"
            assert advisory.summary == "Test advisory"
            assert advisory.severity == "high"

    @pytest.mark.asyncio
    async def test_http_error(self, client_cls) -> None:
        resp = MagicMock(status_code=404)
        error = httpx.HTTPStatusError("Not found", request=MagicMock(), response=resp)
        with patch.object(client_cls, "_get_with_rate_limit_retry", side_effect=error):
            c = client_cls(logger=logging.getLogger("test"))
            with pytest.raises(httpx.HTTPStatusError):
                await maybe_await(c.get_advisory(GHSA_ID("GHSA-test-1234-5678")))

    @pytest.mark.integration
    def test_real_advisory(self) -> None:
        c = GHSAClient(logger=logging.getLogger("test"))
        advisory = c.get_advisory(GHSA_ID("GHSA-8r8j-xvfj-36f9"))
        assert advisory.ghsa_id.id == "GHSA-8r8j-xvfj-36f9"
        assert advisory.summary == "Code injection in ymlref"
        assert advisory.severity == "critical"
        assert advisory.published_at == "2018-12-19T19:25:14Z"


class TestSearchAdvisories:
    @pytest.mark.asyncio
    async def test_pagination(self, client) -> None:
        page1 = make_response(
            [
                {
                    "ghsa_id": "GHSA-gq96-8w38-hhj2",
                    "summary": "Advisory 1",
                    "severity": "high",
                    "published_at": "2024-01-01T00:00:00Z",
                    "vulnerabilities": [],
                },
                {
                    "ghsa_id": "GHSA-abc1-2def-3ghi",
                    "summary": "Advisory 2",
                    "severity": "medium",
                    "published_at": "2024-01-02T00:00:00Z",
                    "vulnerabilities": [],
                },
            ],
            headers={"link": '<https://api.github.com/advisories?page=2>; rel="next"'},
        )
        routes = {
            "rate_limit": make_response(RATE_LIMIT_OK),
            "page=2": make_response([]),
        }
        with patched_session_get(client, url_router(routes, default=page1)):
            advisories = await collect(
                client.search_advisories(ecosystem="pip", per_page=2)
            )
            assert len(advisories) == 2
            assert advisories[0].ghsa_id.id == "GHSA-gq96-8w38-hhj2"
            assert advisories[1].ghsa_id.id == "GHSA-abc1-2def-3ghi"

    @pytest.mark.asyncio
    async def test_generator_protocol(self, client, is_async) -> None:
        routes = {"rate_limit": make_response(RATE_LIMIT_OK)}
        with patched_session_get(client, url_router(routes, default=make_response([]))):
            result = client.search_advisories(ecosystem="pip")
            if is_async:
                assert hasattr(result, "__aiter__")
                assert hasattr(result, "__anext__")
            else:
                assert hasattr(result, "__iter__")
                assert hasattr(result, "__next__")
            assert await collect(result) == []

    @pytest.mark.asyncio
    async def test_success(self, client_cls) -> None:
        mock_resp = make_response(
            [
                {
                    "ghsa_id": "GHSA-test-1234-5678",
                    "summary": "Test advisory",
                    "severity": "HIGH",
                    "published_at": "2023-01-01T00:00:00Z",
                    "vulnerabilities": [],
                }
            ]
        )
        with patch.object(
            client_cls, "_get_with_rate_limit_retry", return_value=mock_resp
        ):
            c = client_cls(logger=logging.getLogger("test"))
            advisories = await collect(
                c.search_advisories(ecosystem=Ecosystem.NPM.value, severity="HIGH")
            )
            assert len(advisories) == 1


class TestGetAllAdvisoriesForYear:
    @pytest.mark.asyncio
    async def test_calls_search(self, client_cls, is_async) -> None:
        with patch.object(client_cls, "search_advisories") as mock_search:
            if is_async:

                async def empty_gen(*a, **kw):
                    return
                    yield  # type: ignore[misc]

                mock_search.return_value = empty_gen()

            c = client_cls(logger=logging.getLogger("test"))
            await maybe_await(c.get_all_advisories_for_year(2023))
            mock_search.assert_called_once_with(published="2023-01-01..2023-12-31")


class TestRateLimit:
    @pytest.mark.asyncio
    async def test_retry_success(self, client_cls, is_async) -> None:
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None

        with patch.object(client_cls, "wait_for_ratelimit"):
            c = client_cls(logger=logging.getLogger("test"))
            mock_session = AsyncMock() if is_async else MagicMock()
            mock_session.get.return_value = mock_response
            c.session = mock_session

            result = await maybe_await(
                c._get_with_rate_limit_retry("https://api.github.com/test")
            )
            assert result == mock_response
            mock_session.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_remaining(self, client_cls, is_async) -> None:
        expected = {"resources": {"core": {"remaining": 42, "reset": 1234567890}}}
        mock_resp = make_response(expected)

        c = client_cls(logger=logging.getLogger("test"))
        mock_session = AsyncMock() if is_async else MagicMock()
        mock_session.get.return_value = mock_resp
        c.session = mock_session

        result = await maybe_await(c.get_ratelimit_remaining())
        assert result == expected
        mock_session.get.assert_called_once_with("https://api.github.com/rate_limit")

    @pytest.mark.asyncio
    async def test_wait_no_wait_needed(self, client) -> None:
        data = {"resources": {"core": {"remaining": 100, "reset": 1234567890}}}
        with patch.object(client, "get_ratelimit_remaining", return_value=data):
            await maybe_await(client.wait_for_ratelimit())
