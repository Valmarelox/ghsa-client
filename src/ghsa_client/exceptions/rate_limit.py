"""Rate limit exception for GHSA API operations."""


class RateLimitExceeded(Exception):
    """Raised when API rate limit is exceeded."""

    pass
