"""Exceptions specific to GHSA operations."""

from .cvss import InvalidCVSSError
from .rate_limit import RateLimitExceeded

__all__ = ["RateLimitExceeded", "InvalidCVSSError"]
