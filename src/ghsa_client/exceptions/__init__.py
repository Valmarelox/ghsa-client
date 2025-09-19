"""Exceptions specific to GHSA operations."""

from .rate_limit import RateLimitExceeded
from .cvss import InvalidCVSSError

__all__ = ["RateLimitExceeded", "InvalidCVSSError"]
