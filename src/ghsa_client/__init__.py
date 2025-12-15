"""GitHub Security Advisory (GHSA) client library.

A Python library for interacting with the GitHub Security Advisory API,
providing structured access to security advisory data.

Main exports:
- GHSAClient: Main client for interacting with the GHSA API
- Advisory: Main model representing a GitHub Security Advisory
- GHSA_ID: Type-safe GHSA identifier with validation
- CVE_ID: Type-safe CVE identifier with validation
- Vulnerability: Model representing a vulnerability within an advisory
- CVSS: Model representing CVSS scoring information
- RateLimitExceeded: Exception raised when API rate limit is exceeded
"""

from importlib.metadata import version

from .client import GHSAClient
from .exceptions import RateLimitExceeded
from .models import CVE_ID, CVSS, GHSA_ID, Advisory, Ecosystem, Vulnerability

__version__ = version("ghsa-client")
__all__ = [
    "GHSAClient",
    "Advisory",
    "GHSA_ID",
    "CVE_ID",
    "Vulnerability",
    "CVSS",
    "Ecosystem",
    "RateLimitExceeded",
]
