# GHSA Client

A Python client library for the GitHub Security Advisory (GHSA) API, providing structured access to security advisory data.

## Features

- **Type-safe models**: Full Pydantic models for GHSA data structures
- **Rate limiting**: Built-in rate limit handling and retry logic
- **Flexible queries**: Search advisories with various filters
- **Comprehensive data**: Access to all GHSA fields including CVSS scores, CWE mappings, and package information

## Installation

```bash
pip install ghsa-client
```

## Quick Start

```python
import logging
from ghsa_client import GHSAClient, GHSA_ID

# Set up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create client
client = GHSAClient(logger)

# Get a specific advisory
ghsa_id = GHSA_ID("GHSA-gq96-8w38-hhj2")
advisory = client.get_advisory(ghsa_id)

print(f"Advisory: {advisory.summary}")
print(f"Severity: {advisory.severity}")
print(f"CVSS Score: {advisory.cvss.score if advisory.cvss else 'N/A'}")
```

## Usage

### Authentication

The client automatically uses the `GITHUB_TOKEN` environment variable if available:

```bash
export GITHUB_TOKEN=your_github_token_here
```

### Getting an Advisory

```python
from ghsa_client import GHSAClient, GHSA_ID

client = GHSAClient(logger)
advisory = client.get_advisory(GHSA_ID("GHSA-gq96-8w38-hhj2"))

# Access advisory properties
print(advisory.summary)
print(advisory.severity)
print(advisory.published_at)
print(advisory.vulnerabilities)
```

### Searching Advisories

```python
# Search by ecosystem
advisories = client.search_advisories(ecosystem="npm")

# Search by severity
advisories = client.search_advisories(severity="high")

# Search by date range
advisories = client.search_advisories(published="2024-01-01..2024-12-31")

# Get all advisories for a year
advisories = client.get_all_advisories_for_year(2024)
```

### Rate Limiting

The client automatically handles GitHub's rate limits:

```python
# Check remaining rate limit
rate_limit = client.get_ratelimit_remaining()
print(f"Remaining requests: {rate_limit['resources']['core']['remaining']}")

# The client will automatically wait for rate limit reset when needed
```

## Models

### Advisory

The main model representing a GitHub Security Advisory:

```python
from ghsa_client import Advisory

advisory: Advisory = client.get_advisory(ghsa_id)

# Core properties
advisory.ghsa_id          # GHSA_ID object
advisory.cve_id           # Optional CVE_ID object
advisory.summary          # str
advisory.severity         # str
advisory.published_at     # str (ISO date)
advisory.description      # Optional[str]

# Vulnerability data
advisory.vulnerabilities  # List[Vulnerability]
advisory.affected_packages # List[Package] (computed property)

# CVSS data
advisory.cvss             # Optional[CVSS]
advisory.cwes             # Optional[List[str]]

# Repository information
advisory.source_code_location # Optional[str]
advisory.repository_url   # str (property, raises if not found)

# References
advisory.references       # List[str]
```

### GHSA_ID

Type-safe GHSA identifier with validation:

```python
from ghsa_client import GHSA_ID, InvalidGHSAIDError

try:
    ghsa_id = GHSA_ID("GHSA-gq96-8w38-hhj2")
    print(ghsa_id.id)  # "GHSA-gq96-8w38-hhj2"
except InvalidGHSAIDError as e:
    print(f"Invalid GHSA ID: {e}")
```

### CVE_ID

Type-safe CVE identifier with validation:

```python
from ghsa_client import CVE_ID

cve_id = CVE_ID("CVE-2024-12345")
print(cve_id.id)  # "CVE-2024-12345"
```


## Error Handling

The client raises specific exceptions for different error conditions:

```python
from ghsa_client import RateLimitExceeded, GHSAClient
import requests

try:
    advisory = client.get_advisory(ghsa_id)
except requests.HTTPError as e:
    if e.response.status_code == 404:
        print("Advisory not found")
    else:
        print(f"HTTP error: {e}")
except RateLimitExceeded as e:
    print(f"Rate limit exceeded: {e}")
except requests.RequestException as e:
    print(f"Network error: {e}")
```

## Development

### Setup

```bash
git clone https://github.com/auto-exploit/ghsa-client.git
cd ghsa-client
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
```

### Code Formatting

```bash
black .
isort .
```

### Type Checking

```bash
mypy src/ghsa_client
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or pull request on [GitHub](https://github.com/auto-exploit/ghsa-client).

## Changelog

See the [releases page](https://github.com/auto-exploit/ghsa-client/releases) for a history of changes.
