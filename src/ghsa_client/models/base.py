"""Base models for GHSA operations."""

import re
from typing import ClassVar, Optional, Any, List
from pydantic import BaseModel, field_validator


class CVE_ID(BaseModel):
    """Strongly-typed CVE identifier with validation.
    CVE IDs follow the format: CVE-YYYY-NNNN+, where NNNN can be 4 or more digits.
    """

    id: str

    PATTERN: ClassVar[re.Pattern] = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

    def __init__(self, id: Optional[str] = None, **data: Any) -> None:
        if id is not None:
            data["id"] = id
        elif "id" not in data:
            raise ValueError("CVE ID cannot be None")
        super().__init__(**data)

    @field_validator("id", mode="before")
    @classmethod
    def validate_id(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError(
                f"CVE ID must be a string, got {type(value).__name__}"
            )
        normalized = value.strip()
        if not normalized:
            raise ValueError("CVE ID cannot be empty")
        if not cls.PATTERN.match(normalized):
            raise ValueError(
                f"Invalid CVE ID format: '{normalized}'. Expected CVE-YYYY-NNNN (e.g., CVE-2024-12345)"
            )
        # Normalize to upper-case prefix and keep the rest as-is
        parts = normalized.split("-", 2)
        return f"CVE-{parts[1]}-{parts[2]}"

    def __str__(self) -> str:
        return self.id

    def __repr__(self) -> str:
        return f"CVE_ID('{self.id}')"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, CVE_ID):
            return self.id == other.id
        if not isinstance(other, str):
            return False
        try:
            other_cve = CVE_ID(id=other)
            return self.id == other_cve.id
        except ValueError:
            return False

    def __hash__(self) -> int:
        return hash(self.id)


class CVSSVector(BaseModel):
    """CVSS vector representation."""
    vector: str


class CVSS(BaseModel):
    """CVSS score representation."""
    string: Optional[str] = None
    score: Optional[float] = None
    vector: Optional[CVSSVector] = None


class Package(BaseModel):
    """Package representation."""
    name: str
    ecosystem: str


class VersionPredicate(BaseModel):
    """Version predicate for vulnerability ranges."""
    predicate: str
    
    @classmethod
    def from_str(cls, predicate_str: str) -> "VersionPredicate":
        """Create a VersionPredicate from a string."""
        return cls(predicate=predicate_str)
    
    def __str__(self) -> str:
        return self.predicate


class Vulnerability(BaseModel):
    """Represents a vulnerability within an advisory."""

    package: Package
    vulnerable_version_range: List[VersionPredicate] = []
    first_patched_version: Optional[str] = None

    @field_validator("vulnerable_version_range", mode="before")
    @classmethod
    def parse_vulnerable_version_range(cls, v: Any) -> List[VersionPredicate]:
        if not isinstance(v, str):
            raise ValueError(f"Invalid vulnerable version range: {v}")
        # Handle single predicate string
        if "," not in v:
            return [VersionPredicate.from_str(v)]
        # Handle comma-separated predicates
        return [
            VersionPredicate.from_str(predicate.strip()) for predicate in v.split(",")
        ]

    def __str__(self) -> str:
        patched = (
            f" → {self.first_patched_version}"
            if self.first_patched_version is not None
            else ""
        )
        version_range_str = (
            "[" + ", ".join(str(pred) for pred in self.vulnerable_version_range) + "]"
        )
        return f"{self.package}: {version_range_str}{patched}"

    def __repr__(self) -> str:
        version_range_str = (
            "[" + ", ".join(str(pred) for pred in self.vulnerable_version_range) + "]"
        )
        return (
            f"Vulnerability(package={self.package!r}, "
            f"vulnerable_version_range={version_range_str}, "
            f"first_patched_version={self.first_patched_version!r})"
        )


class GitCommit(BaseModel):
    """Git commit representation."""
    sha: str
    message: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None
