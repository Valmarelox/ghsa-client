"""Semantic version models using the semver package."""

import re
from semver import VersionInfo
from functools import total_ordering
from typing import Any
from pydantic import BaseModel


@total_ordering
class SemanticVersion(BaseModel):
    """Semantic version using the semver package."""

    semver_parts: dict[str, Any]
    original_version: str
    prefix: str = ""

    @property
    def installable_version(self) -> str:
        return (
            self.original_version[len(self.prefix) :]
            if self.original_version
            else str(self)
        )

    @classmethod
    def parse(cls, version: str) -> "SemanticVersion":
        # Extract prefix if present
        original_version = version
        prefix = ""
        match = re.match("^((?:.+@)?v|V)(.*)", version)
        if match:
            prefix = match.group(1)
            version = match.group(2)

        # TODO: Why is it here?
        if version.count(".") > 2:
            major, minor, patch, release = version.split(".", maxsplit=3)
            version = f"{major}.{minor}.{patch}-{release}"

        try:
            semver_version = VersionInfo.parse(version, optional_minor_and_patch=True)
            return cls(
                semver_parts=semver_version.to_dict(),
                prefix=prefix,
                original_version=original_version,
            )
        except ValueError as e:
            raise ValueError(f"Invalid version: {version}") from e

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SemanticVersion):
            raise NotImplementedError
        return self.version_info == other.version_info

    def __lt__(self, other: "SemanticVersion") -> bool:
        return self.version_info < other.version_info

    def __repr__(self) -> str:
        return f'SemanticVersion("{str(self)}")'

    def __str__(self) -> str:
        version_str = str(self.version_info)
        if self.prefix:
            return f"{self.prefix}{version_str}"
        return version_str

    def matches_predicate(self, predicate: "VersionPredicate") -> bool:
        """Check if this version matches a version predicate."""
        return self.version_info.match(str(predicate.semver))

    @property
    def variations(self) -> list[str]:
        """Get all variations of the version."""
        variations = [str(self.version_info)]

        if self.original_version:
            variations.append(self.original_version)

        if self.prefix:
            variations.append(str(self.version_info))

        return variations

    @property
    def version_info(self) -> VersionInfo:
        return VersionInfo(**self.semver_parts)


class VersionPredicate(BaseModel):
    """Version predicate for comparison operations."""

    operator: str
    version: str

    def __repr__(self) -> str:
        return f'VersionPredicate("{str(self)}")'

    def operator_to_symbol(self) -> str:
        """Convert operator to method name."""
        operator_map = {
            "<": "__lt__",
            "<=": "__le__",
            ">": "__gt__",
            ">=": "__ge__",
            "!=": "__ne__",
            "==": "__eq__",
        }
        if self.operator not in operator_map:
            raise ValueError(f"Invalid operator: {self.operator}")
        return operator_map[self.operator]

    @classmethod
    def from_str(cls, s: str) -> "VersionPredicate":
        """Parse version predicate from string."""
        s = s.strip()

        match = re.match(r"^(!=|<=|>=|<|>|=|==)\s*(.*)", s)
        if not match:
            raise ValueError("Invalid version predicate format")

        operator = match.group(1)
        version_str = match.group(2)

        if operator == "=":
            operator = "=="

        # Normalize version formats that don't follow strict SemVer
        # Handle formats like "6.0.0a1" -> "6.0.0-a1"
        try:
            return cls(operator=operator, version=version_str)
        except ValueError as e:
            raise ValueError(f"Invalid version predicate format: {e}") from e

    def __str__(self) -> str:
        return f"{self.operator}{str(self.version)}"

    @property
    def semver(self) -> SemanticVersion:
        return SemanticVersion.parse(self.version)
