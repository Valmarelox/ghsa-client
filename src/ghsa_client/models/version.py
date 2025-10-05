"""Semantic version models using the semver package."""

import re
from enum import Enum
from semver import VersionInfo
from packaging.version import Version as PyPIVersion
from functools import total_ordering
from typing import Any, Optional
from pydantic import BaseModel


class VersionFormat(Enum):
    """Version format enumeration."""
    
    SEMVER = "semver"
    PYPI = "pypi"
    UNKNOWN = "unknown"


@total_ordering
class SemanticVersion(BaseModel):
    """Enhanced semantic version supporting both semver and PyPI formats.
    
    This class can parse and convert between semantic versioning (semver) and 
    PyPI versioning (PEP 440) formats. It automatically detects the format
    and provides conversion methods.
    
    Attributes:
        semver_parts: Internal semver representation as a dictionary
        original_version: The original version string that was parsed
        prefix: Any prefix (like 'v' or 'V') that was stripped
        version_format: The detected format (SEMVER, PYPI, or UNKNOWN)
    """

    semver_parts: dict[str, Any]
    original_version: str
    prefix: str = ""
    version_format: VersionFormat = VersionFormat.SEMVER

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

        # Error-driven approach: try parsers in order until one works
        # 1. Try semver first (most common)
        try:
            return cls._parse_semver(version, prefix, original_version)
        except ValueError:
            pass
        
        # 2. Try PyPI format
        try:
            return cls._parse_pypi(version, prefix, original_version)
        except ValueError:
            pass
        
        # 3. Fallback to legacy parsing
        return cls._parse_legacy(version, prefix, original_version)

    @classmethod
    def _parse_pypi(cls, version: str, prefix: str, original_version: str) -> "SemanticVersion":
        """Parse PyPI version and convert to semver."""
        try:
            pypi_version = PyPIVersion(version)
            
            # Convert PyPI to semver format
            major = pypi_version.major
            minor = pypi_version.minor or 0
            patch = pypi_version.micro or 0
            
            # Handle pre-release
            prerelease = None
            if pypi_version.pre:
                pre_type, pre_num = pypi_version.pre
                # Convert PyPI pre-release to semver format
                if pre_type == 'a':
                    prerelease = f"alpha.{pre_num}"
                elif pre_type == 'b':
                    prerelease = f"beta.{pre_num}"
                elif pre_type == 'rc':
                    prerelease = f"rc.{pre_num}"
                else:
                    prerelease = f"{pre_type}.{pre_num}"
            
            # Handle build metadata (dev releases become build metadata)
            build = None
            if pypi_version.dev:
                build = f"dev.{pypi_version.dev}"
            
            # Handle post-release (convert to build metadata)
            if pypi_version.post:
                if build:
                    build = f"{build}.post{pypi_version.post}"
                else:
                    build = f"post.{pypi_version.post}"
            
            # Create semver version
            semver_version = VersionInfo(
                major=major,
                minor=minor,
                patch=patch,
                prerelease=prerelease,
                build=build
            )
            
            return cls(
                semver_parts=semver_version.to_dict(),
                prefix=prefix,
                original_version=original_version,
                version_format=VersionFormat.PYPI,
            )
        except Exception as e:
            raise ValueError(f"Invalid PyPI version: {version}") from e

    @classmethod
    def _parse_semver(cls, version: str, prefix: str, original_version: str) -> "SemanticVersion":
        """Parse semver version."""
        try:
            semver_version = VersionInfo.parse(version, optional_minor_and_patch=True)
            return cls(
                semver_parts=semver_version.to_dict(),
                prefix=prefix,
                original_version=original_version,
                version_format=VersionFormat.SEMVER,
            )
        except ValueError as e:
            raise ValueError(f"Invalid semver version: {version}") from e

    @classmethod
    def _parse_legacy(cls, version: str, prefix: str, original_version: str) -> "SemanticVersion":
        """Legacy parsing for backward compatibility."""
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
                version_format=VersionFormat.UNKNOWN,
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
        return self.version_info.match(str(predicate))

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

    def to_pypi(self) -> str:
        """Convert to PyPI version format."""
        version_info = self.version_info
        
        # Start with basic version
        pypi_version = f"{version_info.major}.{version_info.minor}.{version_info.patch}"
        
        # Handle pre-release
        if version_info.prerelease:
            prerelease = version_info.prerelease
            # Convert semver pre-release to PyPI format
            if prerelease.startswith("alpha."):
                pypi_version += f"a{prerelease.split('.')[1]}"
            elif prerelease.startswith("beta."):
                pypi_version += f"b{prerelease.split('.')[1]}"
            elif prerelease.startswith("rc."):
                pypi_version += f"rc{prerelease.split('.')[1]}"
            else:
                # Keep as-is for other formats
                pypi_version += f"-{prerelease}"
        
        # Handle build metadata (convert to dev release or post release)
        if version_info.build:
            build = version_info.build
            if build.startswith("dev."):
                pypi_version += f".dev{build.split('.')[1]}"
            elif build.startswith("post."):
                pypi_version += f".post{build.split('.')[1]}"
            else:
                pypi_version += f"+{build}"
        
        return pypi_version

    def to_semver(self) -> str:
        """Convert to semver format."""
        return str(self.version_info)


class VersionPredicate(BaseModel):
    """Version predicate for comparison operations.
    
    Supports both semver and PyPI version formats with automatic detection
    and conversion capabilities.
    
    Attributes:
        operator: Comparison operator (>=, <=, >, <, ==, !=)
        version: Version string to compare against
        version_format: Detected format of the version string
    """

    operator: str
    version: str
    version_format: VersionFormat = VersionFormat.SEMVER

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

        match = re.match(r"^(!=|<=|>=|<|>|==|=)\s*(.*)", s)
        if not match:
            raise ValueError("Invalid version predicate format")

        operator = match.group(1)
        version_str = match.group(2)

        if operator == "=":
            operator = "=="

        # Parse and normalize the version to ensure consistency
        try:
            normalized_version = SemanticVersion.parse(version_str)
            normalized_version_str = str(normalized_version.version_info)
            
            return cls(operator=operator, version=normalized_version_str, version_format=normalized_version.version_format)
        except ValueError as e:
            raise ValueError(f"Invalid version predicate format: {e}") from e

    def __str__(self) -> str:
        return f"{self.operator}{str(self.version)}"

    @property
    def semver(self) -> SemanticVersion:
        return SemanticVersion.parse(self.version)

    def to_pypi_predicate(self) -> str:
        """Convert predicate to PyPI format."""
        semver_version = self.semver
        pypi_version = semver_version.to_pypi()
        return f"{self.operator}{pypi_version}"

    def to_semver_predicate(self) -> str:
        """Convert predicate to semver format."""
        semver_version = self.semver
        semver_version_str = semver_version.to_semver()
        return f"{self.operator}{semver_version_str}"
