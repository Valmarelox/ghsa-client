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
        """Parse version string using error-driven approach."""
        original_version = version
        prefix = ""
        
        # Extract prefix if present
        if match := re.match("^((?:.+@)?v|V)(.*)", version):
            prefix = match.group(1)
            version = match.group(2)

        # Try parsers in order of preference
        for parser in [cls._parse_semver, cls._parse_pypi, cls._parse_legacy]:
            try:
                return parser(version, prefix, original_version)
            except ValueError:
                continue
        
        raise ValueError(f"Invalid version: {version}")

    @classmethod
    def _parse_pypi(cls, version: str, prefix: str, original_version: str) -> "SemanticVersion":
        """Parse PyPI version and convert to semver."""
        pypi_version = PyPIVersion(version)
        
        # Convert PyPI components to semver
        prerelease = cls._convert_pypi_prerelease(pypi_version.pre)
        build = cls._convert_pypi_build(pypi_version.dev, pypi_version.post)
        
        semver_version = VersionInfo(
            major=pypi_version.major,
            minor=pypi_version.minor or 0,
            patch=pypi_version.micro or 0,
            prerelease=prerelease,
            build=build
        )
        
        return cls(
            semver_parts=semver_version.to_dict(),
            prefix=prefix,
            original_version=original_version,
            version_format=VersionFormat.PYPI,
        )

    @classmethod
    def _convert_pypi_prerelease(cls, pre: Optional[tuple]) -> Optional[str]:
        """Convert PyPI prerelease to semver format."""
        if not pre:
            return None
        
        pre_type, pre_num = pre
        pre_type_map = {'a': 'alpha', 'b': 'beta', 'rc': 'rc'}
        return f"{pre_type_map.get(pre_type, pre_type)}.{pre_num}"

    @classmethod
    def _convert_pypi_build(cls, dev: Optional[int], post: Optional[int]) -> Optional[str]:
        """Convert PyPI dev/post to semver build metadata."""
        parts = []
        if dev:
            parts.append(f"dev.{dev}")
        if post:
            parts.append(f"post.{post}")
        return ".".join(parts) if parts else None

    @classmethod
    def _parse_semver(cls, version: str, prefix: str, original_version: str) -> "SemanticVersion":
        """Parse semver version."""
        semver_version = VersionInfo.parse(version, optional_minor_and_patch=True)
        return cls(
            semver_parts=semver_version.to_dict(),
            prefix=prefix,
            original_version=original_version,
            version_format=VersionFormat.SEMVER,
        )

    @classmethod
    def _parse_legacy(cls, version: str, prefix: str, original_version: str) -> "SemanticVersion":
        """Legacy parsing for backward compatibility."""
        # Handle 4-part versions by converting to semver format
        if version.count(".") > 2:
            major, minor, patch, release = version.split(".", maxsplit=3)
            version = f"{major}.{minor}.{patch}-{release}"

        semver_version = VersionInfo.parse(version, optional_minor_and_patch=True)
        return cls(
            semver_parts=semver_version.to_dict(),
            prefix=prefix,
            original_version=original_version,
            version_format=VersionFormat.UNKNOWN,
        )

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
        pypi_version = f"{version_info.major}.{version_info.minor}.{version_info.patch}"
        
        # Add prerelease
        if version_info.prerelease:
            pypi_version += self._convert_semver_prerelease_to_pypi(version_info.prerelease)
        
        # Add build metadata
        if version_info.build:
            pypi_version += self._convert_semver_build_to_pypi(version_info.build)
        
        return pypi_version

    def _convert_semver_prerelease_to_pypi(self, prerelease: str) -> str:
        """Convert semver prerelease to PyPI format."""
        if prerelease.startswith("alpha."):
            return f"a{prerelease.split('.')[1]}"
        elif prerelease.startswith("beta."):
            return f"b{prerelease.split('.')[1]}"
        elif prerelease.startswith("rc."):
            return f"rc{prerelease.split('.')[1]}"
        else:
            return f"-{prerelease}"

    def _convert_semver_build_to_pypi(self, build: str) -> str:
        """Convert semver build metadata to PyPI format."""
        if build.startswith("dev."):
            return f".dev{build.split('.')[1]}"
        elif build.startswith("post."):
            return f".post{build.split('.')[1]}"
        else:
            return f"+{build}"

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
