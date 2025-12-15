"""Tests for GHSA models."""

import pytest
from pydantic import ValidationError

from ghsa_client import GHSA_ID, Advisory, Ecosystem
from ghsa_client.models import (
    CVE_ID,
    InvalidGHSAIDError,
    Package,
    Vulnerability,
)


class TestGHSA_ID:
    def test_valid_ghsa_id(self) -> None:
        """Test valid GHSA ID creation."""
        ghsa_id = GHSA_ID("GHSA-gq96-8w38-hhj2")
        assert ghsa_id.id == "GHSA-gq96-8w38-hhj2"

    def test_ghsa_id_validation_multiple_formats(self) -> None:
        """Test GHSA ID validation with multiple valid formats."""
        valid_ids = [
            "GHSA-1234-5678-90ab",
            "GHSA-abcd-efgh-ijkl",
            "GHSA-xxxx-yyyy-zzzz",
        ]

        for valid_id in valid_ids:
            ghsa = GHSA_ID(valid_id)
            assert str(ghsa) == valid_id.upper()

    def test_invalid_ghsa_id_format(self) -> None:
        """Test invalid GHSA ID format raises error."""
        with pytest.raises(InvalidGHSAIDError):
            GHSA_ID("invalid-id")

    def test_invalid_ghsa_id_multiple_formats(self) -> None:
        """Test GHSA ID validation with various invalid inputs."""
        invalid_ids = [
            "invalid-format",
            "GHSA-12345-678-90ab",  # wrong length
            "GHSA-123-5678-90ab",  # wrong length
            "",
            "GHSA-",
        ]

        for invalid_id in invalid_ids:
            with pytest.raises((ValueError, InvalidGHSAIDError)):
                GHSA_ID(invalid_id)

    def test_ghsa_id_string_conversion(self) -> None:
        """Test GHSA ID string conversion."""
        ghsa_id = GHSA_ID("GHSA-gq96-8w38-hhj2")
        assert str(ghsa_id) == "GHSA-gq96-8w38-hhj2"

    def test_ghsa_string_formatting(self) -> None:
        """Test GHSA string formatting is consistent."""
        ghsa = GHSA_ID("GHSA-1234-5678-90ab")
        assert str(ghsa) == "GHSA-1234-5678-90ab"
        assert repr(ghsa) == "GHSA_ID('GHSA-1234-5678-90ab')"

    def test_ghsa_id_equality(self) -> None:
        """Test GHSA ID equality."""
        ghsa_id1 = GHSA_ID("GHSA-gq96-8w38-hhj2")
        ghsa_id2 = GHSA_ID("GHSA-gq96-8w38-hhj2")
        assert ghsa_id1 == ghsa_id2
        assert ghsa_id1 == "GHSA-gq96-8w38-hhj2"

    def test_ghsa_equality_and_hash(self) -> None:
        """Test GHSA equality comparison and hashing."""
        ghsa1 = GHSA_ID("GHSA-1234-5678-90ab")
        ghsa2 = GHSA_ID("GHSA-1234-5678-90ab")
        ghsa3 = GHSA_ID("GHSA-abcd-efgh-ijkl")

        assert ghsa1 == ghsa2
        assert ghsa1 != ghsa3
        assert hash(ghsa1) == hash(ghsa2)


class TestCVE_ID:
    def test_valid_cve_id(self) -> None:
        """Test valid CVE ID creation."""
        cve_id = CVE_ID("CVE-2024-12345")
        assert cve_id.id == "CVE-2024-12345"

    def test_cve_id_validation_multiple_formats(self) -> None:
        """Test CVE ID validation with multiple valid formats."""
        valid_ids = [
            "CVE-2023-1234",
            "CVE-2024-56789",
            "CVE-1999-0001",
        ]

        for valid_id in valid_ids:
            cve = CVE_ID(valid_id)
            assert str(cve) == valid_id

    def test_invalid_cve_id_format(self) -> None:
        """Test invalid CVE ID format raises error."""
        with pytest.raises(ValueError):
            CVE_ID("invalid-id")

    def test_cve_id_string_conversion(self) -> None:
        """Test CVE ID string conversion."""
        cve_id = CVE_ID("CVE-2024-12345")
        assert str(cve_id) == "CVE-2024-12345"

    def test_cve_string_formatting(self) -> None:
        """Test CVE string formatting is consistent."""
        cve = CVE_ID("CVE-2023-1234")
        assert str(cve) == "CVE-2023-1234"


class TestPackage:
    def test_package_with_ecosystem_enum(self) -> None:
        """Test Package creation with Ecosystem enum."""
        package = Package(name="test-package", ecosystem=Ecosystem.NPM)
        assert package.name == "test-package"
        assert package.ecosystem == Ecosystem.NPM
        assert isinstance(package.ecosystem, Ecosystem)

    def test_package_with_ecosystem_string(self) -> None:
        """Test Package creation with ecosystem as string (simulating API response)."""
        package = Package(name="test-package", ecosystem="npm")
        assert package.name == "test-package"
        assert package.ecosystem == Ecosystem.NPM
        assert isinstance(package.ecosystem, Ecosystem)

    def test_package_with_different_ecosystems(self) -> None:
        """Test Package creation with different ecosystem values."""
        ecosystems = ["pip", "npm", "composer", "maven", "rubygems", "cargo", "go"]
        for eco_str in ecosystems:
            package = Package(name="test-package", ecosystem=eco_str)
            assert isinstance(package.ecosystem, Ecosystem)
            assert package.ecosystem.value == eco_str

    def test_package_invalid_ecosystem(self) -> None:
        """Test Package creation with invalid ecosystem raises error."""
        with pytest.raises(ValidationError):
            Package(name="test-package", ecosystem="invalid-ecosystem")

    def test_package_equality(self) -> None:
        """Test Package equality comparison."""
        package1 = Package(name="test-package", ecosystem=Ecosystem.NPM)
        package2 = Package(name="test-package", ecosystem="npm")
        package3 = Package(name="test-package", ecosystem=Ecosystem.PIP)

        assert package1 == package2
        assert package1 != package3


class TestAdvisory:
    def test_advisory_creation(self) -> None:
        """Test advisory model creation."""
        ghsa_id = GHSA_ID("GHSA-gq96-8w38-hhj2")
        package = Package(name="test-package", ecosystem=Ecosystem.NPM)
        vulnerability = Vulnerability(package=package)

        advisory = Advisory(
            ghsa_id=ghsa_id,
            summary="Test advisory",
            severity="high",
            published_at="2024-01-01T00:00:00Z",
            vulnerabilities=[vulnerability],
        )

        assert advisory.ghsa_id == ghsa_id
        assert advisory.summary == "Test advisory"
        assert advisory.severity == "high"
        assert len(advisory.vulnerabilities) == 1

    def test_advisory_has_cve_property(self) -> None:
        """Test advisory has_cve property."""
        ghsa_id = GHSA_ID("GHSA-gq96-8w38-hhj2")
        package = Package(name="test-package", ecosystem=Ecosystem.NPM)
        vulnerability = Vulnerability(package=package)

        # Advisory without CVE
        advisory = Advisory(
            ghsa_id=ghsa_id,
            summary="Test advisory",
            severity="high",
            published_at="2024-01-01T00:00:00Z",
            vulnerabilities=[vulnerability],
        )
        assert not advisory.has_cve

        # Advisory with CVE
        advisory.cve_id = CVE_ID("CVE-2024-12345")
        assert advisory.has_cve
