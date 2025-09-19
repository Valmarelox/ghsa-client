"""Tests for GHSA models."""

import pytest
from ghsa_client import GHSA_ID, Advisory
from ghsa_client.models import CVE_ID, InvalidGHSAIDError, Package, Vulnerability, VersionPredicate


class TestGHSA_ID:
    def test_valid_ghsa_id(self) -> None:
        """Test valid GHSA ID creation."""
        ghsa_id = GHSA_ID("GHSA-gq96-8w38-hhj2")
        assert ghsa_id.id == "GHSA-gq96-8w38-hhj2"
    
    def test_invalid_ghsa_id_format(self) -> None:
        """Test invalid GHSA ID format raises error."""
        with pytest.raises(InvalidGHSAIDError):
            GHSA_ID("invalid-id")
    
    def test_ghsa_id_string_conversion(self) -> None:
        """Test GHSA ID string conversion."""
        ghsa_id = GHSA_ID("GHSA-gq96-8w38-hhj2")
        assert str(ghsa_id) == "GHSA-gq96-8w38-hhj2"
    
    def test_ghsa_id_equality(self) -> None:
        """Test GHSA ID equality."""
        ghsa_id1 = GHSA_ID("GHSA-gq96-8w38-hhj2")
        ghsa_id2 = GHSA_ID("GHSA-gq96-8w38-hhj2")
        assert ghsa_id1 == ghsa_id2
        assert ghsa_id1 == "GHSA-gq96-8w38-hhj2"


class TestCVE_ID:
    def test_valid_cve_id(self) -> None:
        """Test valid CVE ID creation."""
        cve_id = CVE_ID("CVE-2024-12345")
        assert cve_id.id == "CVE-2024-12345"
    
    def test_invalid_cve_id_format(self) -> None:
        """Test invalid CVE ID format raises error."""
        with pytest.raises(ValueError):
            CVE_ID("invalid-id")
    
    def test_cve_id_string_conversion(self) -> None:
        """Test CVE ID string conversion."""
        cve_id = CVE_ID("CVE-2024-12345")
        assert str(cve_id) == "CVE-2024-12345"


class TestAdvisory:
    def test_advisory_creation(self) -> None:
        """Test advisory model creation."""
        ghsa_id = GHSA_ID("GHSA-gq96-8w38-hhj2")
        package = Package(name="test-package", ecosystem="npm")
        vulnerability = Vulnerability(package=package)
        
        advisory = Advisory(
            ghsa_id=ghsa_id,
            summary="Test advisory",
            severity="high",
            published_at="2024-01-01T00:00:00Z",
            vulnerabilities=[vulnerability]
        )
        
        assert advisory.ghsa_id == ghsa_id
        assert advisory.summary == "Test advisory"
        assert advisory.severity == "high"
        assert len(advisory.vulnerabilities) == 1
    
    def test_advisory_has_cve_property(self) -> None:
        """Test advisory has_cve property."""
        ghsa_id = GHSA_ID("GHSA-gq96-8w38-hhj2")
        package = Package(name="test-package", ecosystem="npm")
        vulnerability = Vulnerability(package=package)
        
        # Advisory without CVE
        advisory = Advisory(
            ghsa_id=ghsa_id,
            summary="Test advisory",
            severity="high",
            published_at="2024-01-01T00:00:00Z",
            vulnerabilities=[vulnerability]
        )
        assert not advisory.has_cve
        
        # Advisory with CVE
        advisory.cve_id = CVE_ID("CVE-2024-12345")
        assert advisory.has_cve
