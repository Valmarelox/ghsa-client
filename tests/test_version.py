"""Tests for enhanced version handling with PyPI support."""

import pytest

from ghsa_client.models.version import SemanticVersion, VersionFormat, VersionPredicate


class TestSemanticVersion:
    """Test enhanced SemanticVersion class."""

    def test_parse_semver_version(self) -> None:
        """Test parsing semver versions."""
        version = SemanticVersion.parse("1.0.0")
        assert version.version_format == VersionFormat.SEMVER
        assert version.version_info.major == 1
        assert version.version_info.minor == 0
        assert version.version_info.patch == 0
        assert str(version) == "1.0.0"

    def test_parse_semver_with_prerelease(self) -> None:
        """Test parsing semver with pre-release."""
        version = SemanticVersion.parse("1.0.0-alpha.1")
        assert version.version_format == VersionFormat.SEMVER
        assert version.version_info.prerelease == "alpha.1"
        assert str(version) == "1.0.0-alpha.1"

    def test_parse_semver_with_build(self) -> None:
        """Test parsing semver with build metadata."""
        version = SemanticVersion.parse("1.0.0+build.1")
        assert version.version_format == VersionFormat.SEMVER
        assert version.version_info.build == "build.1"
        assert str(version) == "1.0.0+build.1"

    def test_parse_pypi_version(self) -> None:
        """Test parsing PyPI versions."""
        version = SemanticVersion.parse("1.0.0")
        assert version.version_format == VersionFormat.SEMVER  # Basic version is semver

    def test_parse_pypi_with_prerelease(self) -> None:
        """Test parsing PyPI versions with pre-release."""
        version = SemanticVersion.parse("1.0.0a1")
        assert version.version_format == VersionFormat.PYPI
        assert version.version_info.major == 1
        assert version.version_info.minor == 0
        assert version.version_info.patch == 0
        assert version.version_info.prerelease == "alpha.1"

    def test_parse_pypi_with_beta(self) -> None:
        """Test parsing PyPI versions with beta."""
        version = SemanticVersion.parse("1.0.0b2")
        assert version.version_format == VersionFormat.PYPI
        assert version.version_info.prerelease == "beta.2"

    def test_parse_pypi_with_rc(self) -> None:
        """Test parsing PyPI versions with release candidate."""
        version = SemanticVersion.parse("1.0.0rc3")
        assert version.version_format == VersionFormat.PYPI
        assert version.version_info.prerelease == "rc.3"

    def test_parse_pypi_with_dev(self) -> None:
        """Test parsing PyPI versions with dev release."""
        version = SemanticVersion.parse("1.0.0.dev1")
        assert version.version_format == VersionFormat.PYPI
        assert version.version_info.build == "dev.1"

    def test_parse_pypi_with_post(self) -> None:
        """Test parsing PyPI versions with post release."""
        version = SemanticVersion.parse("1.0.0.post1")
        assert version.version_format == VersionFormat.PYPI
        # Post releases are not directly supported in semver, so they become build metadata
        assert version.version_info.build == "post.1"

    def test_parse_pypi_with_epoch(self) -> None:
        """Test parsing PyPI versions with epoch."""
        version = SemanticVersion.parse("1!2.0.0")
        assert version.version_format == VersionFormat.PYPI
        # Epoch is not supported in semver, so it's ignored
        assert version.version_info.major == 2
        assert version.version_info.minor == 0
        assert version.version_info.patch == 0

    def test_parse_with_prefix(self) -> None:
        """Test parsing versions with prefix."""
        version = SemanticVersion.parse("v1.0.0")
        assert version.prefix == "v"
        assert version.version_info.major == 1
        assert str(version) == "v1.0.0"

    def test_to_pypi_conversion(self) -> None:
        """Test conversion to PyPI format."""
        # Test semver to PyPI
        version = SemanticVersion.parse("1.0.0-alpha.1")
        assert version.to_pypi() == "1.0.0a1"

        version = SemanticVersion.parse("1.0.0-beta.2")
        assert version.to_pypi() == "1.0.0b2"

        version = SemanticVersion.parse("1.0.0-rc.3")
        assert version.to_pypi() == "1.0.0rc3"

        version = SemanticVersion.parse("1.0.0+build.1")
        assert version.to_pypi() == "1.0.0+build.1"

    def test_to_semver_conversion(self) -> None:
        """Test conversion to semver format."""
        version = SemanticVersion.parse("1.0.0a1")
        assert version.to_semver() == "1.0.0-alpha.1"

        version = SemanticVersion.parse("1.0.0b2")
        assert version.to_semver() == "1.0.0-beta.2"

        version = SemanticVersion.parse("1.0.0rc3")
        assert version.to_semver() == "1.0.0-rc.3"

    def test_version_comparison(self) -> None:
        """Test version comparison."""
        v1 = SemanticVersion.parse("1.0.0")
        v2 = SemanticVersion.parse("1.0.1")
        v3 = SemanticVersion.parse("1.0.0a1")

        assert v1 < v2
        assert v3 < v1
        assert v1 == SemanticVersion.parse("1.0.0")

    def test_installable_version(self) -> None:
        """Test installable version property."""
        version = SemanticVersion.parse("v1.0.0")
        assert version.installable_version == "1.0.0"

        version = SemanticVersion.parse("1.0.0")
        assert version.installable_version == "1.0.0"

    def test_variations(self) -> None:
        """Test version variations."""
        version = SemanticVersion.parse("v1.0.0")
        variations = version.variations
        assert "1.0.0" in variations
        assert "v1.0.0" in variations

    def test_invalid_version(self) -> None:
        """Test handling of invalid versions."""
        with pytest.raises(ValueError, match="Invalid version"):
            SemanticVersion.parse("invalid-version")

    def test_none_semver(self) -> None:
        """Test handling of None semver."""
        version = SemanticVersion.parse("4.2")
        assert version is not None
        assert str(version) == "4.2.0"

    def test_parse_rubygems_version_with_p_suffix(self) -> None:
        """Test parsing RubyGems versions with 'p' suffix."""
        version = SemanticVersion.parse("4.25.14p12")
        assert version.version_format == VersionFormat.RUBYGEMS
        assert version.version_info.major == 4
        assert version.version_info.minor == 25
        assert version.version_info.patch == 14
        assert version.version_info.build == "p12"
        assert str(version) == "4.25.14+p12"
        assert version.original_version == "4.25.14p12"

    def test_parse_rubygems_version_with_p_suffix_single_digit(self) -> None:
        """Test parsing RubyGems versions with single digit patch."""
        version = SemanticVersion.parse("1.2.3p1")
        assert version.version_format == VersionFormat.RUBYGEMS
        assert version.version_info.major == 1
        assert version.version_info.minor == 2
        assert version.version_info.patch == 3
        assert version.version_info.build == "p1"
        assert str(version) == "1.2.3+p1"

    def test_parse_rubygems_version_with_p_suffix_multiple_digits(self) -> None:
        """Test parsing RubyGems versions with multi-digit patch."""
        version = SemanticVersion.parse("10.20.30p123")
        assert version.version_format == VersionFormat.RUBYGEMS
        assert version.version_info.major == 10
        assert version.version_info.minor == 20
        assert version.version_info.patch == 30
        assert version.version_info.build == "p123"
        assert str(version) == "10.20.30+p123"

    def test_parse_ubuntu_version_basic(self) -> None:
        """Test parsing basic Ubuntu package versions."""
        version = SemanticVersion.parse("0.8.3ubuntu7.5")
        assert version.version_format == VersionFormat.UBUNTU
        assert version.version_info.major == 0
        assert version.version_info.minor == 8
        assert version.version_info.patch == 3
        assert version.version_info.build == "ubuntu7.5"
        assert str(version) == "0.8.3+ubuntu7.5"
        assert version.original_version == "0.8.3ubuntu7.5"

    def test_parse_ubuntu_version_with_single_suffix(self) -> None:
        """Test parsing Ubuntu versions with single digit suffix."""
        version = SemanticVersion.parse("1.6.5ubuntu0.1")
        assert version.version_format == VersionFormat.UBUNTU
        assert version.version_info.major == 1
        assert version.version_info.minor == 6
        assert version.version_info.patch == 5
        assert version.version_info.build == "ubuntu0.1"
        assert str(version) == "1.6.5+ubuntu0.1"

    def test_parse_ubuntu_version_multiple_parts(self) -> None:
        """Test parsing Ubuntu versions with multiple part suffix."""
        version = SemanticVersion.parse("1.9.0ubuntu1.2")
        assert version.version_format == VersionFormat.UBUNTU
        assert version.version_info.major == 1
        assert version.version_info.minor == 9
        assert version.version_info.patch == 0
        assert version.version_info.build == "ubuntu1.2"
        assert str(version) == "1.9.0+ubuntu1.2"


class TestVersionPredicate:
    """Test enhanced VersionPredicate class."""

    def test_parse_semver_predicate(self) -> None:
        """Test parsing semver predicates."""
        predicate = VersionPredicate.from_str(">=1.0.0")
        assert predicate.operator == ">="
        assert predicate.version == "1.0.0"
        assert predicate.version_format == VersionFormat.SEMVER

    def test_parse_pypi_predicate(self) -> None:
        """Test parsing PyPI predicates."""
        predicate = VersionPredicate.from_str(">=1.0.0a1")
        assert predicate.operator == ">="
        assert predicate.version == "1.0.0-alpha.1"  # Should be normalized to semver
        assert predicate.version_format == VersionFormat.PYPI

    def test_parse_predicate_with_spaces(self) -> None:
        """Test parsing predicates with spaces."""
        predicate = VersionPredicate.from_str(">= 1.0.0")
        assert predicate.operator == ">="
        assert predicate.version == "1.0.0"

    def test_parse_equality_operators(self) -> None:
        """Test parsing different equality operators."""
        predicate1 = VersionPredicate.from_str("=1.0.0")
        assert predicate1.operator == "=="

        predicate2 = VersionPredicate.from_str("==1.0.0")
        assert predicate2.operator == "=="

    def test_to_pypi_predicate(self) -> None:
        """Test conversion to PyPI predicate format."""
        predicate = VersionPredicate.from_str(">=1.0.0-alpha.1")
        pypi_predicate = predicate.to_pypi_predicate()
        assert pypi_predicate == ">=1.0.0a1"

    def test_to_semver_predicate(self) -> None:
        """Test conversion to semver predicate format."""
        predicate = VersionPredicate.from_str(">=1.0.0a1")
        semver_predicate = predicate.to_semver_predicate()
        assert semver_predicate == ">=1.0.0-alpha.1"

    def test_predicate_string_representation(self) -> None:
        """Test predicate string representation."""
        predicate = VersionPredicate.from_str(">=1.0.0")
        assert str(predicate) == ">=1.0.0"

    def test_invalid_predicate_format(self) -> None:
        """Test handling of invalid predicate formats."""
        with pytest.raises(ValueError, match="Invalid version predicate format"):
            VersionPredicate.from_str("invalid-predicate")

    def test_operator_to_symbol(self) -> None:
        """Test operator to symbol conversion."""
        predicate = VersionPredicate.from_str(">=1.0.0")
        assert predicate.operator_to_symbol() == "__ge__"

        predicate = VersionPredicate.from_str("<1.0.0")
        assert predicate.operator_to_symbol() == "__lt__"

    def test_invalid_operator(self) -> None:
        """Test handling of invalid operators."""
        predicate = VersionPredicate(operator="invalid", version="1.0.0")
        with pytest.raises(ValueError, match="Invalid operator"):
            predicate.operator_to_symbol()

    def test_version_predicate(self) -> None:
        predicate = VersionPredicate.from_str(">=4.2")
        assert predicate is not None
        assert predicate.version == "4.2.0"  # Should be normalized
        assert predicate.semver == SemanticVersion.parse("4.2.0")

    def test_parse_rubygems_predicate_with_p_suffix(self) -> None:
        """Test parsing RubyGems version predicates with 'p' suffix."""
        predicate = VersionPredicate.from_str("< 4.25.14p12")
        assert predicate.operator == "<"
        assert predicate.version == "4.25.14+p12"  # Should be normalized to semver
        assert predicate.version_format == VersionFormat.RUBYGEMS

    def test_parse_rubygems_predicate_without_spaces(self) -> None:
        """Test parsing RubyGems predicates without spaces."""
        predicate = VersionPredicate.from_str(">=4.25.14p12")
        assert predicate.operator == ">="
        assert predicate.version == "4.25.14+p12"
        assert predicate.version_format == VersionFormat.RUBYGEMS

    def test_parse_rubygems_predicate_equality(self) -> None:
        """Test parsing RubyGems equality predicates."""
        predicate = VersionPredicate.from_str("==4.25.14p12")
        assert predicate.operator == "=="
        assert predicate.version == "4.25.14+p12"
        assert predicate.version_format == VersionFormat.RUBYGEMS

    def test_parse_ubuntu_predicate_with_ubuntu_suffix(self) -> None:
        """Test parsing Ubuntu version predicates with ubuntu suffix."""
        predicate = VersionPredicate.from_str("< 0.8.3ubuntu7.5")
        assert predicate.operator == "<"
        assert predicate.version == "0.8.3+ubuntu7.5"  # Should be normalized to semver
        assert predicate.version_format == VersionFormat.UBUNTU

    def test_parse_ubuntu_predicate_without_spaces(self) -> None:
        """Test parsing Ubuntu predicates without spaces."""
        predicate = VersionPredicate.from_str(">=1.6.5ubuntu0.1")
        assert predicate.operator == ">="
        assert predicate.version == "1.6.5+ubuntu0.1"
        assert predicate.version_format == VersionFormat.UBUNTU

    def test_parse_ubuntu_predicate_equality(self) -> None:
        """Test parsing Ubuntu equality predicates."""
        predicate = VersionPredicate.from_str("==1.9.0ubuntu1.2")
        assert predicate.operator == "=="
        assert predicate.version == "1.9.0+ubuntu1.2"
        assert predicate.version_format == VersionFormat.UBUNTU


class TestVersionIntegration:
    """Test integration between SemanticVersion and VersionPredicate."""

    def test_predicate_matching(self) -> None:
        """Test version predicate matching."""
        version = SemanticVersion.parse("1.0.0")
        predicate = VersionPredicate.from_str(">=1.0.0")
        assert version.matches_predicate(predicate)

        predicate = VersionPredicate.from_str(">1.0.0")
        assert not version.matches_predicate(predicate)

    def test_mixed_format_comparison(self) -> None:
        """Test comparison between different format versions."""
        semver_version = SemanticVersion.parse("1.0.0")
        pypi_version = SemanticVersion.parse("1.0.0")

        # Both should be equivalent
        assert semver_version == pypi_version

    def test_complex_version_scenarios(self) -> None:
        """Test complex version scenarios."""
        # Test PyPI version with multiple components
        version = SemanticVersion.parse("1.0.0a1.dev1")
        assert version.version_format == VersionFormat.PYPI
        assert version.version_info.prerelease == "alpha.1"
        assert version.version_info.build == "dev.1"

        # Test conversion
        assert version.to_pypi() == "1.0.0a1.dev1"
        assert version.to_semver() == "1.0.0-alpha.1+dev.1"
