from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from auto_exploit.models.etc.language import Language


class Ecosystem(StrEnum):
    """Package ecosystem enumeration."""

    PIP = "pip"
    NPM = "npm"
    COMPOSER = "composer"
    MAVEN = "maven"
    RUBYGEMS = "rubygems"
    CARGO = "cargo"
    GO = "go"

    @property
    def s3_key(self) -> str:
        """Get the S3 key for this ecosystem's advisories list."""
        return f"{self.value}_advisories_list.json"

    @property
    def regression_s3_key(self) -> str:
        """Get the S3 key for this ecosystem's regression advisories."""
        return f"{self.value}_regression_advisories.json"

    @property
    def cache_file(self) -> str:
        """Get the local cache file path for this ecosystem."""
        return f"cache/filtered_{self.value}_advisories.json"

    @property
    def regression_cache_file(self) -> str:
        """Get the local regression cache file path for this ecosystem."""
        return f"cache/{self.value}_regression_advisories.json"

    @property
    def workdir_prefix(self) -> str:
        """Get the workdir prefix for this ecosystem."""
        return f"all_{self.value}"

    @property
    def language(self) -> "Language":
        """Get the language for this ecosystem."""
        from auto_exploit.models.etc.language import Language
        
        match self:
            case Ecosystem.NPM:
                return Language.NODEJS
            case Ecosystem.MAVEN:
                return Language.JAVA
            case Ecosystem.GO:
                return Language.GOLANG
            case Ecosystem.COMPOSER:
                return Language.PHP
            case Ecosystem.RUBYGEMS:
                return Language.RUBY
            case Ecosystem.PIP:
                return Language.PYTHON
            case Ecosystem.CARGO:
                return Language.RUST
        raise ValueError(f"No language found for ecosystem: {self}")

