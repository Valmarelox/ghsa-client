"""Advisory model for GHSA operations."""

from typing import Any, Optional

from pydantic import BaseModel, computed_field, field_validator, model_validator

from .cve_id import CVE_ID
from .cvss import CVSS
from .ghsa_id import GHSA_ID
from .package import Package
from .vulnerability import Vulnerability


class NoSourceCodeLocationFound(Exception):
    """Raised when source code location is not found in advisory."""

    pass


class Advisory(BaseModel):
    """Represents a GitHub Security Advisory (GHSA)."""

    ghsa_id: GHSA_ID
    cve_id: Optional[CVE_ID] = None
    summary: str
    severity: str
    published_at: str
    vulnerabilities: list[Vulnerability]
    description: Optional[str] = None
    source_code_location: Optional[str] = None
    cwes: Optional[list[str]] = None
    references: list[str] = []
    cvss: Optional[CVSS] = None

    @field_validator("ghsa_id", mode="before")
    @classmethod
    def validate_ghsa_id(cls, v: Any) -> GHSA_ID:
        if isinstance(v, str):
            return GHSA_ID(id=v)
        if isinstance(v, GHSA_ID):
            return v
        if isinstance(v, dict):
            return GHSA_ID.model_validate(v)
        raise ValueError("Invalid value for ghsa_id")

    @field_validator("cve_id", mode="before")
    @classmethod
    def validate_cve_id(cls, v: Any) -> Optional[CVE_ID]:
        if v is None:
            return None
        if isinstance(v, str):
            return CVE_ID(id=v)
        if isinstance(v, CVE_ID):
            return v
        if isinstance(v, dict):
            return CVE_ID.model_validate(v)
        raise ValueError("Invalid value for cve_id")

    @field_validator("cwes", mode="before")
    @classmethod
    def parse_cwes(cls, v: Any) -> Optional[list[str]]:
        if not v:
            return None
        cwes = []
        for cwe_data in v:
            if isinstance(cwe_data, dict):
                cwe_id = cwe_data.get("cwe_id", "")
                if cwe_id:
                    cwes.append(cwe_id)
            elif isinstance(cwe_data, str):
                cwes.append(cwe_data)
        return cwes if cwes else None

    @field_validator("cvss", mode="before")
    @classmethod
    def parse_cvss(cls, v: Any, info: Any) -> Optional[CVSS]:
        if not v:
            return None
        # Let the CVSS model handle the validation and parsing
        try:
            return CVSS.model_validate(v)
        except Exception:
            return None

    @model_validator(mode="before")
    @classmethod
    def parse_cvss_severity(cls, data: Any) -> Any:
        if isinstance(data, dict) and "cvss_severity" in data:
            cvss_severity = data.pop("cvss_severity")
            if cvss_severity:
                if "cvss_v4" in cvss_severity:
                    data["cvss"] = CVSS(string=cvss_severity["cvss_v4"])
                elif "cvss_v3" in cvss_severity:
                    data["cvss"] = CVSS(string=cvss_severity["cvss_v3"])
        return data

    def __str__(self) -> str:
        return f"{self.ghsa_id}: {self.summary} ({self.severity})"

    def __repr__(self) -> str:
        vulns_repr = f"[{len(self.vulnerabilities)} vulnerabilities]"
        desc_preview = (
            self.description[:100] + "..."
            if self.description and len(self.description) > 100
            else self.description
        )

        return (
            f"Advisory(\n"
            f"  ghsa_id={self.ghsa_id!r},\n"
            f"  cve_id={self.cve_id!r},\n"
            f"  summary={self.summary!r},\n"
            f"  severity={self.severity!r},\n"
            f"  published_at={self.published_at!r},\n"
            f"  vulnerabilities={vulns_repr},\n"
            f"  description={desc_preview!r},\n"
            f"  source_code_location={self.source_code_location!r},\n"
            f"  cwes={self.cwes!r},\n"
            f"  references={self.references!r}\n"
            f")"
        )

    @property
    def has_cve(self) -> bool:
        """Check if the advisory has an associated CVE."""
        return self.cve_id is not None and str(self.cve_id) != ""

    @computed_field(return_type=str)
    def vuln_id(self) -> str:
        """Canonical vulnerability ID for the system, always a CVE when available, else GHSA."""
        if self.cve_id is not None:
            return str(self.cve_id)
        return str(self.ghsa_id)

    @property
    def affected_packages(self) -> list[Package]:
        """Get all unique packages affected by this advisory."""
        packages = []
        seen = set()
        for vuln in self.vulnerabilities:
            key = (vuln.package.name, vuln.package.ecosystem)
            if key not in seen:
                packages.append(vuln.package)
                seen.add(key)
        return packages
