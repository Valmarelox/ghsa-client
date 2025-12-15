
# Python < 3.11 compatibility
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, field_validator, model_validator

from ghsa_client.exceptions import InvalidCVSSError


class StrEnum(str, Enum):
    pass


class CVSSVector(StrEnum):
    """CVSS vector field names."""

    AttackVector = "AV"
    AttackComplexity = "AC"
    PrivilegesRequired = "PR"
    UserInteraction = "UI"
    Scope = "S"
    ConfidentialityImpact = "C"
    IntegrityImpact = "I"
    AvailabilityImpact = "A"
    Authentication = "Au"


class CVSS(BaseModel):
    """CVSS vector string representation."""

    string: str
    _parts: dict[str, str] = {}

    @model_validator(mode="before")
    @classmethod
    def validate_cvss_data(cls, data: Any) -> Optional[dict[str, str]]:
        if isinstance(data, dict):
            # Handle API response format with vector_string and score
            if "vector_string" in data and data["vector_string"]:
                return {"string": data["vector_string"]}
            elif "string" in data:
                return data
            else:
                # If no valid CVSS data, return None to skip this field
                return None
        elif isinstance(data, str):
            return {"string": data}
        else:
            return None

    @field_validator("string", mode="before")
    @classmethod
    def validate_string(cls, data: Any) -> str:
        if not isinstance(data, str):
            raise InvalidCVSSError(
                f"CVSS string must be a string, got {type(data).__name__}"
            )
        data = data.strip()
        if not data:
            raise InvalidCVSSError("CVSS string cannot be empty")
        assert isinstance(data, str)
        return data

    def model_post_init(self, __context: Any) -> None:
        self._parts = self._parse()

    def _parse(self) -> dict[str, str]:
        chunks = self.string.split("/")
        return dict(tuple(chunk.split(":", 1)) for chunk in chunks if ":" in chunk)

    def __contains__(self, field: CVSSVector) -> bool:
        return field.value in self._parts

    def __getitem__(self, field: CVSSVector) -> str:
        return self._parts[field.value]

    def __str__(self) -> str:
        return self.string

    @property
    def version(self) -> Optional[str]:
        return self._parts.get("CVSS", None) if self._parts else None
