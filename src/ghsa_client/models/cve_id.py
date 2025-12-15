import re
from typing import Any, ClassVar, Optional

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
            raise ValueError(f"CVE ID must be a string, got {type(value).__name__}")
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
