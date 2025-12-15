"""GHSA ID model with validation."""

import re
from typing import Any, ClassVar

from pydantic import BaseModel, field_validator


class InvalidGHSAIDError(Exception):
    """Raised when GHSA ID format is invalid."""

    pass


class GHSA_ID(BaseModel):
    """
    A strongly-typed GHSA identifier with proper validation.
    GHSA IDs follow the format: GHSA-xxxx-xxxx-xxxx where x is an alphanumeric character [0-9a-z].
    """

    id: str

    PATTERN: ClassVar[re.Pattern] = re.compile(
        r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$", re.IGNORECASE
    )

    def __init__(self, id: str | None = None, **data: Any) -> None:
        if id is not None:
            data["id"] = id
        elif "id" not in data:
            raise InvalidGHSAIDError("GHSA ID cannot be None")
        super().__init__(**data)

    @field_validator("id", mode="before")
    @classmethod
    def validate_id(cls, v: Any) -> str:
        if not isinstance(v, str):
            raise InvalidGHSAIDError(
                f"GHSA ID must be a string, got {type(v).__name__}"
            )
        normalized_id = v.strip()
        if not normalized_id:
            raise InvalidGHSAIDError("GHSA ID cannot be empty")
        if not cls.PATTERN.match(normalized_id):
            raise InvalidGHSAIDError(
                f"Invalid GHSA ID format: '{normalized_id}'. "
                f"Expected format: GHSA-xxxx-xxxx-xxxx where x is alphanumeric (e.g., GHSA-gq96-8w38-hhj2)"
            )
        return "GHSA-" + normalized_id[5:].lower()

    @property
    def ghsa_id(self) -> "GHSA_ID":
        return self

    def __str__(self) -> str:
        return self.id

    def __repr__(self) -> str:
        return f"GHSA_ID('{self.id}')"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, GHSA_ID):
            return self.id == other.id
        if not isinstance(other, str):
            return False
        try:
            other_ghsa = GHSA_ID(id=other)
            return self.id == other_ghsa.id
        except (InvalidGHSAIDError, Exception):
            return False

    def __hash__(self) -> int:
        return hash(self.id)
