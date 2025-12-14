from typing import Any

from pydantic import BaseModel, field_validator

from .ecosystem import Ecosystem


class Package(BaseModel):
    """Package representation."""
    name: str
    ecosystem: Ecosystem

    @field_validator("ecosystem", mode="before")
    @classmethod
    def validate_ecosystem(cls, v: Any) -> Ecosystem:
        """Convert string ecosystem to Ecosystem enum."""
        if isinstance(v, Ecosystem):
            return v
        if isinstance(v, str):
            return Ecosystem(v.lower())
        raise ValueError(f"Invalid ecosystem type: {type(v)}")

