"""Base models for GHSA operations."""

from typing import Optional, Any, List
from pydantic import BaseModel, field_validator

class Package(BaseModel):
    """Package representation."""
    name: str
    ecosystem: str
