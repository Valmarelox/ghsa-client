from pydantic import BaseModel


class Package(BaseModel):
    """Package representation."""
    name: str
    ecosystem: str

