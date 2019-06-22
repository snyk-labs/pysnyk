from dataclasses import dataclass, field
from typing import Optional

from mashumaro import DataClassJSONMixin  # type: ignore


@dataclass
class Organization(DataClassJSONMixin):
    name: str
    id: str
    group: Optional[str] = None


@dataclass
class Member(DataClassJSONMixin):
    id: str
    username: str
    name: str
    email: str
    role: str
