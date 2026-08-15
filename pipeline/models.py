from dataclasses import dataclass, asdict
from typing import Optional

@dataclass
class Finding:
    application: str
    scanner: str
    category: str
    title: str
    severity: str

    cwe: Optional[str] = None
    cve: Optional[str] = None
    location: Optional[str] = None
    component: Optional[str] = None

    environment: str = "development"
    internet_exposed: bool = False
    status: str = "open"

    def to_dict(self):
        return asdict(self)