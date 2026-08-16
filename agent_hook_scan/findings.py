"""Data structures for scan findings."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Finding severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @classmethod
    def from_string(cls, s: str) -> "Severity":
        """Parse severity from string."""
        return cls[s.upper()]


@dataclass
class Finding:
    """A single security finding from the scan."""
    severity: Severity
    rule_id: str
    title: str
    file_path: str
    line: Optional[int] = None
    description: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "severity": self.severity.value,
            "rule_id": self.rule_id,
            "title": self.title,
            "file_path": self.file_path,
            "line": self.line,
            "description": self.description,
            "remediation": self.remediation,
        }
