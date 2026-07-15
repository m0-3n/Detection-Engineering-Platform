from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Status(Enum):
    DRAFT = "draft"
    TESTING = "testing"
    PRODUCTION = "production"
    DEPRECATED = "deprecated"


@dataclass(slots=True)
class DetectionRule:
    """
    Represents a platform-independent detection rule.
    """

    rule_id: str
    title: str
    description: str
    severity: Severity
    log_source: str

    mitre_techniques: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    author: str = "m03n"
    status: Status = Status.DRAFT