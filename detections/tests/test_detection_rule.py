from models.detection_rule import (
    DetectionRule,
    Severity,
    Status,
)


def test_detection_rule_creation():

    rule = DetectionRule(
        rule_id="DET-001",
        title="PowerShell Execution",
        description="Detect PowerShell execution.",
        severity=Severity.MEDIUM,
        log_source="Windows Security Logs",
    )

    assert rule.rule_id == "DET-001"
    assert rule.severity == Severity.MEDIUM
    assert rule.status == Status.DRAFT
    assert rule.author == "m03n"