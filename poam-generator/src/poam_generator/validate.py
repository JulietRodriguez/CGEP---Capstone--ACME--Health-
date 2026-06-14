"""Validation logic for POAM findings."""

from .models import REQUIRED_FIELDS, VALID_SEVERITIES, VALID_SOURCES, VALID_STATUSES


def validate_finding(finding: dict, index: int) -> list[str]:
    """Return a list of error strings for a single finding dict."""
    errors = []
    label = finding.get("weakness_name") or f"finding #{index + 1}"

    for f in REQUIRED_FIELDS:
        if f not in finding or finding[f] is None or finding[f] == "":
            errors.append(f"[{label}] Missing required field: '{f}'")

    severity = finding.get("severity", "")
    if severity and severity not in VALID_SEVERITIES:
        errors.append(
            f"[{label}] Invalid severity '{severity}'. "
            f"Must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
        )

    status = finding.get("status", "")
    if status and status not in VALID_STATUSES:
        errors.append(
            f"[{label}] Invalid status '{status}'. "
            f"Must be one of: {', '.join(sorted(VALID_STATUSES))}"
        )

    source = finding.get("source", "")
    if source and source not in VALID_SOURCES:
        errors.append(
            f"[{label}] Invalid source '{source}'. "
            f"Must be one of: {', '.join(sorted(VALID_SOURCES))}"
        )

    milestones = finding.get("milestones")
    if milestones is not None and not isinstance(milestones, (list, str)):
        errors.append(f"[{label}] 'milestones' must be a list of strings or a semicolon-separated string")

    return errors


def validate_findings(findings: list[dict]) -> list[str]:
    """Validate all findings and return consolidated error list."""
    if not findings:
        return ["No findings found in input file."]
    all_errors = []
    for i, f in enumerate(findings):
        all_errors.extend(validate_finding(f, i))
    return all_errors
