"""POAM finding data model and field definitions."""

from dataclasses import dataclass, field
from typing import Literal

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}
VALID_STATUSES = {"Open", "In Progress", "Closed", "Risk Accepted"}
VALID_SOURCES = {"Audit", "Vulnerability Scan", "Penetration Test"}

REQUIRED_FIELDS = [
    "weakness_name",
    "weakness_description",
    "security_control",
    "severity",
    "source",
    "detection_date",
    "scheduled_completion",
    "office_org",
    "point_of_contact",
    "resources_required",
    "remediation_plan",
    "milestones",
    "status",
    "comments",
]

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


@dataclass
class Finding:
    weakness_name: str
    weakness_description: str
    security_control: str
    severity: Literal["Critical", "High", "Medium", "Low"]
    source: Literal["Audit", "Vulnerability Scan", "Penetration Test"]
    detection_date: str
    scheduled_completion: str
    office_org: str
    point_of_contact: str
    resources_required: str
    remediation_plan: str
    milestones: list[str]
    status: Literal["Open", "In Progress", "Closed", "Risk Accepted"]
    comments: str

    def to_csv_row(self) -> dict:
        return {
            "Weakness Name": self.weakness_name,
            "Weakness Description": self.weakness_description,
            "Security Control": self.security_control,
            "Severity": self.severity,
            "Source": self.source,
            "Detection Date": self.detection_date,
            "Scheduled Completion": self.scheduled_completion,
            "Office/Org": self.office_org,
            "Point of Contact": self.point_of_contact,
            "Resources Required": self.resources_required,
            "Remediation Plan": self.remediation_plan,
            "Milestones": "; ".join(self.milestones),
            "Status": self.status,
            "Comments": self.comments,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        milestones = data.get("milestones", [])
        if isinstance(milestones, str):
            milestones = [m.strip() for m in milestones.split(";") if m.strip()]
        return cls(
            weakness_name=data["weakness_name"],
            weakness_description=data["weakness_description"],
            security_control=data["security_control"],
            severity=data["severity"],
            source=data["source"],
            detection_date=data["detection_date"],
            scheduled_completion=data["scheduled_completion"],
            office_org=data["office_org"],
            point_of_contact=data["point_of_contact"],
            resources_required=data["resources_required"],
            remediation_plan=data["remediation_plan"],
            milestones=milestones,
            status=data["status"],
            comments=data["comments"],
        )
