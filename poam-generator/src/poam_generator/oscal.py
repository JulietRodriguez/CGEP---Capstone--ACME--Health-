"""OSCAL 1.0.4 POA&M export — JSON and XML — stdlib only."""

import json
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding

OSCAL_NS = "http://csrc.nist.gov/ns/oscal/1.0"
OSCAL_VERSION = "1.0.4"

_STATUS_MAP = {
    "Open": "open",
    "In Progress": "open",
    "Closed": "closed",
    "Risk Accepted": "closed",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _date_iso(date_str: str) -> str:
    """Append Z to a bare YYYY-MM-DD date string."""
    return f"{date_str}T00:00:00Z"


def _build_oscal_dict(findings: list[Finding]) -> dict:
    doc_uuid = str(uuid.uuid4())
    system_id = str(uuid.uuid4())

    risks = []
    poam_items = []

    for finding in findings:
        risk_uuid = str(uuid.uuid4())
        item_uuid = str(uuid.uuid4())

        milestones = [
            {
                "uuid": str(uuid.uuid4()),
                "type": "milestone",
                "title": m,
                "timing": {
                    "within-date-range": {
                        "start": _date_iso(finding.detection_date),
                        "end": _date_iso(finding.scheduled_completion),
                    }
                },
            }
            for m in finding.milestones
        ]

        risks.append(
            {
                "uuid": risk_uuid,
                "title": finding.weakness_name,
                "description": finding.weakness_description,
                "statement": finding.remediation_plan,
                "status": _STATUS_MAP.get(finding.status, "open"),
                "characterizations": [
                    {
                        "origin": {
                            "actors": [
                                {
                                    "type": "assessment-platform",
                                    "actor-uuid": str(uuid.uuid4()),
                                }
                            ]
                        },
                        "facets": [
                            {
                                "name": "impact",
                                "system": "http://csrc.nist.gov/ns/oscal/unknown",
                                "value": finding.severity.lower(),
                            },
                            {
                                "name": "source",
                                "system": "http://csrc.nist.gov/ns/oscal/unknown",
                                "value": finding.source,
                            },
                        ],
                    }
                ],
                "response": [
                    {
                        "uuid": str(uuid.uuid4()),
                        "lifecycle": "planned",
                        "title": "Remediation Plan",
                        "description": finding.remediation_plan,
                        "required-assets": [{"description": finding.resources_required}],
                        "tasks": milestones,
                    }
                ],
            }
        )

        poam_items.append(
            {
                "uuid": item_uuid,
                "title": finding.weakness_name,
                "description": finding.weakness_description,
                "collected": _date_iso(finding.detection_date),
                "scheduled-completion-date": _date_iso(finding.scheduled_completion),
                "remarks": finding.comments,
                "related-findings": [
                    {
                        "target": {
                            "type": "objective-id",
                            "target-id": finding.security_control,
                            "description": (
                                f"Security control {finding.security_control} — "
                                f"identified via {finding.source}"
                            ),
                        }
                    }
                ],
                "related-risks": [{"risk-uuid": risk_uuid}],
                "props": [
                    {"name": "severity", "value": finding.severity},
                    {"name": "office-org", "value": finding.office_org},
                    {"name": "point-of-contact", "value": finding.point_of_contact},
                    {"name": "risk-state", "value": _STATUS_MAP.get(finding.status, "open")},
                ],
            }
        )

    return {
        "plan-of-action-and-milestones": {
            "uuid": doc_uuid,
            "metadata": {
                "title": "POAM Export",
                "last-modified": _now_iso(),
                "version": "0.2.0",
                "oscal-version": OSCAL_VERSION,
            },
            "system-id": {
                "identifier-type": "https://ietf.org/rfc/rfc4122",
                "id": system_id,
            },
            "risks": risks,
            "poam-items": poam_items,
        }
    }


def write_oscal_json(findings: list[Finding], output_path: str | Path) -> None:
    doc = _build_oscal_dict(findings)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# XML export
# ---------------------------------------------------------------------------

def _sub(parent: ET.Element, tag: str, text: str | None = None) -> ET.Element:
    el = ET.SubElement(parent, f"{{{OSCAL_NS}}}{tag}")
    if text is not None:
        el.text = text
    return el


def _build_oscal_xml(findings: list[Finding]) -> ET.Element:
    ET.register_namespace("", OSCAL_NS)
    root = ET.Element(f"{{{OSCAL_NS}}}plan-of-action-and-milestones")
    root.set("uuid", str(uuid.uuid4()))

    # metadata
    meta = _sub(root, "metadata")
    _sub(meta, "title", "POAM Export")
    _sub(meta, "last-modified", _now_iso())
    _sub(meta, "version", "0.2.0")
    _sub(meta, "oscal-version", OSCAL_VERSION)

    # system-id
    sys_id = _sub(root, "system-id")
    sys_id.set("identifier-type", "https://ietf.org/rfc/rfc4122")
    sys_id.text = str(uuid.uuid4())

    risk_uuid_map: dict[int, str] = {}

    # risks
    for idx, finding in enumerate(findings):
        risk_uuid = str(uuid.uuid4())
        risk_uuid_map[idx] = risk_uuid

        risk = _sub(root, "risk")
        risk.set("uuid", risk_uuid)
        _sub(risk, "title", finding.weakness_name)
        _sub(risk, "description", finding.weakness_description)
        _sub(risk, "statement", finding.remediation_plan)
        _sub(risk, "status", _STATUS_MAP.get(finding.status, "open"))

        charact = _sub(risk, "characterization")
        origin = _sub(charact, "origin")
        actor = _sub(origin, "actor")
        actor.set("type", "assessment-platform")
        actor.set("actor-uuid", str(uuid.uuid4()))
        for name, value in (("impact", finding.severity.lower()), ("source", finding.source)):
            facet = _sub(charact, "facet")
            facet.set("name", name)
            facet.set("system", "http://csrc.nist.gov/ns/oscal/unknown")
            facet.set("value", value)

        response = _sub(risk, "response")
        response.set("uuid", str(uuid.uuid4()))
        response.set("lifecycle", "planned")
        _sub(response, "title", "Remediation Plan")
        _sub(response, "description", finding.remediation_plan)
        req_assets = _sub(response, "required-assets")
        _sub(req_assets, "description", finding.resources_required)

        for milestone in finding.milestones:
            task = _sub(response, "task")
            task.set("uuid", str(uuid.uuid4()))
            task.set("type", "milestone")
            _sub(task, "title", milestone)
            timing = _sub(task, "timing")
            wdr = _sub(timing, "within-date-range")
            wdr.set("start", _date_iso(finding.detection_date))
            wdr.set("end", _date_iso(finding.scheduled_completion))

    # poam-items
    for idx, finding in enumerate(findings):
        item = _sub(root, "poam-item")
        item.set("uuid", str(uuid.uuid4()))
        _sub(item, "title", finding.weakness_name)
        _sub(item, "description", finding.weakness_description)
        _sub(item, "collected", _date_iso(finding.detection_date))
        _sub(item, "scheduled-completion-date", _date_iso(finding.scheduled_completion))
        _sub(item, "remarks", finding.comments)

        for prop_name, prop_val in (
            ("severity", finding.severity),
            ("office-org", finding.office_org),
            ("point-of-contact", finding.point_of_contact),
            ("risk-state", _STATUS_MAP.get(finding.status, "open")),
        ):
            prop = _sub(item, "prop")
            prop.set("name", prop_name)
            prop.set("value", prop_val)

        rel_finding = _sub(item, "related-finding")
        target = _sub(rel_finding, "target")
        target.set("type", "objective-id")
        target.set("target-id", finding.security_control)
        _sub(
            target,
            "description",
            f"Security control {finding.security_control} — identified via {finding.source}",
        )

        rel_risk = _sub(item, "related-risk")
        rel_risk.set("risk-uuid", risk_uuid_map[idx])

    return root


def write_oscal_xml(findings: list[Finding], output_path: str | Path) -> None:
    root = _build_oscal_xml(findings)
    ET.indent(root, space="  ")
    tree = ET.ElementTree(root)
    with open(output_path, "wb") as f:
        f.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
        tree.write(f, encoding="utf-8", xml_declaration=False)
