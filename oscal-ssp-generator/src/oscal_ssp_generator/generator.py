"""Generate an OSCAL 1.1.2 System Security Plan from an :class:`Inventory`."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from . import OSCAL_VERSION, __version__
from .controls import (
    baseline_coverage,
    control_title,
    map_resources_to_controls,
)
from .models import Inventory

# Deterministic namespace so re-running against the same system yields stable
# component / requirement UUIDs (helpful for diffing draft SSPs in git).
_NAMESPACE = uuid.UUID("12345678-1234-5678-1234-567812345678")

FEDRAMP_MODERATE_PROFILE = (
    "https://raw.githubusercontent.com/GSA/fedramp-automation/master/"
    "dist/content/rev5/baselines/json/FedRAMP_rev5_MODERATE-baseline_profile.json"
)


def _uuid_for(*parts: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, "::".join(parts)))


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _metadata(system_name: str, timestamp: str) -> dict:
    return {
        "title": f"{system_name} System Security Plan (Draft)",
        "last-modified": timestamp,
        "version": "0.1.0-draft",
        "oscal-version": OSCAL_VERSION,
        "props": [
            {"name": "marking", "value": "CUI"},
            {"name": "generator", "value": f"oscal-ssp-generator {__version__}"},
        ],
        "roles": [
            {"id": "system-owner", "title": "System Owner"},
            {"id": "authorizing-official", "title": "Authorizing Official"},
            {"id": "isso", "title": "Information System Security Officer"},
        ],
        "parties": [
            {
                "uuid": _uuid_for("party", "owning-org"),
                "type": "organization",
                "name": "My Organization",
            }
        ],
        "responsible-parties": [
            {
                "role-id": "system-owner",
                "party-uuids": [_uuid_for("party", "owning-org")],
            }
        ],
    }


def _system_information() -> dict:
    """The system-information section (information types + categorization)."""
    return {
        "information-types": [
            {
                "uuid": _uuid_for("info-type", "system-ops"),
                "title": "System Operations Information",
                "description": (
                    "Information related to the operation and management of the "
                    "cloud infrastructure described in this plan."
                ),
                "categorizations": [
                    {
                        "system": "https://doi.org/10.6028/NIST.SP.800-60v2r1",
                        "information-type-ids": ["C.3.5.1"],
                    }
                ],
                "confidentiality-impact": {"base": "fips-199-moderate"},
                "integrity-impact": {"base": "fips-199-moderate"},
                "availability-impact": {"base": "fips-199-moderate"},
            }
        ]
    }


def _system_characteristics(inventory: Inventory, timestamp: str) -> dict:
    return {
        "system-ids": [
            {
                "identifier-type": "https://ietf.org/rfc/rfc4122",
                "id": _uuid_for("system-id", inventory.system_name),
            }
        ],
        "system-name": inventory.system_name,
        "description": (
            f"Draft System Security Plan auto-generated from {inventory.source} "
            f"input covering {len(inventory)} discovered AWS resources across "
            f"{len(inventory.resource_types())} resource types."
        ),
        "date-authorized": timestamp[:10],
        "security-sensitivity-level": "fips-199-moderate",
        "system-information": _system_information(),
        "security-impact-level": {
            "security-objective-confidentiality": "fips-199-moderate",
            "security-objective-integrity": "fips-199-moderate",
            "security-objective-availability": "fips-199-moderate",
        },
        "status": {"state": "under-development"},
        "authorization-boundary": {
            "description": (
                "Logical authorization boundary inferred from the provided "
                "infrastructure inventory. Review and refine before submission."
            )
        },
    }


def _components(inventory: Inventory) -> List[dict]:
    """Emit one OSCAL component per distinct AWS resource type."""
    components: List[dict] = [
        {
            "uuid": _uuid_for("component", "this-system"),
            "type": "this-system",
            "title": inventory.system_name,
            "description": "The overall system described by this SSP.",
            "status": {"state": "under-development"},
        }
    ]
    for rtype, count in inventory.count_by_type().items():
        components.append(
            {
                "uuid": _uuid_for("component", rtype),
                "type": "service",
                "title": rtype,
                "description": f"{count} {rtype} resource(s) discovered in the inventory.",
                "props": [
                    {"name": "resource-type", "value": rtype},
                    {"name": "resource-count", "value": str(count)},
                ],
                "status": {"state": "operational"},
            }
        )
    return components


def _inventory_items(inventory: Inventory) -> List[dict]:
    items: List[dict] = []
    for resource in inventory.resources:
        props = [{"name": "resource-type", "value": resource.resource_type}]
        if resource.region:
            props.append({"name": "region", "value": str(resource.region)})
        if resource.identifier:
            props.append({"name": "asset-id", "value": str(resource.identifier)})
        items.append(
            {
                "uuid": _uuid_for("inventory-item", resource.resource_type, resource.display_name),
                "description": f"{resource.resource_type}: {resource.display_name}",
                "props": props,
                "implemented-components": [
                    {"component-uuid": _uuid_for("component", resource.resource_type)}
                ],
            }
        )
    return items


def _system_implementation(inventory: Inventory) -> dict:
    return {
        "users": [
            {
                "uuid": _uuid_for("user", "system-administrator"),
                "title": "System Administrator",
                "role-ids": ["system-owner"],
                "authorized-privileges": [
                    {
                        "title": "Full Administrative Access",
                        "functions-performed": ["Manage infrastructure and security controls"],
                    }
                ],
            }
        ],
        "components": _components(inventory),
        "inventory-items": _inventory_items(inventory),
    }


def _implemented_requirements(inventory: Inventory) -> List[dict]:
    control_map = map_resources_to_controls(inventory.resource_types())
    coverage = baseline_coverage(control_map.keys())

    requirements: List[dict] = []

    # Satisfied controls, with evidence linking back to components.
    for control_id in coverage["satisfied"]:
        contributing_types = sorted(control_map.get(control_id, []))
        statement = (
            f"This control is partially addressed by the following discovered "
            f"resource types: {', '.join(contributing_types)}. "
            f"({control_title(control_id)})"
        )
        requirements.append(
            {
                "uuid": _uuid_for("requirement", control_id),
                "control-id": control_id,
                "props": [{"name": "implementation-status", "value": "implemented"}],
                "statements": [
                    {
                        "statement-id": f"{control_id}_smt",
                        "uuid": _uuid_for("statement", control_id),
                        "description": statement,
                    }
                ],
                "by-components": [
                    {
                        "component-uuid": _uuid_for("component", rtype),
                        "uuid": _uuid_for("by-component", control_id, rtype),
                        "description": f"Implemented via {rtype} resources.",
                        "implementation-status": {"state": "implemented"},
                    }
                    for rtype in contributing_types
                ],
            }
        )

    # Always-required controls with no supporting resource -> planned.
    for control_id in coverage["planned"]:
        requirements.append(
            {
                "uuid": _uuid_for("requirement", control_id),
                "control-id": control_id,
                "props": [{"name": "implementation-status", "value": "planned"}],
                "statements": [
                    {
                        "statement-id": f"{control_id}_smt",
                        "uuid": _uuid_for("statement", control_id),
                        "description": (
                            f"No resource in the inventory currently satisfies this "
                            f"required control ({control_title(control_id)}). "
                            f"Implementation is planned."
                        ),
                    }
                ],
            }
        )

    return requirements


def _control_implementation(inventory: Inventory) -> dict:
    return {
        "description": (
            "Control implementation mapped from discovered AWS resources to the "
            "FedRAMP Moderate baseline (NIST SP 800-53 Rev 5). Each requirement "
            "is a draft starting point requiring human validation."
        ),
        "implemented-requirements": _implemented_requirements(inventory),
    }


def generate_ssp(inventory: Inventory, *, timestamp: Optional[str] = None) -> Dict:
    """Build a complete OSCAL 1.1.2 ``system-security-plan`` document.

    Args:
        inventory: Parsed resource inventory.
        timestamp: Optional ISO-8601 timestamp (mainly for deterministic tests).

    Returns:
        A dict ready to be serialised as OSCAL JSON.
    """
    ts = timestamp or _now()
    ssp = {
        "system-security-plan": {
            "uuid": _uuid_for("ssp", inventory.system_name),
            "metadata": _metadata(inventory.system_name, ts),
            "import-profile": {"href": FEDRAMP_MODERATE_PROFILE},
            "system-characteristics": _system_characteristics(inventory, ts),
            "system-implementation": _system_implementation(inventory),
            "control-implementation": _control_implementation(inventory),
        }
    }
    return ssp


def summarize(inventory: Inventory) -> Dict[str, object]:
    """Return a compact coverage summary used by the CLI and dashboard."""
    control_map = map_resources_to_controls(inventory.resource_types())
    coverage = baseline_coverage(control_map.keys())
    return {
        "system_name": inventory.system_name,
        "source": inventory.source,
        "resource_count": len(inventory),
        "resource_types": inventory.count_by_type(),
        "controls_satisfied": coverage["satisfied"],
        "controls_planned": coverage["planned"],
        "control_evidence": {c: sorted(t) for c, t in control_map.items()},
    }
