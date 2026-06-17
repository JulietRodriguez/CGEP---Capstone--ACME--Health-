"""FedRAMP Moderate baseline control mapping (NIST SP 800-53 Rev 5).

This module provides:

* ``CONTROL_CATALOG`` -- a curated subset of NIST 800-53 Rev 5 controls that
  are part of the FedRAMP Moderate baseline, with human readable titles.
* ``RESOURCE_CONTROL_MAP`` -- a mapping from AWS resource types to the set of
  controls those resources help satisfy.
* helper functions to resolve controls for a collection of resources.

The mapping is intentionally pragmatic rather than exhaustive: it is meant to
produce a useful *draft* SSP that a security engineer can refine, not to be an
authoritative control allocation.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Set

# ---------------------------------------------------------------------------
# Control catalog (subset of FedRAMP Moderate / NIST 800-53 Rev 5)
# ---------------------------------------------------------------------------

#: Control id -> human readable title.
CONTROL_CATALOG: Dict[str, str] = {
    "AC-2": "Account Management",
    "AC-3": "Access Enforcement",
    "AC-4": "Information Flow Enforcement",
    "AC-6": "Least Privilege",
    "AC-17": "Remote Access",
    "AU-2": "Event Logging",
    "AU-3": "Content of Audit Records",
    "AU-6": "Audit Record Review, Analysis, and Reporting",
    "AU-9": "Protection of Audit Information",
    "AU-12": "Audit Record Generation",
    "CA-3": "Information Exchange",
    "CM-2": "Baseline Configuration",
    "CM-3": "Configuration Change Control",
    "CM-6": "Configuration Settings",
    "CM-8": "System Component Inventory",
    "CP-9": "System Backup",
    "CP-10": "System Recovery and Reconstitution",
    "IA-2": "Identification and Authentication (Organizational Users)",
    "IA-5": "Authenticator Management",
    "IR-6": "Incident Reporting",
    "RA-5": "Vulnerability Monitoring and Scanning",
    "SC-7": "Boundary Protection",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-12": "Cryptographic Key Establishment and Management",
    "SC-13": "Cryptographic Protection",
    "SC-28": "Protection of Information at Rest",
    "SI-3": "Malicious Code Protection",
    "SI-4": "System Monitoring",
}

# ---------------------------------------------------------------------------
# Resource type -> controls mapping
# ---------------------------------------------------------------------------

#: AWS resource type -> list of controls the resource contributes to.
RESOURCE_CONTROL_MAP: Dict[str, List[str]] = {
    "aws_s3_bucket": ["SC-13", "SC-28", "AC-3", "AU-9"],
    "aws_s3_bucket_server_side_encryption_configuration": ["SC-13", "SC-28"],
    "aws_security_group": ["SC-7", "AC-4", "CA-3"],
    "aws_vpc": ["SC-7", "AC-4"],
    "aws_subnet": ["SC-7"],
    "aws_network_acl": ["SC-7", "AC-4"],
    "aws_iam_role": ["AC-2", "AC-3", "AC-6", "IA-2"],
    "aws_iam_policy": ["AC-3", "AC-6"],
    "aws_iam_user": ["AC-2", "IA-2", "IA-5"],
    "aws_iam_group": ["AC-2", "AC-6"],
    "aws_kms_key": ["SC-12", "SC-13", "SC-28"],
    "aws_cloudtrail": ["AU-2", "AU-3", "AU-6", "AU-9", "AU-12"],
    "aws_config_configuration_recorder": ["CM-2", "CM-3", "CM-6"],
    "aws_config_config_rule": ["CM-6", "CM-3"],
    "aws_guardduty_detector": ["SI-4", "RA-5"],
    "aws_inspector2_enabler": ["RA-5", "SI-4"],
    "aws_db_instance": ["SC-28", "CP-9", "CP-10", "AU-2"],
    "aws_rds_cluster": ["SC-28", "CP-9", "CP-10"],
    "aws_instance": ["CM-2", "CM-8", "SC-7"],
    "aws_cloudwatch_log_group": ["AU-2", "AU-6", "AU-9"],
    "aws_cloudwatch_metric_alarm": ["AU-6", "SI-4"],
    "aws_sns_topic": ["IR-6", "SI-4"],
    "aws_wafv2_web_acl": ["SC-7", "SI-3"],
    "aws_lb": ["SC-7", "SC-8"],
    "aws_lb_listener": ["SC-8", "SC-13"],
    "aws_acm_certificate": ["SC-8", "SC-12", "SC-13"],
    "aws_backup_plan": ["CP-9", "CP-10"],
    "aws_ebs_volume": ["SC-28"],
    "aws_efs_file_system": ["SC-28", "SC-13"],
}

#: Controls that every FedRAMP Moderate system is expected to address even when
#: no specific resource maps to them. These are emitted as "planned" so the
#: draft SSP surfaces the gap instead of silently dropping the requirement.
ALWAYS_REQUIRED_CONTROLS: List[str] = [
    "AC-2",
    "AU-2",
    "CM-8",
    "IA-2",
    "SC-7",
    "SC-13",
    "SC-28",
    "SI-4",
]


def controls_for_resource_type(resource_type: str) -> List[str]:
    """Return the controls associated with a single AWS resource type."""
    return list(RESOURCE_CONTROL_MAP.get(resource_type, []))


def map_resources_to_controls(resource_types: Iterable[str]) -> Dict[str, Set[str]]:
    """Map a collection of resource types to the controls they satisfy.

    Returns a dict of ``control_id -> set(resource_type)`` describing which
    resource types contribute evidence toward each control.
    """
    mapping: Dict[str, Set[str]] = {}
    for rtype in resource_types:
        for control in controls_for_resource_type(rtype):
            mapping.setdefault(control, set()).add(rtype)
    return mapping


def control_title(control_id: str) -> str:
    """Return a human readable title for a control id (or the id if unknown)."""
    return CONTROL_CATALOG.get(control_id, control_id)


def baseline_coverage(satisfied: Iterable[str]) -> Dict[str, List[str]]:
    """Summarise FedRAMP Moderate coverage for the catalog subset.

    Returns ``{"satisfied": [...], "planned": [...]}`` where *planned* are
    always-required controls that no resource currently satisfies.
    """
    satisfied_set = set(satisfied)
    planned = [c for c in ALWAYS_REQUIRED_CONTROLS if c not in satisfied_set]
    return {
        "satisfied": sorted(satisfied_set),
        "planned": sorted(planned),
    }
