"""Parsers that turn Terraform state or a JSON inventory into an :class:`Inventory`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Union

from .models import Inventory, Resource

PathLike = Union[str, Path]


class ParseError(ValueError):
    """Raised when an input file cannot be understood."""


def _load_json(path: PathLike) -> dict:
    p = Path(path)
    if not p.exists():
        raise ParseError(f"Input file not found: {p}")
    try:
        with p.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:  # pragma: no cover - error path
        raise ParseError(f"Invalid JSON in {p}: {exc}") from exc


def _looks_like_tfstate(data: dict) -> bool:
    return "terraform_version" in data or ("resources" in data and "format_version" in data) or (
        "resources" in data and any(isinstance(r, dict) and "instances" in r for r in data.get("resources", []))
    )


def parse_terraform_state(path: PathLike) -> Inventory:
    """Parse a Terraform state file (``*.tfstate``).

    Supports the standard Terraform state schema where each resource entry has
    ``type``, ``name`` and a list of ``instances``.
    """
    data = _load_json(path)
    resources: list[Resource] = []

    for entry in data.get("resources", []):
        rtype = entry.get("type")
        # Only AWS resources are mapped to controls for now.
        if not rtype or not str(rtype).startswith("aws_"):
            continue
        rname = entry.get("name", rtype)
        instances = entry.get("instances") or [{}]
        for idx, instance in enumerate(instances):
            attrs = instance.get("attributes", {}) if isinstance(instance, dict) else {}
            identifier = attrs.get("arn") or attrs.get("id")
            region = attrs.get("region") or attrs.get("availability_zone")
            inst_name = rname if len(instances) == 1 else f"{rname}[{idx}]"
            resources.append(
                Resource(
                    resource_type=rtype,
                    name=inst_name,
                    identifier=identifier,
                    region=region,
                    attributes=attrs if isinstance(attrs, dict) else {},
                )
            )

    system_name = _derive_system_name(data, default="Terraform-Managed System")
    return Inventory(resources=resources, system_name=system_name, source="terraform")


def parse_json_inventory(path: PathLike) -> Inventory:
    """Parse a simple JSON inventory of AWS resources.

    Expected schema::

        {
          "system_name": "My System",
          "resources": [
            {"type": "aws_s3_bucket", "name": "data", "arn": "...", "region": "us-east-1"}
          ]
        }
    """
    data = _load_json(path)
    raw_resources = data.get("resources")
    if raw_resources is None:
        raise ParseError("JSON inventory must contain a top-level 'resources' list")

    resources: list[Resource] = []
    for item in raw_resources:
        if not isinstance(item, dict):
            raise ParseError(f"Each resource must be an object, got: {type(item).__name__}")
        rtype = item.get("type") or item.get("resource_type")
        if not rtype:
            raise ParseError("Each resource requires a 'type' field")
        resources.append(
            Resource(
                resource_type=rtype,
                name=item.get("name", rtype),
                identifier=item.get("arn") or item.get("id") or item.get("identifier"),
                provider=item.get("provider", "aws"),
                region=item.get("region"),
                attributes={k: v for k, v in item.items() if k not in {"type", "resource_type", "name"}},
            )
        )

    system_name = data.get("system_name", "AWS Inventory System")
    return Inventory(resources=resources, system_name=system_name, source="json_inventory")


def parse(path: PathLike) -> Inventory:
    """Auto-detect the input format and parse it.

    Detection rules:

    * ``*.tfstate`` extension or Terraform-shaped JSON -> Terraform state.
    * Otherwise -> simple JSON inventory.
    """
    p = Path(path)
    data = _load_json(p)
    if p.suffix == ".tfstate" or _looks_like_tfstate(data):
        return parse_terraform_state(p)
    return parse_json_inventory(p)


def _derive_system_name(data: dict, default: str) -> str:
    outputs = data.get("outputs") or {}
    for key in ("system_name", "project_name", "name"):
        node = outputs.get(key)
        if isinstance(node, dict) and node.get("value"):
            return str(node["value"])
    return default
