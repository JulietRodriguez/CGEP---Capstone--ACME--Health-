"""Lightweight data models shared across the generator."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Resource:
    """A single discovered cloud resource.

    Attributes:
        resource_type: Provider resource type, e.g. ``aws_s3_bucket``.
        name: Logical name (Terraform address name or inventory ``name``).
        identifier: Real-world id (ARN / physical id) when available.
        provider: Cloud provider, defaults to ``aws``.
        region: AWS region when known.
        attributes: Free-form attributes captured for context.
    """

    resource_type: str
    name: str
    identifier: Optional[str] = None
    provider: str = "aws"
    region: Optional[str] = None
    attributes: Dict[str, object] = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        return self.identifier or self.name


@dataclass
class Inventory:
    """A parsed collection of resources plus system-level metadata."""

    resources: List[Resource] = field(default_factory=list)
    system_name: str = "Untitled System"
    source: str = "unknown"

    def resource_types(self) -> List[str]:
        """Return the distinct resource types, sorted."""
        return sorted({r.resource_type for r in self.resources})

    def count_by_type(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for r in self.resources:
            counts[r.resource_type] = counts.get(r.resource_type, 0) + 1
        return dict(sorted(counts.items()))

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self.resources)
