import json

import pytest

from oscal_ssp_generator.models import Inventory
from oscal_ssp_generator.parsers import (
    ParseError,
    parse,
    parse_json_inventory,
    parse_terraform_state,
)


def test_parse_terraform_state(tfstate_path):
    inv = parse_terraform_state(tfstate_path)
    assert isinstance(inv, Inventory)
    assert inv.source == "terraform"
    # System name pulled from outputs.
    assert inv.system_name == "ACME Health Patient Portal"
    assert "aws_s3_bucket" in inv.resource_types()
    assert len(inv) == 10


def test_terraform_resources_capture_identifier(tfstate_path):
    inv = parse_terraform_state(tfstate_path)
    s3 = next(r for r in inv.resources if r.resource_type == "aws_s3_bucket")
    assert s3.identifier == "arn:aws:s3:::acme-health-patient-data"
    assert s3.region == "us-east-1"


def test_parse_json_inventory(inventory_path):
    inv = parse_json_inventory(inventory_path)
    assert inv.source == "json_inventory"
    assert inv.system_name == "ACME Health Analytics Platform"
    counts = inv.count_by_type()
    assert counts["aws_s3_bucket"] == 2


def test_auto_detect_tfstate(tfstate_path):
    inv = parse(tfstate_path)
    assert inv.source == "terraform"


def test_auto_detect_json(inventory_path):
    inv = parse(inventory_path)
    assert inv.source == "json_inventory"


def test_missing_file_raises():
    with pytest.raises(ParseError):
        parse("does-not-exist.json")


def test_invalid_inventory_missing_resources(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"system_name": "x"}), encoding="utf-8")
    with pytest.raises(ParseError):
        parse_json_inventory(p)


def test_resource_missing_type_raises(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"resources": [{"name": "x"}]}), encoding="utf-8")
    with pytest.raises(ParseError):
        parse_json_inventory(p)


def test_non_aws_resources_skipped(tmp_path):
    state = {
        "terraform_version": "1.7.5",
        "resources": [
            {"type": "google_storage_bucket", "name": "g", "instances": [{"attributes": {}}]},
            {"type": "aws_s3_bucket", "name": "a", "instances": [{"attributes": {"id": "a"}}]},
        ],
    }
    p = tmp_path / "mixed.tfstate"
    p.write_text(json.dumps(state), encoding="utf-8")
    inv = parse_terraform_state(p)
    assert inv.resource_types() == ["aws_s3_bucket"]


def test_multiple_instances_get_indexed_names(tmp_path):
    state = {
        "terraform_version": "1.7.5",
        "resources": [
            {
                "type": "aws_instance",
                "name": "web",
                "instances": [
                    {"attributes": {"id": "i-1"}},
                    {"attributes": {"id": "i-2"}},
                ],
            }
        ],
    }
    p = tmp_path / "multi.tfstate"
    p.write_text(json.dumps(state), encoding="utf-8")
    inv = parse_terraform_state(p)
    names = sorted(r.name for r in inv.resources)
    assert names == ["web[0]", "web[1]"]
