from oscal_ssp_generator.controls import (
    ALWAYS_REQUIRED_CONTROLS,
    CONTROL_CATALOG,
    RESOURCE_CONTROL_MAP,
    baseline_coverage,
    control_title,
    controls_for_resource_type,
    map_resources_to_controls,
)


def test_every_mapped_control_is_in_catalog():
    for controls in RESOURCE_CONTROL_MAP.values():
        for control in controls:
            assert control in CONTROL_CATALOG, f"{control} missing from catalog"


def test_always_required_controls_in_catalog():
    for control in ALWAYS_REQUIRED_CONTROLS:
        assert control in CONTROL_CATALOG


def test_controls_for_known_resource():
    controls = controls_for_resource_type("aws_kms_key")
    assert "SC-13" in controls
    assert "SC-28" in controls


def test_controls_for_unknown_resource_is_empty():
    assert controls_for_resource_type("aws_made_up") == []


def test_map_resources_to_controls():
    mapping = map_resources_to_controls(["aws_s3_bucket", "aws_kms_key"])
    assert "SC-28" in mapping
    assert mapping["SC-28"] == {"aws_s3_bucket", "aws_kms_key"}


def test_control_title_known_and_unknown():
    assert control_title("SC-7") == "Boundary Protection"
    assert control_title("ZZ-9") == "ZZ-9"


def test_baseline_coverage_marks_missing_as_planned():
    coverage = baseline_coverage(["SC-7"])
    assert "SC-7" in coverage["satisfied"]
    # AC-2 is always-required but not satisfied here.
    assert "AC-2" in coverage["planned"]
    assert "SC-7" not in coverage["planned"]
