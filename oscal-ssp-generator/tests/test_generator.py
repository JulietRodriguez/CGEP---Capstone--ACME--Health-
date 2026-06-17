from oscal_ssp_generator import OSCAL_VERSION
from oscal_ssp_generator.generator import generate_ssp, summarize
from oscal_ssp_generator.parsers import parse


def _ssp(path):
    return generate_ssp(parse(path), timestamp="2026-06-17T00:00:00+00:00")


def test_top_level_structure(tfstate_path):
    ssp = _ssp(tfstate_path)
    assert "system-security-plan" in ssp
    root = ssp["system-security-plan"]
    for key in (
        "uuid",
        "metadata",
        "import-profile",
        "system-characteristics",
        "system-implementation",
        "control-implementation",
    ):
        assert key in root, f"missing {key}"


def test_metadata_oscal_version(tfstate_path):
    ssp = _ssp(tfstate_path)
    meta = ssp["system-security-plan"]["metadata"]
    assert meta["oscal-version"] == OSCAL_VERSION
    assert "title" in meta


def test_system_characteristics_has_system_information(tfstate_path):
    ssp = _ssp(tfstate_path)
    sc = ssp["system-security-plan"]["system-characteristics"]
    assert sc["security-sensitivity-level"] == "fips-199-moderate"
    info_types = sc["system-information"]["information-types"]
    assert info_types and "confidentiality-impact" in info_types[0]


def test_system_implementation_components_and_inventory(tfstate_path):
    ssp = _ssp(tfstate_path)
    si = ssp["system-security-plan"]["system-implementation"]
    # this-system component + one per resource type.
    titles = [c["title"] for c in si["components"]]
    assert any(c["type"] == "this-system" for c in si["components"])
    assert "aws_s3_bucket" in titles
    assert len(si["inventory-items"]) == 10


def test_control_implementation_requirements(tfstate_path):
    ssp = _ssp(tfstate_path)
    ci = ssp["system-security-plan"]["control-implementation"]
    reqs = ci["implemented-requirements"]
    control_ids = {r["control-id"] for r in reqs}
    # S3 + KMS present -> SC-28 implemented.
    assert "SC-28" in control_ids
    # Every requirement carries an implementation-status prop.
    for req in reqs:
        statuses = [p["value"] for p in req["props"] if p["name"] == "implementation-status"]
        assert statuses and statuses[0] in {"implemented", "planned"}


def test_implemented_requirement_links_components(tfstate_path):
    ssp = _ssp(tfstate_path)
    reqs = ssp["system-security-plan"]["control-implementation"]["implemented-requirements"]
    sc28 = next(r for r in reqs if r["control-id"] == "SC-28")
    comp_uuids = [bc["component-uuid"] for bc in sc28["by-components"]]
    assert comp_uuids  # has evidence components


def test_deterministic_output(tfstate_path):
    a = _ssp(tfstate_path)
    b = _ssp(tfstate_path)
    assert a == b  # same input + timestamp -> identical document


def test_summarize(tfstate_path):
    summary = summarize(parse(tfstate_path))
    assert summary["resource_count"] == 10
    assert "SC-28" in summary["controls_satisfied"]
    assert isinstance(summary["controls_planned"], list)
