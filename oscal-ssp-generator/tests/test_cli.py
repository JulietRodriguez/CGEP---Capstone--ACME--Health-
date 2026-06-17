import json

from oscal_ssp_generator.cli import main


def test_cli_summary_runs(tfstate_path, capsys):
    code = main([str(tfstate_path), "--no-banner"])
    out = capsys.readouterr().out
    assert code == 0
    assert "System Overview" in out
    assert "aws_s3_bucket" in out


def test_cli_json_output(inventory_path, capsys):
    code = main([str(inventory_path), "--json"])
    out = capsys.readouterr().out
    assert code == 0
    data = json.loads(out)
    assert "system-security-plan" in data


def test_cli_writes_output_file(tfstate_path, tmp_path, capsys):
    out_file = tmp_path / "ssp.json"
    code = main([str(tfstate_path), "-o", str(out_file), "--no-banner"])
    assert code == 0
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["system-security-plan"]["metadata"]["oscal-version"] == "1.1.2"


def test_cli_no_input_returns_1(capsys):
    code = main([])
    assert code == 1


def test_cli_bad_input_returns_2(capsys):
    code = main(["nonexistent-file.json"])
    assert code == 2
    err = capsys.readouterr().out
    assert "Error" in err
