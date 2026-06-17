import json
from pathlib import Path

import pytest

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


@pytest.fixture
def tfstate_path() -> Path:
    return EXAMPLES / "terraform.tfstate"


@pytest.fixture
def inventory_path() -> Path:
    return EXAMPLES / "aws_inventory.json"


@pytest.fixture
def tmp_json_inventory(tmp_path) -> Path:
    data = {
        "system_name": "Test System",
        "resources": [
            {"type": "aws_s3_bucket", "name": "b1", "arn": "arn:aws:s3:::b1"},
            {"type": "aws_kms_key", "name": "k1", "arn": "arn:aws:kms:...:key/1"},
        ],
    }
    p = tmp_path / "inv.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p
