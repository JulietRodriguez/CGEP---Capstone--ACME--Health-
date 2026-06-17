# 🛡️ oscal-ssp-generator

> Auto-generate draft **OSCAL 1.1.2 System Security Plans** from Terraform state or AWS resource inventories — mapped to the **FedRAMP Moderate** baseline (NIST SP 800-53 Rev 5).

[![CI](https://github.com/JulietRodriguez/oscal-ssp-generator/actions/workflows/ci.yml/badge.svg)](https://github.com/JulietRodriguez/oscal-ssp-generator/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![OSCAL](https://img.shields.io/badge/OSCAL-1.1.2-7c3aed.svg)](https://pages.nist.gov/OSCAL/)
[![Baseline](https://img.shields.io/badge/FedRAMP-Moderate-22c55e.svg)](https://www.fedramp.gov/)
[![NIST 800-53](https://img.shields.io/badge/NIST_800--53-Rev_5-0ea5e9.svg)](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

Authoring a System Security Plan by hand is slow and error-prone. `oscal-ssp-generator`
reads what you've actually deployed — your Terraform state or a simple JSON inventory —
and produces a **draft, machine-readable OSCAL SSP** with control implementation statements
already wired to the resources that satisfy them. It's a starting point your security
engineers refine, not a rubber stamp.

## ✨ Features

| Capability | Description |
| --- | --- |
| 🧩 **Dual input formats** | Parse a Terraform `*.tfstate` file or a simple JSON AWS inventory — format auto-detected. |
| 📄 **OSCAL 1.1.2 output** | Emits a compliant `system-security-plan` with metadata, system characteristics, system implementation, **system information**, and control implementation. |
| 🎯 **FedRAMP Moderate mapping** | 28+ AWS resource types mapped to NIST 800-53 Rev 5 controls, with always-required controls surfaced as *planned* when no resource satisfies them. |
| 🖥️ **Rich CLI** | Color terminal summary of resources and control coverage, plus JSON export. |
| 📊 **Streamlit dashboard** | Dark, security-tool styled UI to upload inventory, inspect coverage, and download the SSP. |
| 🔁 **Deterministic UUIDs** | Stable `uuid5`-based identifiers so re-runs diff cleanly in git. |
| ✅ **Tested & CI'd** | Full pytest suite + GitHub Actions matrix across Python 3.9–3.12. |

## 🏗️ Architecture

```
                         ┌────────────────────────────┐
   Terraform state  ───► │           parsers          │
   AWS JSON inventory ─► │  (auto-detect → Inventory)  │
                         └─────────────┬──────────────┘
                                       │ Inventory(resources, system_name)
                                       ▼
                         ┌────────────────────────────┐
                         │          controls          │
                         │  AWS type → 800-53 Rev 5    │
                         │  FedRAMP Moderate baseline  │
                         └─────────────┬──────────────┘
                                       │ control map + coverage
                                       ▼
                         ┌────────────────────────────┐
                         │          generator         │
                         │  build OSCAL 1.1.2 SSP:     │
                         │   • metadata                │
                         │   • system-characteristics  │
                         │   • system-information      │
                         │   • system-implementation   │
                         │   • control-implementation  │
                         └──────┬───────────────┬──────┘
                                │               │
                     ┌──────────▼─────┐  ┌──────▼───────────┐
                     │   Rich CLI     │  │  Streamlit dash  │
                     │  (cli.py)      │  │  (dashboard.py)  │
                     └────────────────┘  └──────────────────┘
                                │               │
                                ▼               ▼
                          ssp.json  +  control coverage views
```

## 🚀 Installation

```bash
git clone https://github.com/JulietRodriguez/oscal-ssp-generator.git
cd oscal-ssp-generator
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## 🧪 Usage

### CLI

Render a coverage summary in the terminal:

```bash
oscal-ssp-generator examples/terraform.tfstate
```

Write the OSCAL SSP to a file:

```bash
oscal-ssp-generator examples/aws_inventory.json -o ssp.json
```

Pipe the raw OSCAL JSON to another tool:

```bash
oscal-ssp-generator examples/terraform.tfstate --json | jq '.["system-security-plan"].metadata'
```

| Flag | Purpose |
| --- | --- |
| `-o, --output PATH` | Write the OSCAL SSP JSON to a file. |
| `--json` | Print the OSCAL JSON to stdout instead of the summary. |
| `--no-banner` | Suppress the ASCII banner. |
| `--version` | Print the version and exit. |

### Streamlit dashboard

```bash
streamlit run src/oscal_ssp_generator/dashboard.py
```

Then upload a `*.tfstate` / `*.json` file (or pick a bundled example) to explore
control coverage and download the generated SSP. The dashboard ships with a dark
theme via [`.streamlit/config.toml`](.streamlit/config.toml).

### Python API

```python
from oscal_ssp_generator.parsers import parse
from oscal_ssp_generator.generator import generate_ssp, summarize

inventory = parse("examples/aws_inventory.json")
ssp = generate_ssp(inventory)          # dict -> dump as OSCAL JSON
summary = summarize(inventory)         # compact coverage summary
```

## 📥 Input formats

**Simple JSON inventory:**

```json
{
  "system_name": "My System",
  "resources": [
    { "type": "aws_s3_bucket", "name": "data", "arn": "arn:aws:s3:::data", "region": "us-east-1" }
  ]
}
```

**Terraform state** — the standard `*.tfstate` schema is read directly; the system
name is pulled from a `system_name` output when present. See
[`examples/terraform.tfstate`](examples/terraform.tfstate).

## 🗂️ Control mapping

Mappings live in [`src/oscal_ssp_generator/controls.py`](src/oscal_ssp_generator/controls.py).
A few examples:

| AWS resource | Controls |
| --- | --- |
| `aws_s3_bucket` | SC-13, SC-28, AC-3, AU-9 |
| `aws_kms_key` | SC-12, SC-13, SC-28 |
| `aws_cloudtrail` | AU-2, AU-3, AU-6, AU-9, AU-12 |
| `aws_security_group` | SC-7, AC-4, CA-3 |
| `aws_guardduty_detector` | SI-4, RA-5 |
| `aws_db_instance` | SC-28, CP-9, CP-10, AU-2 |

Controls in `ALWAYS_REQUIRED_CONTROLS` that no resource satisfies are emitted with
implementation status **`planned`**, so gaps are visible rather than silently dropped.

## ✅ Development

```bash
pytest                       # run the suite
pytest --cov=oscal_ssp_generator --cov-report=term-missing
```

CI runs the suite plus a CLI smoke test across Python 3.9–3.12 via
[GitHub Actions](.github/workflows/ci.yml).

## ⚠️ Disclaimer

This tool produces a **draft** SSP intended to accelerate authoring. It is **not** an
authoritative control allocation and does not constitute compliance. Every generated
requirement must be reviewed and validated by qualified security personnel before use
in an authorization package.

## 📜 License

[MIT](LICENSE)
