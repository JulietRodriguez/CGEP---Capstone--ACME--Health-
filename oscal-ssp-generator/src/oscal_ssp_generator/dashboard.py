"""Streamlit dashboard for oscal-ssp-generator.

Run with::

    streamlit run src/oscal_ssp_generator/dashboard.py

The dashboard lets a security engineer upload a Terraform state or JSON
inventory, preview the FedRAMP Moderate control coverage, and download the
generated OSCAL 1.1.2 SSP.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import streamlit as st

from oscal_ssp_generator import __version__
from oscal_ssp_generator.controls import CONTROL_CATALOG, control_title
from oscal_ssp_generator.generator import generate_ssp, summarize
from oscal_ssp_generator.parsers import ParseError, parse

# ---------------------------------------------------------------------------
# Page + theme
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="OSCAL SSP Generator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom dark "security tool" styling layered on top of the Streamlit theme.
st.markdown(
    """
    <style>
        .stApp { background-color: #0b0f17; }
        section[data-testid="stSidebar"] { background-color: #11161f; }
        h1, h2, h3, h4 { color: #e6edf3 !important; font-family: 'Segoe UI', sans-serif; }
        .metric-card {
            background: linear-gradient(145deg, #161b24, #0f141d);
            border: 1px solid #1f2937;
            border-radius: 10px;
            padding: 18px 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.4);
        }
        .metric-card .value { font-size: 2.2rem; font-weight: 700; color: #38bdf8; }
        .metric-card .label { font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.08em; }
        .badge-impl { color: #22c55e; font-weight: 600; }
        .badge-plan { color: #f59e0b; font-weight: 600; }
        .muted { color: #64748b; }
    </style>
    """,
    unsafe_allow_html=True,
)


def _metric(label: str, value, accent: str = "#38bdf8") -> str:
    return (
        f'<div class="metric-card"><div class="value" style="color:{accent}">'
        f"{value}</div><div class=\"label\">{label}</div></div>"
    )


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("## 🛡️ OSCAL SSP Generator")
    st.caption(f"v{__version__} · OSCAL 1.1.2 · FedRAMP Moderate")
    st.markdown("---")
    st.markdown("### Input")
    uploaded = st.file_uploader(
        "Terraform state (*.tfstate) or JSON inventory",
        type=["tfstate", "json"],
    )
    examples_dir = Path(__file__).resolve().parents[2] / "examples"
    example_choice = st.selectbox(
        "…or load a bundled example",
        ["(none)", "terraform.tfstate", "aws_inventory.json"],
    )
    st.markdown("---")
    st.markdown(
        '<span class="muted">Drafts produced here are starting points and '
        "require human validation before authorization submission.</span>",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Resolve the active input into a temp file path
# ---------------------------------------------------------------------------

def _resolve_input() -> Path | None:
    if uploaded is not None:
        suffix = ".tfstate" if uploaded.name.endswith(".tfstate") else ".json"
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        tmp.write(uploaded.getvalue())
        tmp.flush()
        return Path(tmp.name)
    if example_choice != "(none)":
        candidate = examples_dir / example_choice
        if candidate.exists():
            return candidate
    return None


st.markdown("# System Security Plan Dashboard")
st.markdown(
    '<span class="muted">Auto-generate a draft OSCAL 1.1.2 SSP from your '
    "cloud infrastructure inventory.</span>",
    unsafe_allow_html=True,
)

input_path = _resolve_input()

if input_path is None:
    st.info("Upload a file or select a bundled example from the sidebar to begin.")
    st.stop()

try:
    inventory = parse(input_path)
except ParseError as exc:
    st.error(f"Could not parse input: {exc}")
    st.stop()

summary = summarize(inventory)
ssp = generate_ssp(inventory)
requirements = ssp["system-security-plan"]["control-implementation"]["implemented-requirements"]

# ---------------------------------------------------------------------------
# Metrics row
# ---------------------------------------------------------------------------

c1, c2, c3, c4 = st.columns(4)
c1.markdown(_metric("Resources", summary["resource_count"]), unsafe_allow_html=True)
c2.markdown(_metric("Resource Types", len(summary["resource_types"])), unsafe_allow_html=True)
c3.markdown(
    _metric("Controls Implemented", len(summary["controls_satisfied"]), "#22c55e"),
    unsafe_allow_html=True,
)
c4.markdown(
    _metric("Controls Planned", len(summary["controls_planned"]), "#f59e0b"),
    unsafe_allow_html=True,
)

st.markdown("&nbsp;", unsafe_allow_html=True)
st.markdown(f"### System: `{summary['system_name']}`  ·  source: `{summary['source']}`")

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------

tab_controls, tab_resources, tab_oscal = st.tabs(
    ["🎯 Control Coverage", "📦 Inventory", "📄 OSCAL Document"]
)

with tab_controls:
    coverage_pct = 0
    catalog_total = len(CONTROL_CATALOG)
    if catalog_total:
        coverage_pct = int(100 * len(summary["controls_satisfied"]) / catalog_total)
    st.progress(coverage_pct / 100, text=f"Catalog coverage: {coverage_pct}%")

    evidence = summary["control_evidence"]
    rows = []
    for control in summary["controls_satisfied"]:
        rows.append(
            {
                "Control": control,
                "Title": control_title(control),
                "Status": "✅ implemented",
                "Evidence": ", ".join(evidence.get(control, [])),
            }
        )
    for control in summary["controls_planned"]:
        rows.append(
            {
                "Control": control,
                "Title": control_title(control),
                "Status": "🟡 planned",
                "Evidence": "—",
            }
        )
    st.dataframe(rows, use_container_width=True, hide_index=True)

with tab_resources:
    st.markdown("#### Resource counts by type")
    counts = summary["resource_types"]
    st.bar_chart(counts)
    st.dataframe(
        [{"Resource Type": k, "Count": v} for k, v in counts.items()],
        use_container_width=True,
        hide_index=True,
    )

with tab_oscal:
    st.markdown(f"#### OSCAL 1.1.2 SSP · {len(requirements)} implemented requirements")
    pretty = json.dumps(ssp, indent=2)
    st.download_button(
        "⬇️ Download OSCAL SSP (JSON)",
        data=pretty,
        file_name="ssp.json",
        mime="application/json",
        type="primary",
    )
    st.json(ssp, expanded=False)
