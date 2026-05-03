"""
CLEARANCE Report Generator — V1.0
Converts a CLEARANCE engine run_record (JSON) into a human-readable
one-page Markdown summary report.

Usage:
    python3 CLEARANCE_Report_Generator_V1_0.py <run_record.json>

    Or import and call generate_report(run_record) directly.

Output:
    A Markdown string suitable for:
    - Saving as .md and converting to PDF
    - Pasting into a client-facing document
    - Forwarding internally as a risk summary
"""

import json
import sys
from datetime import datetime
from pathlib import Path


# ===================================================================
# SEVERITY LABELS
# ===================================================================

SEVERITY_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}

DEPLOYMENT_STATUS_BLOCKED  = "🚫  DEPLOYMENT BLOCKED"
DEPLOYMENT_STATUS_HIGH     = "⚠️   HIGH RISK — Review Required"
DEPLOYMENT_STATUS_MEDIUM   = "⚠️   MEDIUM RISK — Gaps Identified"
DEPLOYMENT_STATUS_CLEAR    = "✅  NO CRITICAL GAPS DETECTED"


# ===================================================================
# DEPLOYMENT STATUS LOGIC
# ===================================================================

def derive_deployment_status(summary):
    if summary.get("deployment_blocking", 0) > 0:
        return DEPLOYMENT_STATUS_BLOCKED
    if summary.get("critical", 0) > 0:
        return DEPLOYMENT_STATUS_BLOCKED
    if summary.get("high", 0) > 0:
        return DEPLOYMENT_STATUS_HIGH
    if summary.get("medium", 0) > 0:
        return DEPLOYMENT_STATUS_MEDIUM
    return DEPLOYMENT_STATUS_CLEAR


# ===================================================================
# REPORT GENERATOR
# ===================================================================

# ===================================================================
# SECTOR-AWARE REGULATORY FRAMEWORK TABLES
# ===================================================================

_REGULATORY_ROWS = {
    "Healthcare_US": [
        "| HIPAA Privacy Rule | PHI processing basis, purpose limitation, patient rights, retention |",
        "| HIPAA Security Rule | Administrative safeguards, technical safeguards, BAA requirements |",
        "| HIPAA Breach Notification Rule | 60-day notification obligations, incident response |",
        "| NIST AI RMF | Govern, Map, Measure, Manage functions — referenced per gap |",
        "| State AI Laws (CA, TX, CO, MD) | Patient disclosure, coverage decisions, high-risk AI — where states declared |",
        "| FTC Act §5 | Deceptive AI practices in healthcare (non-PHI clinical AI) |",
    ],
    "Healthcare": [
        "| UK GDPR | Lawful basis, purpose limitation, data subject rights, retention, DPA obligations |",
        "| Data Protection Act 2018 | UK implementation — special category data, automated decision-making |",
        "| DUAA 2025 | Digital information and automated decision accountability |",
        "| DCB0160 | Clinical risk management — safety case requirement for clinical AI |",
        "| CQC Regulation 12 | Safe care and treatment — clinical AI governance |",
        "| NIST AI RMF | Govern, Map, Measure, Manage functions — referenced per gap |",
    ],
    "Financial_Services": [
        "| UK GDPR / DPA 2018 | Lawful basis, automated decision-making, data subject rights |",
        "| FCA Consumer Duty | Good outcomes, fair treatment, suitability, consumer understanding |",
        "| SM&CR | Senior Manager accountability for AI in regulated activities |",
        "| FCA PS22/3 | Diversity and inclusion — algorithmic bias in financial services |",
        "| DUAA 2025 | Automated decision accountability |",
        "| NIST AI RMF | Govern, Map, Measure, Manage functions — referenced per gap |",
    ],
    "Legal": [
        "| UK GDPR / DPA 2018 | Client data processing, lawful basis, retention, subject access |",
        "| SRA Code of Conduct | Client disclosure obligations for AI use |",
        "| SRA AI Guidance 2024 | Solicitor duties when using AI in legal work |",
        "| Legal Services Act 2007 | Reserved activities — AI must not imply reserved legal advice |",
        "| DUAA 2025 | Automated decision accountability |",
        "| NIST AI RMF | Govern, Map, Measure, Manage functions — referenced per gap |",
    ],
    "Recruitment_HR": [
        "| UK GDPR / DPA 2018 | Lawful basis for employee data, automated decision-making, subject rights |",
        "| Equality Act 2010 | Algorithmic discrimination in hiring, performance, and disciplinary AI |",
        "| ICO Employment Guidance 2023 | AI in employment decisions — monitoring, scoring, termination |",
        "| DUAA 2025 | Automated decision accountability |",
        "| NIST AI RMF | Govern, Map, Measure, Manage functions — referenced per gap |",
    ],
}

_REGULATORY_MAPPING_REFS = {
    "Healthcare_US": "Full control-to-regulation mapping: **CLEARANCE_HIPAA_Mapping_V1_0.md**",
    "Healthcare":    "Full control-to-regulation mapping: **CLEARANCE_EU_Mapping_V1_0.json**",
    "default":       "Full control-to-regulation mapping available on request.",
}

_CORE_ROWS = [
    "| EU AI Act (where applicable) | High-risk AI classification, transparency, human oversight |",
]


def _regulatory_rows(sector: str) -> list:
    rows = _REGULATORY_ROWS.get(sector, [
        "| UK GDPR / DPA 2018 | Lawful basis, data subject rights, retention, automated decision-making |",
        "| DUAA 2025 | Automated decision accountability |",
        "| NIST AI RMF | Govern, Map, Measure, Manage functions — referenced per gap |",
    ])
    return rows + _CORE_ROWS


def _regulatory_mapping_ref(sector: str) -> str:
    return _REGULATORY_MAPPING_REFS.get(sector, _REGULATORY_MAPPING_REFS["default"])


def generate_report(run_record: dict) -> str:
    """
    Takes a CLEARANCE run_record dict and returns a Markdown report string.
    """

    # ── Header metadata
    run_id        = run_record.get("run_id", "N/A")
    timestamp     = run_record.get("run_timestamp", "N/A")
    engine_ver    = run_record.get("engine_version", "N/A")
    lib_ver       = run_record.get("library_version", "N/A")
    us_layer_ver  = run_record.get("us_layer_version")
    engagement    = run_record.get("engagement_ref", "N/A")
    sector        = run_record.get("sector", "N/A")
    eng_type      = run_record.get("engagement_type", "full")

    # ── Summary
    summary       = run_record.get("summary", {})
    gaps_total    = summary.get("gaps_triggered", 0)
    n_critical    = summary.get("critical", 0)
    n_high        = summary.get("high", 0)
    n_medium      = summary.get("medium", 0)
    n_blocking    = summary.get("deployment_blocking", 0)

    # ── Gaps
    all_gaps      = run_record.get("gaps", [])
    blockers      = [g for g in all_gaps if g.get("deployment_blocking")]
    critical_gaps = [g for g in all_gaps if g.get("severity") == "CRITICAL" and not g.get("deployment_blocking")]
    high_gaps     = [g for g in all_gaps if g.get("severity") == "HIGH"     and not g.get("deployment_blocking")]
    medium_gaps   = [g for g in all_gaps if g.get("severity") == "MEDIUM"]

    # ── State law notes
    state_notes   = run_record.get("state_law_notes", [])
    phi_in_scope  = run_record.get("phi_in_scope", False)
    states        = run_record.get("operating_states", [])

    # ── Deployment status
    status        = derive_deployment_status(summary)

    # ── Format timestamp
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        ts_display = dt.strftime("%d %B %Y, %H:%M UTC")
    except Exception:
        ts_display = timestamp

    lines = []

    # ════════════════════════════════════════════════════════════════
    # HEADER
    # ════════════════════════════════════════════════════════════════
    lines += [
        "# CLEARANCE — AI Governance Diagnostic Report",
        "",
        f"**Engagement Ref:** {engagement}  ",
        f"**Sector:** {sector}  ",
        f"**Engagement Type:** {eng_type.upper()}  ",
        f"**Run Date:** {ts_display}  ",
        f"**Run ID:** `{run_id}`  ",
        f"**Engine Version:** {engine_ver}  |  **Library:** {lib_ver}" +
            (f"  |  **US Layer:** {us_layer_ver}" if us_layer_ver else ""),
        "",
        "---",
        "",
    ]

    # ════════════════════════════════════════════════════════════════
    # DEPLOYMENT STATUS — the most important line
    # ════════════════════════════════════════════════════════════════
    lines += [
        "## Deployment Status",
        "",
        f"### {status}",
        "",
    ]

    if n_blocking > 0:
        lines += [
            f"> **{n_blocking} deployment-blocking gap{'s' if n_blocking > 1 else ''} identified.**  ",
            f"> This AI system must not be deployed or remain in production until all deployment blockers are resolved.",
            "",
        ]
    elif n_critical > 0:
        lines += [
            f"> **{n_critical} critical gap{'s' if n_critical > 1 else ''} identified.**  ",
            f"> Immediate remediation required before deployment.",
            "",
        ]
    elif n_high > 0:
        lines += [
            f"> **{n_high} high-severity gap{'s' if n_high > 1 else ''} identified.**  ",
            f"> Governance review and remediation required.",
            "",
        ]
    elif n_medium > 0:
        lines += [
            f"> **{n_medium} medium-severity gap{'s' if n_medium > 1 else ''} identified.**  ",
            f"> Gaps should be addressed before next compliance review.",
            "",
        ]
    else:
        lines += [
            "> No critical or high-severity gaps detected. Periodic review recommended.",
            "",
        ]

    lines += ["---", ""]

    # ════════════════════════════════════════════════════════════════
    # RISK SUMMARY
    # ════════════════════════════════════════════════════════════════
    lines += [
        "## Risk Summary",
        "",
        f"| Category | Count |",
        f"|---|---|",
        f"| 🚫 Deployment Blockers | **{n_blocking}** |",
        f"| 🔴 Critical | **{n_critical}** |",
        f"| 🟠 High | **{n_high}** |",
        f"| 🟡 Medium | **{n_medium}** |",
        f"| **Total gaps triggered** | **{gaps_total}** |",
        "",
    ]

    if phi_in_scope:
        lines += [
            f"**PHI in scope:** Yes  ",
            f"**Operating states:** {', '.join(states) if states else 'Not specified'}  ",
            "",
        ]

    lines += ["---", ""]

    # ════════════════════════════════════════════════════════════════
    # DEPLOYMENT BLOCKERS (most prominent section)
    # ════════════════════════════════════════════════════════════════
    if blockers:
        lines += [
            "## 🚫 Deployment Blockers",
            "",
            "These gaps must be remediated before this AI system is deployed or remains in production.",
            "",
        ]
        for g in blockers:
            icon = SEVERITY_ICON.get(g.get("severity", ""), "•")
            lines += [
                f"### {icon} {g.get('gap_id', g.get('id'))}",
                f"**{g.get('title', '')}**",
                "",
            ]
            if g.get("pain_line"):
                lines += [f"> {g['pain_line']}", ""]
            if g.get("regulatory_refs"):
                lines += ["**Regulatory basis:**"]
                for ref in g["regulatory_refs"][:3]:
                    lines += [f"- {ref}"]
                lines += [""]
            if g.get("what_happens_next"):
                lines += [f"**Next step:** {g['what_happens_next']}", ""]
        lines += ["---", ""]

    # ════════════════════════════════════════════════════════════════
    # CRITICAL + HIGH GAPS
    # ════════════════════════════════════════════════════════════════
    priority_gaps = critical_gaps + high_gaps
    if priority_gaps:
        lines += [
            "## High Priority Gaps",
            "",
        ]
        for g in priority_gaps:
            icon = SEVERITY_ICON.get(g.get("severity", ""), "•")
            lines += [
                f"### {icon} {g.get('gap_id', g.get('id'))}",
                f"**{g.get('title', '')}**  ",
                f"Severity: {g.get('severity', 'N/A')} | Plane: {g.get('plane', 'N/A')}",
                "",
            ]
            if g.get("pain_line"):
                lines += [f"> {g['pain_line']}", ""]
            if g.get("regulatory_refs"):
                lines += ["**Regulatory basis:**"]
                for ref in g["regulatory_refs"][:2]:
                    lines += [f"- {ref}"]
                lines += [""]
        lines += ["---", ""]

    # ════════════════════════════════════════════════════════════════
    # MEDIUM GAPS (condensed)
    # ════════════════════════════════════════════════════════════════
    if medium_gaps:
        lines += [
            "## Medium Priority Gaps",
            "",
            "| Gap ID | Title |",
            "|---|---|",
        ]
        for g in medium_gaps:
            lines += [f"| `{g.get('gap_id', g.get('id'))}` | {g.get('title', '')} |"]
        lines += [""]
        lines += ["---", ""]

    # ════════════════════════════════════════════════════════════════
    # STATE LAW NOTES
    # ════════════════════════════════════════════════════════════════
    if state_notes:
        lines += [
            "## State Law Applicability",
            "",
            "Based on operating states declared, the following state-level AI and healthcare obligations apply:",
            "",
        ]
        for note in state_notes:
            lines += [f"- {note}"]
        lines += ["", "---", ""]

    # ════════════════════════════════════════════════════════════════
    # REGULATORY ALIGNMENT FOOTER — sector-aware
    # ════════════════════════════════════════════════════════════════
    lines += [
        "## Regulatory Alignment",
        "",
        "This diagnostic evaluates AI governance against the following frameworks:",
        "",
        "| Framework | Coverage |",
        "|---|---|",
    ]
    lines += _regulatory_rows(sector)
    lines += [
        "",
        _regulatory_mapping_ref(sector),
        "",
        "---",
        "",
        "## About This Report",
        "",
        "This report was produced by the CLEARANCE AI Governance Diagnostic Engine.",
        "CLEARANCE applies a deterministic gap library to evaluate AI deployments against",
        "a defined set of governance failure patterns. Results are reproducible — the same",
        "intake produces the same output on every run.",
        "",
        "**This report is not legal advice.** For HIPAA compliance audits, engage a",
        "qualified HIPAA consultant. CLEARANCE is a diagnostic tool, not a certification.",
        "",
        f"*CLEARANCE Report Generator V1.0 | Run ID: {run_id}*  ",
        f"*Engine {engine_ver} | Library {lib_ver}" +
            (f" | US Layer {us_layer_ver}" if us_layer_ver else "") + "*",
        f"*Engagement: {engagement} | {ts_display}*",
    ]

    return "\n".join(lines)


# ===================================================================
# CLI ENTRY POINT
# ===================================================================

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 CLEARANCE_Report_Generator_V1_0.py <run_record.json>")
        print()
        print("Reads a CLEARANCE engine run_record JSON file and prints")
        print("a formatted Markdown report to stdout.")
        print()
        print("Example:")
        print("  python3 CLEARANCE_Engine_Evaluator_V1_3.py > run_record.json")
        print("  python3 CLEARANCE_Report_Generator_V1_0.py run_record.json > report.md")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    if not input_path.exists():
        print(f"Error: file not found: {input_path}")
        sys.exit(1)

    with open(input_path) as f:
        # Engine outputs terminal text then JSON — try to find JSON block
        raw = f.read()
        json_start = raw.find("{")
        if json_start == -1:
            print("Error: no JSON object found in input file")
            sys.exit(1)
        run_record = json.loads(raw[json_start:])

    report = generate_report(run_record)
    print(report)


if __name__ == "__main__":
    main()
