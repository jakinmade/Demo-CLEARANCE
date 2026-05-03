#!/usr/bin/env python3
"""
CLEARANCE GAP Engine Evaluator v1.1
====================================
Changes from v1.0:
  - Run traceability: every execution stamped with run_id (UUID4),
    run_timestamp (ISO 8601), library_version, and engine_version.
  - Section L fields added to INTAKE (US Healthcare supplement):
    L1_handles_phi, L2_baa_in_place, L3_phi_type, L4_access_control,
    L5_patient_disclosure, L6_operating_states.
  - US-specific signals derived from Section L fields:
    has_phi_no_baa, has_phi_no_access_control, has_phi_no_disclosure.
  - US-HC gaps re-wired to use sharpened L-field signals where applicable.
  - Structured JSON summary output: run_record dict returned from
    run_engine() — machine-readable, report-template-ready.
  - Intake guard extended to validate required L fields for Healthcare_US.

Usage:
    python CLEARANCE_Engine_Evaluator_V1_1.py

Output:
    - Terminal: signals, gap evaluation, summary (unchanged)
    - Return: (triggered, signals, run_record) — run_record is the
      structured JSON summary ready for report template or API response.
"""

import hashlib
import hmac
import json
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path

ENGINE_VERSION   = "1.5"
LIBRARY_VERSION  = "1.9.4"
US_LAYER_VERSION = "1.4.0"

# ===================================================================
# INTAKE — structured answers from the completed intake form.
# Replace these values for each new engagement.
# All answers map directly to intake form questions.
# ===================================================================
INTAKE = {
    # Section B
    "B4_live":          True,   # B4: system is live or active pilot
    "B2_high_impact":   True,   # B2: high-impact decision (financial, clinical, safety)

    # Section C
    "C1_automated":     True,   # C1: system makes decisions automatically
    "C2_ruleset":       False,  # C2: defined ruleset governing what system can decide
    "C2a_enforced":     False,  # C2a: rules documented, version-controlled, enforced at runtime

    # Section D
    "D1_external_data": True,   # D1: consumes external data sources
    "D2_traceable":     False,  # D2: can trace every input to origin/owner/last update
    "D3_validated":     False,  # D3: validation step on input data quality

    # Section E
    "E1_logging":       False,  # E1: logging exists for decisions
    "E2_audit_trail":   False,  # E2: sealed audit trail exists

    # Section F
    "F1_override":      False,  # F1: human override mechanism exists
    "F2_accountable":   False,  # F2: named accountable individual exists

    # Section G
    "G1_incidents":     True,   # G1: incidents, near-misses or complaints disclosed
    "G1a_corrective":   False,  # G1a: corrective action taken following incident

    # Section H — HR sector only (set False if not HR)
    "H_employee_monitoring":    False,
    "H_monitoring_disclosure":  False,
    "H_performance_scoring":    False,
    "H_disciplinary_ai":        False,
    "H_workforce_analytics":    False,
    "H_termination_ai":         False,

    # Section I — Legal sector only (set False if not Legal)
    "I1_legal_drafting":        False,
    "I2_legal_advice":          False,
    "I3_client_data":           False,
    "I4_client_disclosure":     False,

    # Section J — Financial Services only (set False if not FS)
    "J1_suitability_ai":        False,
    "J2_smcr_owner":            False,
    "J3_outcome_monitoring":    False,
    "J4_bias_assessment":       False,

    # Section L — US Healthcare only (set False / None if not Healthcare_US)
    # These fields are REQUIRED when sector = "Healthcare_US"
    "L1_handles_phi":           True,   # L1: system processes or accesses Protected Health Information
    "L2_baa_in_place":          False,  # L2: Business Associate Agreements in place covering AI vendors
    "L3_phi_type":              "clinical_notes",  # L3: type of PHI (clinical_notes | imaging | billing | mixed | none)
    "L4_access_control":        False,  # L4: documented access controls on PHI processed by AI
    "L5_patient_disclosure":    False,  # L5: patients informed when AI influences their care
    "L6_operating_states":      ["TX", "CO"],  # L6: US states where system operates (drives state law applicability)
    # v1.3 — Security Rule supplement
    "L7_phi_encrypted":         False,  # L7: PHI encrypted at rest and in transit through AI pipeline
    "L8_incident_response_plan": False, # L8: documented incident response plan covers AI-specific PHI breach scenarios
    "L9_uses_external_ai_api":  True,   # L9: PHI transmitted to third-party AI APIs (OpenAI, Anthropic, Azure OpenAI, etc.)

    # Sector
    "sector": "Healthcare_US",  # Healthcare | Healthcare_US | Financial Services | Legal | Recruitment/HR

    # Engagement type
    "engagement_type": "full",  # "lite" | "full"

    # Engagement reference — required in v1.1
    "engagement_ref": "CLR-US-0001",
}


# ===================================================================
# SIGNAL RESOLVER
# Derives boolean signals from intake answers.
# One rule per signal. No interpretation.
# v1.1 adds: has_phi_no_baa, has_phi_no_access_control,
#             has_phi_no_disclosure derived from Section L fields.
# ===================================================================
def resolve_signals(intake):
    signals = {}

    # Universal signals
    signals["has_automated_decision"]       = intake["C1_automated"] and intake["B4_live"]
    signals["no_rule_enforcement"]          = not intake["C2_ruleset"] or not intake["C2a_enforced"]
    signals["has_external_data"]            = intake["D1_external_data"]
    signals["has_weak_validation"]          = not intake["D2_traceable"] or not intake["D3_validated"]
    signals["no_logging"]                   = not intake["E1_logging"]
    signals["no_audit_trail"]               = not intake["E2_audit_trail"]
    signals["has_high_impact_no_override"]  = intake["B2_high_impact"] and not intake["F1_override"]
    signals["has_incidents"]                = intake["G1_incidents"]
    signals["no_corrective_action"]         = intake["G1_incidents"] and not intake["G1a_corrective"]

    # HR signals
    signals["has_employee_monitoring_ai"]           = intake["H_employee_monitoring"]
    signals["no_employee_monitoring_disclosure"]    = intake["H_employee_monitoring"] and not intake["H_monitoring_disclosure"]
    signals["has_performance_scoring_ai"]           = intake["H_performance_scoring"]
    signals["has_disciplinary_ai"]                  = intake["H_disciplinary_ai"]
    signals["uses_ai_for_workforce_analytics"]      = intake["H_workforce_analytics"]
    signals["has_ai_in_termination_process"]        = intake["H_termination_ai"]

    # Legal signals
    signals["uses_ai_for_legal_drafting"]   = intake["I1_legal_drafting"]
    signals["no_client_ai_disclosure"]      = intake["I1_legal_drafting"] and not intake["I4_client_disclosure"]
    signals["uses_ai_for_legal_advice"]     = intake["I2_legal_advice"]
    signals["uses_ai_with_client_data"]     = intake["I3_client_data"]

    # FS signals
    signals["has_finserv_suitability_ai"]   = intake["J1_suitability_ai"]
    signals["no_smcr_ai_owner"]             = not intake["J2_smcr_owner"]
    signals["no_outcome_monitoring"]        = not intake["J3_outcome_monitoring"]
    signals["no_bias_assessment"]           = not intake["J4_bias_assessment"]

    # US Healthcare signals — derived from Section L fields
    # Only meaningful when sector = Healthcare_US; safe to compute regardless
    handles_phi = intake.get("L1_handles_phi", False)
    signals["has_phi_no_baa"]               = handles_phi and not intake.get("L2_baa_in_place", True)
    signals["has_phi_no_access_control"]    = handles_phi and not intake.get("L4_access_control", True)
    signals["has_phi_no_disclosure"]        = handles_phi and not intake.get("L5_patient_disclosure", True)
    signals["handles_phi"]                  = handles_phi
    # v1.3: Security Rule signals
    signals["no_encryption"]               = handles_phi and not intake.get("L7_phi_encrypted", True)
    signals["no_incident_response_plan"]   = handles_phi and not intake.get("L8_incident_response_plan", True)
    signals["uses_external_ai_api"]        = intake.get("L9_uses_external_ai_api", False)

    # Derived signals — computed after all primary signals
    high_gap_count = sum([
        signals["no_rule_enforcement"],
        signals["has_weak_validation"],
        signals["no_audit_trail"],
        signals["has_high_impact_no_override"],
    ])
    signals["multiple_high_gaps"] = high_gap_count >= 2

    signals["all_gaps_present"] = (
        signals["no_rule_enforcement"] and
        signals["no_audit_trail"] and
        signals["has_high_impact_no_override"]
    )

    signals["no_remediation_roadmap"] = (
        signals["has_incidents"] and signals["no_corrective_action"]
    ) or (
        signals["no_logging"] and
        signals["no_audit_trail"] and
        not intake["F2_accountable"]
    )

    return signals


# ===================================================================
# EXPR EVALUATOR
# Executes gap expr trees directly against resolved signals.
# ===================================================================
def evaluate_expr(expr, signals):
    op = expr["op"]
    if op == "all":
        return all(evaluate_expr(child, signals) for child in expr["children"])
    if op == "any":
        return any(evaluate_expr(child, signals) for child in expr["children"])
    if op == "eq":
        field = expr["field"].replace("signals.", "")
        return signals.get(field, False) == expr["value"]
    if op == "gt":
        field = expr["field"].replace("signals.", "")
        return signals.get(field, 0) > expr["value"]
    if op == "lt":
        field = expr["field"].replace("signals.", "")
        return signals.get(field, 0) < expr["value"]
    raise ValueError(f"Unknown op: {op}")


# ===================================================================
# DOMAIN LAYER SELECTOR
# ===================================================================
SECTOR_LAYERS = {
    "Healthcare":         {"core", "gdpr"},
    "Healthcare_US":      {"core", "us_healthcare"},
    "Financial Services": {"core", "gdpr", "fs"},
    "Legal":              {"core", "gdpr", "legal"},
    "Recruitment/HR":     {"core", "gdpr", "hr"},
    "Insurance":          {"core", "gdpr", "insurance"},
}

LITE_LAYERS = {"core", "gdpr"}

VALID_ENGAGEMENT_TYPES = {"lite", "full"}

GAP_LAYER = {
    "G01": "core", "G02": "core", "G03": "core", "G04": "core", "G05": "core",
    "GDPR-G01": "gdpr", "GDPR-G02": "gdpr", "GDPR-G03": "gdpr",
    "GDPR-G04": "gdpr", "GDPR-G05": "gdpr",
    "US-HC-G01": "us_healthcare", "US-HC-G02": "us_healthcare", "US-HC-G03": "us_healthcare",
    "US-HC-G04": "us_healthcare", "US-HC-G05": "us_healthcare",
    "US-HC-G06": "us_healthcare", "US-HC-G07": "us_healthcare", "US-HC-G08": "us_healthcare",
    "US-HC-G09": "us_healthcare", "US-HC-G10": "us_healthcare", "US-HC-G11": "us_healthcare",
    "HR-G06": "hr", "HR-G06b": "hr", "HR-G07": "hr",
    "HR-G08": "hr", "HR-G09": "hr", "HR-G10": "hr",
    "LEG-G09": "legal", "LEG-G10": "legal", "LEG-G11": "legal", "LEG-G12": "legal",
    "FS-G13": "fs", "FS-G14": "fs", "FS-G15": "fs", "FS-G16": "fs", "FS-G17": "fs",
    "INS-G18": "insurance",
}

# Plain-English summaries for US-HC gaps — used in structured output.
# Core gap pain_line / what_happens_next are read from the gap library.
US_HC_PLAIN = {
    "US-HC-G01": {
        "pain_line": "If OCR audits your AI deployment, the first question is: what is your legal basis for processing this PHI? Without documented HIPAA authorisation or a recognised exception, there is no answer.",
        "what_happens_next": "Document the HIPAA legal basis for every AI use of PHI this week. Assign a named owner. Review with legal counsel within 30 days.",
        "regulatory_refs": ["HIPAA Privacy Rule §164.502", "OCR AI Guidance 2025"],
    },
    "US-HC-G02": {
        "pain_line": "PHI collected for one purpose — say, billing — is being processed by AI for another. Without state law compliance, that is a HIPAA purpose limitation violation.",
        "what_happens_next": "Map every AI input to its original collection purpose. Flag any processing that goes beyond that purpose. Check state law requirements for your operating states.",
        "regulatory_refs": ["HIPAA Privacy Rule §164.502(b)", "CO AI Act", "TX TRAIGA"],
    },
    "US-HC-G03": {
        "pain_line": "AI systems create new categories of patient data records. Without a retention policy covering AI-processed PHI, you are accumulating liability with no defined endpoint.",
        "what_happens_next": "Extend your existing data retention policy to cover AI-processed PHI specifically. Define retention periods by PHI type. Confirm with your privacy officer.",
        "regulatory_refs": ["HIPAA Security Rule §164.316", "OCR Guidance", "CO AI Act §8"],
    },
    "US-HC-G04": {
        "pain_line": "Patients have HIPAA rights over data used in decisions about them. If AI influences those decisions and patients have no mechanism to exercise those rights, that is a structural gap — not a policy gap.",
        "what_happens_next": "Define and document the process for patients to request access to, or correction of, AI-influenced decision records. Disclose AI use in patient-facing communications.",
        "regulatory_refs": ["HIPAA Privacy Rule §164.524", "TX TRAIGA §4(b)", "CA AB 3030"],
    },
    "US-HC-G05": {
        "pain_line": "Every AI vendor processing PHI on your behalf must be covered by a Business Associate Agreement. Most BAAs predate AI — they cover data storage, not AI inference. The gap is contractual, not technical.",
        "what_happens_next": "Audit every AI vendor contract for BAA coverage of AI inference specifically. Amend or replace BAAs that do not address AI processing of PHI.",
        "regulatory_refs": ["HIPAA Privacy Rule §164.504(e)", "HIPAA Security Rule §164.314(a)"],
    },
}


# ===================================================================
# MAIN ENGINE RUN
# v1.1: returns (triggered, signals, run_record)
# run_record is the structured JSON summary.
# ===================================================================
def run_engine(intake, gaps_path):
    # Stamp the run
    run_id        = str(uuid.uuid4())
    run_timestamp = datetime.now(timezone.utc).isoformat()

    print(f"\n{'='*60}")
    print(f"CLEARANCE GAP Engine v{ENGINE_VERSION}")
    print(f"  Run ID    : {run_id}")
    print(f"  Timestamp : {run_timestamp}")
    print(f"{'='*60}")

    # -------------------------------------------------------------------
    # INTAKE INTEGRITY GUARD
    # -------------------------------------------------------------------
    engagement_type = intake.get("engagement_type", "").lower()

    # --- ENUM VALIDATION (v1.2) ---
    VALID_PHI_TYPES = {"clinical_notes", "imaging", "billing", "mixed", "lab_results",
                       "medication", "identifiers", "mental_health", "other", "none"}
    VALID_STATE_CODES = {
        "AL","AK","AZ","AR","CA","CO","CT","DE","FL","GA","HI","ID","IL","IN","IA",
        "KS","KY","LA","ME","MD","MA","MI","MN","MS","MO","MT","NE","NV","NH","NJ",
        "NM","NY","NC","ND","OH","OK","OR","PA","RI","SC","SD","TN","TX","UT","VT",
        "VA","WA","WV","WI","WY","DC"
    }
    phi_type = intake.get("L3_phi_type", "none")
    if phi_type not in VALID_PHI_TYPES:
        raise ValueError(
            "[INTAKE GUARD] REJECTED — L3_phi_type '" + phi_type + "' is not a recognised value. "
            "Valid values: " + str(sorted(VALID_PHI_TYPES)) + ". Engine has not run."
        )
    operating_states = intake.get("L6_operating_states", [])
    if operating_states:
        invalid_states = [s for s in operating_states if s not in VALID_STATE_CODES]
        if invalid_states:
            raise ValueError(
                "[INTAKE GUARD] REJECTED — L6_operating_states contains unrecognised codes: " + str(invalid_states) +
                ". Use standard two-letter US state codes only. Engine has not run."
            )

    if engagement_type not in VALID_ENGAGEMENT_TYPES:
        raise ValueError(
            f"\n[INTAKE GUARD] REJECTED — engagement_type '{engagement_type}' is not valid.\n"
            f"  Set engagement_type to 'lite' or 'full'.\n"
            f"  Engine has not run. No signals resolved. No gaps evaluated."
        )

    if engagement_type == "lite":
        sector_fields = [
            "H_employee_monitoring","H_monitoring_disclosure","H_performance_scoring",
            "H_disciplinary_ai","H_workforce_analytics","H_termination_ai",
            "I1_legal_drafting","I2_legal_advice","I3_client_data","I4_client_disclosure",
            "J1_suitability_ai","J2_smcr_owner","J3_outcome_monitoring","J4_bias_assessment",
        ]
        contaminated = [f for f in sector_fields if intake.get(f, False) is True]
        if contaminated:
            raise ValueError(
                f"\n[INTAKE GUARD] REJECTED — Lite intake contains sector-specific signal fields "
                f"set to True: {contaminated}\n"
                f"  Use engagement_type='full' to run sector layers.\n"
                f"  Engine has not run. No signals resolved. No gaps evaluated."
            )

    if engagement_type == "full":
        sector = intake.get("sector", "")
        required_full_fields = {
            "Financial Services": ["J1_suitability_ai","J2_smcr_owner","J3_outcome_monitoring","J4_bias_assessment"],
            "Legal":              ["I1_legal_drafting","I2_legal_advice","I3_client_data","I4_client_disclosure"],
            "Recruitment/HR":     ["H_employee_monitoring","H_performance_scoring","H_disciplinary_ai","H_workforce_analytics","H_termination_ai"],
            # v1.1: Healthcare_US requires Section L fields
            "Healthcare_US":      ["L1_handles_phi","L2_baa_in_place","L4_access_control","L5_patient_disclosure","L6_operating_states","L7_phi_encrypted","L8_incident_response_plan","L9_uses_external_ai_api"],
        }
        missing = [f for f in required_full_fields.get(sector, []) if f not in intake]
        if missing:
            raise ValueError(
                f"\n[INTAKE GUARD] REJECTED — Full intake for sector '{sector}' is missing "
                f"required sector-specific fields: {missing}\n"
                f"  Healthcare_US requires Section L fields (L1–L6) from the US intake supplement.\n"
                f"  Engine has not run. No signals resolved. No gaps evaluated."
            )

    print(f"  Engagement type : {engagement_type.upper()}")
    print(f"  Sector          : {intake['sector']}")
    print(f"  Engagement ref  : {intake.get('engagement_ref', 'NOT SET')}")

    # Load gap library
    with open(gaps_path) as f:
        library = json.load(f)
    gaps = library["gaps"]

    # Load US Healthcare layer if active
    us_layer_path = Path(gaps_path).parent / "gaps_us_healthcare_v1_4.json"
    if "us_healthcare" in SECTOR_LAYERS.get(intake["sector"], set()) and us_layer_path.exists():
        with open(us_layer_path) as f:
            us_library = json.load(f)
        gaps = gaps + us_library["gaps"]

    # Step 1: Resolve signals
    signals = resolve_signals(intake)
    print(f"\n--- SIGNALS RESOLVED ---")
    for k, v in signals.items():
        marker = "✓" if v else "·"
        print(f"  {marker} {k}: {v}")

    # Step 2: Active layers
    if engagement_type == "lite":
        active_layers = LITE_LAYERS
        print(f"\n--- ACTIVE LAYERS (LITE — sector layers blocked): CORE, GDPR ---")
    else:
        active_layers = SECTOR_LAYERS.get(intake["sector"], {"core", "gdpr"})
        print(f"\n--- ACTIVE LAYERS: {', '.join(sorted(active_layers)).upper()} ---")

    # Step 3: Gap evaluation
    triggered    = []
    not_triggered = []

    # Build a lookup of gap detail for the run record
    gap_detail_map = {g["id"]: g for g in gaps}

    print(f"\n--- GAP EVALUATION ---")
    for gap in gaps:
        gid   = gap["id"]
        layer = GAP_LAYER.get(gid, "core")

        if layer not in active_layers:
            print(f"  SKIP  {gid} (layer '{layer}' not active for this sector)")
            continue

        expr = gap.get("expr")
        if not expr:
            print(f"  SKIP  {gid} (no expr defined)")
            continue

        fired = evaluate_expr(expr, signals)

        if fired:
            triggered.append({
                "id":       gid,
                "title":    gap["title"],
                "severity": gap["severity"],
                "plane":    gap["plane"],
            })
            print(f"  FIRE  {gid} | {gap['severity']:8} | {gap['title']}")
        else:
            not_triggered.append(gid)
            print(f"  ····  {gid} | did not fire")

    # Step 4: Summary counts
    critical = [g for g in triggered if g["severity"] == "CRITICAL"]
    high     = [g for g in triggered if g["severity"] == "HIGH"]
    medium   = [g for g in triggered if g["severity"] == "MEDIUM"]

    print(f"\n{'='*60}")
    print(f"RESULT: {len(triggered)} gaps triggered")
    print(f"  CRITICAL : {len(critical)}")
    print(f"  HIGH     : {len(high)}")
    print(f"  MEDIUM   : {len(medium)}")
    print(f"  Not fired: {len(not_triggered)} ({', '.join(not_triggered)})")
    print(f"{'='*60}\n")

    # -------------------------------------------------------------------
    # v1.1: BUILD STRUCTURED RUN RECORD
    # Machine-readable. Report-template-ready. Audit-traceable.
    # -------------------------------------------------------------------
    run_record_gaps = []
    for g in triggered:
        gid    = g["id"]
        detail = gap_detail_map.get(gid, {})

        # Plain-English text: prefer gap library fields; fall back to US_HC_PLAIN
        if gid in US_HC_PLAIN:
            pain_line        = US_HC_PLAIN[gid]["pain_line"]
            what_happens_next = US_HC_PLAIN[gid]["what_happens_next"]
            regulatory_refs  = US_HC_PLAIN[gid]["regulatory_refs"]
        else:
            pain_line        = detail.get("pain_line", "")
            what_happens_next = detail.get("what_happens_next", "")
            reg_links        = detail.get("regulatory_links", [])
            regulatory_refs  = [r for r in reg_links if isinstance(r, str)]

        run_record_gaps.append({
            "id":               gid,
            "gap_id":           detail.get("gap_id", gid),
            "title":            g["title"],
            "severity":         g["severity"],
            "deployment_blocking": detail.get("deployment_blocking", False),
            "plane":            g["plane"],
            "pain_line":        pain_line,
            "what_happens_next": what_happens_next,
            "regulatory_refs":  regulatory_refs,
        })

    # State law applicability note for Healthcare_US
    state_notes = []
    operating_states = intake.get("L6_operating_states", [])
    if "CO" in operating_states:
        state_notes.append("Colorado AI Act — high-risk AI obligations enforceable June 30 2026")
    if "TX" in operating_states:
        state_notes.append("Texas TRAIGA — patient disclosure before AI-assisted diagnosis — already in force Jan 1 2026")
    if "CA" in operating_states:
        state_notes.append("California AB 3030 — disclaimer required on AI-generated patient comms — in force Jan 1 2025")
        state_notes.append("California AB 489 — AI may not imply clinical licensure — in force Jan 1 2026")

    run_record = {
        "run_id":           run_id,
        "run_timestamp":    run_timestamp,
        "engine_version":   ENGINE_VERSION,
        "library_version":  LIBRARY_VERSION,
        "us_layer_version": US_LAYER_VERSION if "us_healthcare" in active_layers else None,
        "engagement_ref":   intake.get("engagement_ref", ""),
        "sector":           intake["sector"],
        "engagement_type":  engagement_type,
        "phi_in_scope":     intake.get("L1_handles_phi", False),
        "operating_states": operating_states,
        "state_law_notes":  state_notes,
        "summary": {
            "gaps_triggered": len(triggered),
            "critical":       len(critical),
            "high":           len(high),
            "medium":         len(medium),
            "not_fired":      len(not_triggered),
            "deployment_blocking": sum(1 for g in run_record_gaps if g.get("deployment_blocking")),
        },
        "gaps": run_record_gaps,
    }

    # -------------------------------------------------------------------
    # FINDINGS INTEGRITY HASH (v1.4)
    # SHA-256 of the canonical findings payload.
    # Covers: engagement_ref, sector, engine_version, library_version,
    #         summary counts, and full gap list (id, severity, title).
    # Excludes run_id and run_timestamp — these vary by design.
    # Purpose: allows independent verification that findings have not
    #          been altered since the engine produced them.
    #          Use CLEARANCE_Verifier.py to confirm.
    # -------------------------------------------------------------------
    findings_payload = {
        "engagement_ref":  run_record["engagement_ref"],
        "sector":          run_record["sector"],
        "engine_version":  run_record["engine_version"],
        "library_version": run_record["library_version"],
        "summary":         run_record["summary"],
        "gaps": [
            {"id": g["id"], "severity": g["severity"], "title": g["title"]}
            for g in run_record_gaps
        ],
    }
    findings_json   = json.dumps(findings_payload, sort_keys=True, separators=(",", ":"))
    findings_bytes  = findings_json.encode("utf-8")

    # SHA-256 integrity hash (unchanged from v1.4)
    findings_hash   = hashlib.sha256(findings_bytes).hexdigest()
    run_record["findings_hash"]         = findings_hash
    run_record["findings_hash_algo"]    = "SHA-256"
    run_record["findings_hash_note"]    = (
        "Hash of canonical findings payload. Excludes run_id and run_timestamp. "
        "Verify with CLEARANCE_Verifier.py."
    )

    # -------------------------------------------------------------------
    # HMAC-SHA256 EVIDENCE ENVELOPE (v1.5)
    # A per-engagement key (32 random bytes) is generated at run time and
    # stored alongside the HMAC signature in the run record.
    # This allows any holder of the key to independently verify that the
    # findings payload has not been altered since the engine produced it.
    # Key management (HSM, rotation, third-party custody) is a V2 feature.
    # DO NOT share the engagement_key outside the evidence envelope
    # without explicit client authorisation.
    # -------------------------------------------------------------------
    engagement_key  = secrets.token_hex(32)          # 256-bit key, hex-encoded
    hmac_sig        = hmac.new(
        engagement_key.encode("utf-8"),
        findings_bytes,
        hashlib.sha256,
    ).hexdigest()

    run_record["evidence_envelope"] = {
        "algo":            "HMAC-SHA256",
        "engagement_key":  engagement_key,
        "signature":       hmac_sig,
        "signed_payload":  "findings_payload (canonical JSON, sort_keys=True)",
        "excludes":        ["run_id", "run_timestamp"],
        "verification":    "python -c \"import hmac, hashlib, json; "
                           "key=<engagement_key>; payload=<findings_json>; "
                           "print(hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest())\"",
        "note":            (
            "Per-engagement HMAC key. Findings are cryptographically signed. "
            "Any alteration to the findings payload will invalidate this signature. "
            "Full key management (rotation, HSM custody) is a V2 feature."
        ),
    }

    return triggered, signals, run_record


# ===================================================================
# RUN
# ===================================================================
if __name__ == "__main__":
    import importlib.util as _ilu

    GAPS_PATH = Path(__file__).parent / "gaps_v1_9_core.json"
    triggered, signals, run_record = run_engine(INTAKE, GAPS_PATH)

    # ── JSON run record (machine-readable)
    run_record_path = Path(__file__).parent / f"run_record_{run_record['run_id'][:8]}.json"
    with open(run_record_path, "w") as _f:
        json.dump(run_record, _f, indent=2)
    print(f"\n✔  Run record saved: {run_record_path.name}")

    # ── Human-readable report (auto-generated)
    _rg_path = Path(__file__).parent / "CLEARANCE_Report_Generator_V1_0.py"
    if _rg_path.exists():
        _spec = _ilu.spec_from_file_location("report_generator", _rg_path)
        _rg   = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_rg)
        report_md = _rg.generate_report(run_record)
        report_path = Path(__file__).parent / f"report_{run_record['run_id'][:8]}.md"
        with open(report_path, "w") as _f:
            _f.write(report_md)
        print(f"✔  Report saved:     {report_path.name}")
    else:
        print("⚠  CLEARANCE_Report_Generator_V1_0.py not found — skipping report.")

    # ── Print JSON to stdout for pipeline use
    print("\n--- STRUCTURED RUN RECORD (JSON) ---")
    print(json.dumps(run_record, indent=2))
