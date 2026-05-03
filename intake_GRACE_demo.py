#!/usr/bin/env python3
"""
CLEARANCE — GRACE Demo Intake
==============================
Scenario: Meridian Wealth Management
Deployment: ClientAdvisor AI — automated suitability assessment engine

Context for the demo:
  GRACE is deployed. It governs the AI lifecycle — model registry,
  risk framework, ISO 42001 alignment, continuous monitoring across
  the portfolio. That is Layer 1.

  CLEARANCE evaluates Layer 2: what happens at the moment of decision.
  Does a ruleset govern what the AI is permitted to recommend?
  Is every recommendation logged in a sealed audit trail?
  Is there a named SM&CR owner for this system?
  Can the firm demonstrate good client outcomes under Consumer Duty?

  GRACE does not answer those questions. CLEARANCE does.

Usage:
  1. Open this file — show the intake questions being answered
  2. Run: python3 intake_GRACE_demo.py
  3. Run verifier: python3 CLEARANCE_Verifier_V1_1.py run_record_<id>.json
"""

import importlib.util
import json
from pathlib import Path

# ── ENGINE ──────────────────────────────────────────────────────────
ENGINE_PATH = Path(__file__).parent / "CLEARANCE_Engine_Evaluator_V1_5.py"
GAPS_PATH   = Path(__file__).parent / "gaps_v1_9_core.json"

spec = importlib.util.spec_from_file_location("engine", ENGINE_PATH)
eng  = importlib.util.module_from_spec(spec)
spec.loader.exec_module(eng)

# ── INTAKE ───────────────────────────────────────────────────────────
# Meridian Wealth Management — ClientAdvisor AI
# Suitability assessment engine. Generates investment recommendations
# for retail clients. Recommendations are presented to clients via
# adviser portal and accepted without per-decision compliance sign-off.
# GRACE deployed for lifecycle governance. No decision-layer controls.

INTAKE = {
    "engagement_ref":   "CLR-GRACE-DEMO",
    "sector":           "Financial Services",
    "engagement_type":  "full",

    # Section B — Deployment
    "B4_live":          True,   # Live in production
    "B2_high_impact":   True,   # Suitability recommendations — FCA high-impact

    # Section C — Automation and ruleset
    "C1_automated":     True,   # Recommendations execute without per-decision human sign-off
    "C2_ruleset":       False,  # No documented ruleset at the decision boundary
    "C2a_enforced":     False,  # GRACE governs the lifecycle — not the decision layer

    # Section D — Data provenance
    "D1_external_data": True,   # Market data feeds, client CRM, third-party risk scores
    "D2_traceable":     False,  # Cannot trace every input to its origin and last update
    "D3_validated":     False,  # No data quality validation before inference

    # Section E — Logging and audit
    "E1_logging":       False,  # No decision-level logging
    "E2_audit_trail":   False,  # No sealed audit trail per recommendation

    # Section F — Accountability
    "F1_override":      False,  # No human override mechanism at the decision boundary
    "F2_accountable":   False,  # No named SM&CR owner for this AI system

    # Section G — Incidents
    "G1_incidents":     False,  # No declared incidents — clean deployment history
    "G1a_corrective":   False,

    # Section J — Financial Services signals
    "J1_suitability_ai":     True,   # AI generates suitability assessments
    "J2_smcr_owner":         False,  # No named SM&CR owner for the AI system
    "J3_outcome_monitoring": False,  # No Consumer Duty outcome monitoring in place
    "J4_bias_assessment":    False,  # No bias or fairness assessment conducted

    # Sections H, I, L — not applicable
    "H_employee_monitoring": False, "H_monitoring_disclosure": False,
    "H_performance_scoring": False, "H_disciplinary_ai":       False,
    "H_workforce_analytics": False, "H_termination_ai":        False,
    "I1_legal_drafting":     False, "I2_legal_advice":         False,
    "I3_client_data":        False, "I4_client_disclosure":    False,
    "L1_handles_phi":        False, "L2_baa_in_place":         False,
    "L3_phi_type":           "none","L4_access_control":       False,
    "L5_patient_disclosure": False, "L6_operating_states":     [],
    "L7_phi_encrypted":      False, "L8_incident_response_plan": False,
    "L9_uses_external_ai_api": False,
}

# ── RUN ──────────────────────────────────────────────────────────────
triggered, signals, run_record = eng.run_engine(INTAKE, GAPS_PATH)

# ── SAVE RUN RECORD ──────────────────────────────────────────────────
run_record_path = Path(__file__).parent / f"run_record_{run_record['run_id'][:8]}.json"
with open(run_record_path, "w") as f:
    json.dump(run_record, f, indent=2)

print(f"\n{'='*60}")
print(f"Run record : {run_record_path.name}")
print(f"Verify     : python3 CLEARANCE_Verifier_V1_1.py {run_record_path.name}")
print(f"{'='*60}\n")
