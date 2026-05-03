#!/usr/bin/env python3
"""
CLEARANCE Findings Verifier v1.1
==================================
Verifies that a saved CLEARANCE run record has not been altered
since the engine produced it.

v1.1 adds HMAC-SHA256 envelope verification (engine v1.5+).
v1.0 SHA-256 hash check is retained for backward compatibility.

Usage:
  python CLEARANCE_Verifier_V1_1.py <path_to_run_record.json>

Exit codes:
  0 — VERIFIED. Findings are intact (hash and HMAC both pass).
  1 — TAMPERED or CORRUPTED. Hash or HMAC does not match.
  2 — Hash field absent. Run record produced before engine v1.4.
"""

import hashlib
import hmac
import json
import sys
from pathlib import Path


def _build_findings_payload(record: dict) -> dict:
    return {
        "engagement_ref":  record["engagement_ref"],
        "sector":          record["sector"],
        "engine_version":  record["engine_version"],
        "library_version": record["library_version"],
        "summary":         record["summary"],
        "gaps": [
            {"id": g["id"], "severity": g["severity"], "title": g["title"]}
            for g in record.get("gaps", [])
        ],
    }


def verify(run_record_path: str) -> int:
    path = Path(run_record_path)

    if not path.exists():
        print(f"[ERROR] File not found: {run_record_path}")
        return 1

    with open(path) as f:
        try:
            record = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[ERROR] File is not valid JSON: {e}")
            return 1

    stored_hash = record.get("findings_hash")
    if not stored_hash:
        print("[UNVERIFIABLE] No findings_hash field found.")
        print("  This run record was produced before engine v1.4.")
        print("  Findings cannot be independently verified.")
        return 2

    try:
        findings_payload = _build_findings_payload(record)
    except KeyError as e:
        print(f"[ERROR] Run record is missing expected field: {e}")
        return 1

    findings_json   = json.dumps(findings_payload, sort_keys=True, separators=(",", ":"))
    findings_bytes  = findings_json.encode("utf-8")
    recomputed_hash = hashlib.sha256(findings_bytes).hexdigest()

    print(f"\nCLEARANCE Findings Verifier v1.1")
    print(f"{'='*60}")
    print(f"  File            : {path.name}")
    print(f"  Engagement ref  : {record.get('engagement_ref', 'NOT SET')}")
    print(f"  Sector          : {record.get('sector', '')}")
    print(f"  Engine version  : {record.get('engine_version', '')}")
    print(f"  Run ID          : {record.get('run_id', '')}")
    print(f"  Run timestamp   : {record.get('run_timestamp', '')}")
    print(f"{'='*60}")

    # --- SHA-256 check ---
    hash_ok = (recomputed_hash == stored_hash)
    print(f"  Stored hash     : {stored_hash}")
    print(f"  Recomputed hash : {recomputed_hash}")
    print(f"  Hash check      : {'✔  PASS' if hash_ok else '✘  FAIL'}")
    print(f"{'='*60}")

    # --- HMAC check (v1.5+ records only) ---
    envelope = record.get("evidence_envelope")
    hmac_ok  = None

    if envelope:
        stored_sig     = envelope.get("signature", "")
        engagement_key = envelope.get("engagement_key", "")
        algo           = envelope.get("algo", "")

        if algo == "HMAC-SHA256" and engagement_key and stored_sig:
            recomputed_sig = hmac.new(
                engagement_key.encode("utf-8"),
                findings_bytes,
                hashlib.sha256,
            ).hexdigest()
            # Use hmac.compare_digest to prevent timing attacks
            hmac_ok = hmac.compare_digest(recomputed_sig, stored_sig)
            print(f"  Stored HMAC     : {stored_sig}")
            print(f"  Recomputed HMAC : {recomputed_sig}")
            print(f"  HMAC check      : {'✔  PASS' if hmac_ok else '✘  FAIL'}")
            print(f"{'='*60}")
        else:
            print("  HMAC check      : SKIPPED — envelope fields incomplete")
            print(f"{'='*60}")
    else:
        print("  HMAC check      : SKIPPED — no evidence_envelope (pre-v1.5 record)")
        print(f"{'='*60}")

    # --- Verdict ---
    all_pass = hash_ok and (hmac_ok is not False)

    if all_pass:
        print(f"\n  ✔  VERIFIED — Findings are intact.")
        if hmac_ok:
            print(f"     SHA-256 hash and HMAC-SHA256 signature both confirmed.")
        print(f"     Gaps triggered : {record['summary'].get('gaps_triggered', '?')}")
        print(f"     CRITICAL       : {record['summary'].get('critical', '?')}")
        print(f"     HIGH           : {record['summary'].get('high', '?')}")
        print(f"     MEDIUM         : {record['summary'].get('medium', '?')}")
        print(f"\n  These findings have not been altered since the engine produced them.")
        return 0
    else:
        print(f"\n  ✘  VERIFICATION FAILED.")
        if not hash_ok:
            print(f"     SHA-256 hash mismatch — findings payload has been altered.")
        if hmac_ok is False:
            print(f"     HMAC-SHA256 signature mismatch — evidence envelope is invalid.")
        print(f"     This file should not be relied upon.")
        return 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python CLEARANCE_Verifier_V1_1.py <path_to_run_record.json>")
        sys.exit(1)

    exit_code = verify(sys.argv[1])
    sys.exit(exit_code)
