#!/usr/bin/env python3
"""
Comprehensive validator for HackerRank Orchestrate: Ghost Data Still Exists.
Validates root output.csv against all challenge contract requirements.
Exits with code 0 on complete pass, or non-zero exit code with descriptive error.
"""

import sys
import os
import csv
import json
from datetime import datetime

ALLOWED_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}

ALLOWED_FINDING_OPS = {
    "REPORT_REMAINING_RECORD": "PRESENT",
    "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE"
}

ALLOWED_REMEDIATION_OPS = {
    "DISABLE_DATA_FLOW": "DISABLED",
    "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED"
}

ALLOWED_VERIFICATION_OPS = {
    "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED"
}

REQUIRED_STEP_FIELDS = [
    "step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"
]

def parse_iso(ts):
    if not ts: return None
    ts = ts.replace('Z', '+00:00')
    return datetime.fromisoformat(ts)


def validate(repo_root: str) -> bool:
    output_path = os.path.join(repo_root, "output.csv")
    dataset_dir = os.path.join(repo_root, "dataset")
    del_req_path = os.path.join(dataset_dir, "deletion_requests.csv")
    ev_path = os.path.join(dataset_dir, "evidence_files.csv")

    errors = []

    # 1. File existence
    if not os.path.exists(output_path):
        errors.append(f"Missing root output.csv at: {output_path}")
        print("\n".join(errors), file=sys.stderr)
        return False

    if not os.path.exists(del_req_path):
        errors.append(f"Missing evaluation requests file: {del_req_path}")
        print("\n".join(errors), file=sys.stderr)
        return False

    # 2. Evidence manifest loading for cutoff validation
    evidence_times = {}
    if os.path.exists(ev_path):
        with open(ev_path, encoding='utf-8') as f:
            for row in csv.DictReader(f):
                evidence_times[row['file_id']] = parse_iso(row['captured_at'])

    # 3. Load expected cases and their cutoffs
    expected_cases = {}
    with open(del_req_path, encoding='utf-8') as f:
        for row in csv.DictReader(f):
            expected_cases[row['case_id']] = {
                'requested_at': parse_iso(row.get('requested_at')),
                'reported_at': parse_iso(row.get('reported_at')),
                'audit_at': parse_iso(row.get('audit_at'))
            }

    # 4. Parse output.csv
    with open(output_path, encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if header != ["case_id", "deletion_status", "steps_json"]:
            errors.append(f"Invalid CSV header: {header}. Expected: ['case_id', 'deletion_status', 'steps_json']")

        rows = list(reader)

    if len(rows) != len(expected_cases):
        errors.append(f"Row count mismatch: found {len(rows)} data rows, expected exactly {len(expected_cases)} rows.")

    seen_case_ids = []
    for line_no, row in enumerate(rows, start=2):
        if len(row) != 3:
            errors.append(f"Line {line_no}: Row has {len(row)} columns, expected 3.")
            continue

        cid, status, steps_json_str = row[0].strip(), row[1].strip(), row[2].strip()
        seen_case_ids.append(cid)

        # Check status
        if status not in ALLOWED_STATUSES:
            errors.append(f"Line {line_no} ({cid}): Invalid status '{status}'. Must be one of {ALLOWED_STATUSES}")

        # Check case exists in input dataset
        if cid not in expected_cases:
            errors.append(f"Line {line_no}: Unknown case_id '{cid}' not in deletion_requests.csv.")
            continue

        case_meta = expected_cases[cid]
        audit_at = case_meta['audit_at']

        # Check JSON parse
        try:
            steps = json.loads(steps_json_str)
        except Exception as e:
            errors.append(f"Line {line_no} ({cid}): Invalid JSON in steps_json: {e}")
            continue

        if not isinstance(steps, list):
            errors.append(f"Line {line_no} ({cid}): steps_json must be a JSON array.")
            continue

        # Status specific checks
        if status == "NOT_APPLICABLE":
            if steps != []:
                errors.append(f"Line {line_no} ({cid}): NOT_APPLICABLE case must have empty steps array [], got {len(steps)} steps.")
            continue

        if len(steps) == 0:
            errors.append(f"Line {line_no} ({cid}): Status '{status}' has empty steps_json.")
            continue

        # Step validation
        current_phase_idx = 1
        phase_map = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
        has_flow_disable = False
        has_restore_block = False

        for expected_step_no, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                errors.append(f"Line {line_no} ({cid}) step {expected_step_no}: Step must be a JSON object.")
                continue

            # Check consecutive step_no
            if step.get("step_no") != expected_step_no:
                errors.append(f"Line {line_no} ({cid}): Discontinuous step_no: expected {expected_step_no}, got {step.get('step_no')}")

            # Check required fields
            for rf in REQUIRED_STEP_FIELDS:
                if rf not in step:
                    errors.append(f"Line {line_no} ({cid}) step {expected_step_no}: Missing required field '{rf}'")

            phase = step.get("phase", "")
            op = step.get("operation", "")
            st = step.get("state", "")
            ev_id = step.get("evidence_id", "")
            sys_id = step.get("system_id", "")
            res_id = step.get("resource_id", "")

            # Phase order check
            p_idx = phase_map.get(phase, 99)
            if p_idx < current_phase_idx:
                errors.append(f"Line {line_no} ({cid}) step {expected_step_no}: Invalid phase transition from index {current_phase_idx} to {phase} (must be FINDING -> REMEDIATION -> VERIFICATION)")
            current_phase_idx = max(current_phase_idx, p_idx)

            # Operation & state rules
            if phase == "FINDING":
                if status == "COMPLETE":
                    errors.append(f"Line {line_no} ({cid}): COMPLETE case contains FINDING step {expected_step_no}.")
                if op not in ALLOWED_FINDING_OPS:
                    errors.append(f"Line {line_no} ({cid}) step {expected_step_no}: Invalid finding operation '{op}'.")
                elif st != ALLOWED_FINDING_OPS[op]:
                    errors.append(f"Line {line_no} ({cid}) step {expected_step_no}: Invalid state '{st}' for operation '{op}'. Expected '{ALLOWED_FINDING_OPS[op]}'.")
                if not ev_id:
                    errors.append(f"Line {line_no} ({cid}) step {expected_step_no}: Finding step must cite a non-empty evidence_id.")
                elif ev_id in evidence_times and audit_at and evidence_times[ev_id] > audit_at:
                    errors.append(f"Line {line_no} ({cid}) step {expected_step_no}: Post-audit evidence violation! Evidence {ev_id} captured at {evidence_times[ev_id]} > audit_at {audit_at}")

            elif phase == "REMEDIATION":
                if status == "COMPLETE":
                    errors.append(f"Line {line_no} ({cid}): COMPLETE case contains REMEDIATION step {expected_step_no}.")
                if op not in ALLOWED_REMEDIATION_OPS:
                    errors.append(f"Line {line_no} ({cid}) step {expected_step_no}: Invalid remediation operation '{op}'.")
                elif st != ALLOWED_REMEDIATION_OPS[op]:
                    errors.append(f"Line {line_no} ({cid}) step {expected_step_no}: Invalid state '{st}' for operation '{op}'. Expected '{ALLOWED_REMEDIATION_OPS[op]}'.")
                if ev_id != "":
                    errors.append(f"Line {line_no} ({cid}) step {expected_step_no}: Remediation step must have empty evidence_id, got '{ev_id}'.")

                if op == "DISABLE_DATA_FLOW": has_flow_disable = True
                if op == "BLOCK_RESTORE": has_restore_block = True

            elif phase == "VERIFICATION":
                if op not in ALLOWED_VERIFICATION_OPS:
                    errors.append(f"Line {line_no} ({cid}) step {expected_step_no}: Invalid verification operation '{op}'.")
                elif st != ALLOWED_VERIFICATION_OPS[op]:
                    errors.append(f"Line {line_no} ({cid}) step {expected_step_no}: Invalid state '{st}' for operation '{op}'. Expected '{ALLOWED_VERIFICATION_OPS[op]}'.")

                if status == "COMPLETE":
                    if not ev_id:
                        errors.append(f"Line {line_no} ({cid}) step {expected_step_no}: COMPLETE verification step must cite evidence_id proving state at audit_at.")
                    elif ev_id in evidence_times and audit_at and evidence_times[ev_id] > audit_at:
                        errors.append(f"Line {line_no} ({cid}) step {expected_step_no}: Post-audit evidence violation! Evidence {ev_id} captured at {evidence_times[ev_id]} > audit_at {audit_at}")
                elif status == "INCOMPLETE":
                    if ev_id != "":
                        errors.append(f"Line {line_no} ({cid}) step {expected_step_no}: Future verification step in INCOMPLETE case must have empty evidence_id, got '{ev_id}'.")

    # 5. Check sorting of case_ids
    def extract_num(c):
        parts = c.split('_')
        return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else c

    sorted_expected = sorted(list(expected_cases.keys()), key=extract_num)
    if seen_case_ids != sorted_expected:
        errors.append("case_id order in output.csv does not match sorted deletion_requests.csv.")

    # 6. Report summary
    if errors:
        print(f"\n[VALIDATION FAILED] Found {len(errors)} contract errors:", file=sys.stderr)
        for err in errors[:25]:
            print(f"  - {err}", file=sys.stderr)
        if len(errors) > 25:
            print(f"  ... and {len(errors) - 25} more errors.", file=sys.stderr)
        return False

    print("\n[VALIDATION PASSED]")
    print(f"  Total Rows: {len(rows)} data rows + header")
    print(f"  All {len(expected_cases)} case IDs present in exact sorted order.")
    print("  All statuses, JSON structures, phase transitions, and operation-state pairs strictly valid.")
    print("  Zero temporal evidence cutoff violations.")
    print("  Zero ungrounded evidence references in remediation/future verification.")
    return True


if __name__ == "__main__":
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    success = validate(root)
    sys.exit(0 if success else 1)
