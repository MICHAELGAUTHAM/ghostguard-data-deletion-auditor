"""
Independent test suite for GhostGuard Deletion Audit Engine.
Covers critical edge cases specified by HackerRank Orchestrate:
1. Multilingual non-deletion requests (access, export, correction, opt-out) -> NOT_APPLICABLE, []
2. Historical email and SHA-256 digest identity resolution
3. Secondary system residual PII detection and policy enforcement
4. Active data flow and backup restore risk remediation priority ordering
5. Retained account tombstone null-safe parsing and verification
6. Strict temporal evidence cutoff enforcement (post-audit evidence exclusion)
"""

import os
import sys
import json
import pytest

# Add code directory to path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "code"))

from main import DeletionAuditEngine, IntentClassifier, IdentityResolver


@pytest.fixture(scope="module")
def audit_engine():
    dataset_dir = os.path.join(REPO_ROOT, "dataset")
    return DeletionAuditEngine(dataset_dir)


def test_non_deletion_requests_classification(audit_engine):
    """Edge Case 1: Non-deletion requests (access, export, correction, opt-out)."""
    non_deletion_cases = [
        # English: access only
        {"case_id": "test_nd_01", "email": "user1@example.com", "request_text": "I would like to request a full portable export of my personal data under GDPR Article 20.", "audit_at": "2026-09-20T12:00:00Z"},
        # English: marketing opt-out
        {"case_id": "test_nd_02", "email": "user2@example.com", "request_text": "Please remove me from all marketing promotional email lists, but leave my account active.", "audit_at": "2026-09-20T12:00:00Z"},
        # English: profile correction
        {"case_id": "test_nd_03", "email": "user3@example.com", "request_text": "My phone number is out of date. Please update my phone number without removing my profile.", "audit_at": "2026-09-20T12:00:00Z"},
        # French: correction without deletion
        {"case_id": "test_nd_04", "email": "user4@example.com", "request_text": "Je demande la rectification de mon adresse e-mail tout en laissant le compte actif.", "audit_at": "2026-09-20T12:00:00Z"},
        # Spanish: access / download only
        {"case_id": "test_nd_05", "email": "user5@example.com", "request_text": "Solicito una copia de mis datos personales en formato descargable, no solicito la eliminación de mi cuenta.", "audit_at": "2026-09-20T12:00:00Z"},
        # Korean: keep account
        {"case_id": "test_nd_06", "email": "user6@example.com", "request_text": "회원 탈퇴를 원하지 않습니다. 전화번호만 수정해 주세요.", "audit_at": "2026-09-20T12:00:00Z"},
        # Japanese: opt-out only
        {"case_id": "test_nd_07", "email": "user7@example.com", "request_text": "アカウントの削除を希望していません。メールマガジンの配信停止のみをお願いします。", "audit_at": "2026-09-20T12:00:00Z"}
    ]

    for c in non_deletion_cases:
        status, steps_str = audit_engine.audit_case(c)
        assert status == "NOT_APPLICABLE", f"Expected NOT_APPLICABLE for text: '{c['request_text']}', got {status}"
        assert steps_str == "[]", f"Expected '[]' steps for NOT_APPLICABLE, got {steps_str}"


def test_historical_email_and_hash_resolution():
    """Edge Case 2: Historical email from audit log resolves to current user and matches email hash."""
    dataset_dir = os.path.join(REPO_ROOT, "dataset")
    resolver = IdentityResolver(dataset_dir)

    # In user_identities / user_audit_log:
    # case_12 user is user_12 (Min-jun Kim)
    # Current email: minjun.kim@gmail.com
    # Historical email: minjun.kim90@gmail.com
    user_by_current = resolver.resolve_user("minjun.kim@gmail.com")
    user_by_historical = resolver.resolve_user("minjun.kim90@gmail.com")

    assert user_by_current is not None, "Failed to resolve user by current email"
    assert user_by_historical is not None, "Failed to resolve user by historical email from user_audit_log"
    assert user_by_current["user_id"] == user_by_historical["user_id"] == "user_12"

    # Verify both emails and their computed SHA-256 hashes are tracked
    assert "minjun.kim@gmail.com" in user_by_current["emails"]
    assert "minjun.kim90@gmail.com" in user_by_current["emails"]
    assert len(user_by_current["email_hashes"]) >= 2


def test_secondary_system_residual_pii_enforcement(audit_engine):
    """Edge Case 3: Secondary system residual PII detected in support_platform and remediated via REDACT/DELETE."""
    # Case 10: support_002 still active in support replica
    case_10 = {
        "case_id": "case_10",
        "email": "nadia.ionescu@yahoo.com",
        "requested_at": "2026-08-31T10:08:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-09-02T10:08:00Z",
        "audit_at": "2026-09-18T10:08:00Z",
        "request_text": "I am writing to formally request the complete deletion of my account and all personal data associated with this email address."
    }

    status, steps_str = audit_engine.audit_case(case_10)
    assert status == "INCOMPLETE", f"Expected INCOMPLETE due to residual support record, got {status}"

    steps = json.loads(steps_str)
    findings = [s for s in steps if s["phase"] == "FINDING"]
    remediations = [s for s in steps if s["phase"] == "REMEDIATION"]
    verifications = [s for s in steps if s["phase"] == "VERIFICATION"]

    assert len(findings) >= 1
    assert any(f["system_id"] == "support_platform" and f["resource_id"] == "support_002" for f in findings)
    assert len(remediations) >= 1
    assert len(verifications) >= 1


def test_active_data_flow_and_restore_risk_priority_ordering(audit_engine):
    """Edge Case 4: Active data flows and restore risks are remediated BEFORE record deletion."""
    # Case 11: has search_052, analytics_2034, support_864, AND active data_flow_9522
    case_11 = {
        "case_id": "case_11",
        "email": "novak.tomasz@icloud.com",
        "requested_at": "2026-09-10T12:00:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-09-12T12:00:00Z",
        "audit_at": "2026-10-01T12:00:00Z",
        "request_text": "Please delete my account and any personal data you hold about me. I want all records completely removed from all systems."
    }

    status, steps_str = audit_engine.audit_case(case_11)
    assert status == "INCOMPLETE"

    steps = json.loads(steps_str)
    remediations = [s for s in steps if s["phase"] == "REMEDIATION"]

    # Verify DISABLE_DATA_FLOW comes before DELETE_RECORD / REDACT_RECORD / ANONYMIZE_RECORD
    flow_step_idx = None
    first_record_idx = None

    for idx, s in enumerate(remediations):
        if s["operation"] in ("DISABLE_DATA_FLOW", "BLOCK_RESTORE"):
            if flow_step_idx is None:
                flow_step_idx = idx
        elif s["operation"] in ("DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"):
            if first_record_idx is None:
                first_record_idx = idx

    assert flow_step_idx is not None, "Expected DISABLE_DATA_FLOW in remediations"
    assert first_record_idx is not None, "Expected record remediation in remediations"
    assert flow_step_idx < first_record_idx, (
        f"Data flow disabling (idx {flow_step_idx}) must precede record remediation (idx {first_record_idx}) "
        "to prevent data recreation!"
    )


def test_retained_account_tombstone_safe_handling(audit_engine):
    """Edge Case 5: Retained account tombstone with null direct identifiers handled safely."""
    # Case 31: tombstone_440 in customer_data_snapshot_bundle_20260915.json
    case_31 = {
        "case_id": "case_31",
        "email": "a.eze08@gmail.com",
        "requested_at": "2026-09-04T12:00:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-09-06T12:00:00Z",
        "audit_at": "2026-09-15T12:00:00Z",
        "request_text": "Please permanently remove my account and any associated information. Ensure all records are erased from every system."
    }

    status, steps_str = audit_engine.audit_case(case_31)
    assert status == "COMPLETE", f"Expected COMPLETE for properly compliant tombstone, got {status}"

    steps = json.loads(steps_str)
    tombstone_steps = [s for s in steps if s["system_id"] == "identity_service" and "tombstone" in s["resource_id"]]
    assert len(tombstone_steps) == 1
    assert tombstone_steps[0]["operation"] == "VERIFY_RECORD_REDACTED"
    assert tombstone_steps[0]["state"] == "REDACTED"


def test_post_audit_evidence_exclusion(audit_engine):
    """Edge Case 6: Evidence captured strictly AFTER audit_at must not be used for findings or verifications."""
    # Case 01: audit_at is 2026-09-05T09:12:00Z
    # Any evidence file captured after that date (e.g. evidence_51 on 2026-09-15 or evidence_94 on 2026-09-26)
    # must be completely ignored.
    case_01 = {
        "case_id": "case_01",
        "email": "amina.elmasri@gmail.com",
        "requested_at": "2026-09-01T09:12:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-09-03T09:12:00Z",
        "audit_at": "2026-09-05T09:12:00Z",
        "request_text": "Please delete all personal data associated with this account. I request complete erasure from your systems."
    }

    status, steps_str = audit_engine.audit_case(case_01)
    assert status == "COMPLETE"

    steps = json.loads(steps_str)
    manifest = {em["file_id"]: em["captured_at"] for em in audit_engine.evidence_manifest}

    for s in steps:
        ev_id = s.get("evidence_id")
        if ev_id and ev_id in manifest:
            cap_at = manifest[ev_id]
            assert cap_at <= case_01["audit_at"], (
                f"Temporal violation: Step {s['step_no']} cited evidence {ev_id} "
                f"captured at {cap_at} which is AFTER audit_at {case_01['audit_at']}!"
            )


if __name__ == "__main__":
    pytest.main(["-v", __file__])
