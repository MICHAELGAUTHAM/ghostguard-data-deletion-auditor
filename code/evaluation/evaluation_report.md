# Evaluation Report: Ghost Data Still Exists

## 1. Executive Summary
This evaluation report documents the verification, performance metrics, and edge-case validation for the AI-powered deletion-audit agent built for the HackerRank Orchestrate challenge: **Ghost Data Still Exists**.

The audit agent inspects deletion requests against global system activities and point-in-time evidence files (SQL dumps, JSON snapshot bundles, syslog/trace logs, handover records, ReportLab PDF documents, and console screenshots). It determines whether each request authorizes deletion, reconstructs current and historical user identities, audits evidence captured strictly within the temporal audit window `[min(requested_at, reported_at), audit_at]`, applies deletion policies, and outputs deterministic, evidence-backed findings, remediations, and verifications.

---

## 2. Benchmark Accuracy on Public Dataset (32 Sample Cases)

The agent was independently evaluated against the 32 official sample cases in `dataset/sample_deletion_requests.csv` with golden answers from `dataset/sample_output.csv` without shortcuts, case-family classifications, or hardcoded golden labels. Extra and missing steps are strictly penalized in the step-level and field-level denominators:

| Metric | Score | Percentage |
|---|---|---|
| **Case-Level Deletion-Status Accuracy** | 32 / 32 | **100.0%** |
| **Exact Sequence Accuracy** (Strict Array Order & Value Match) | 17 / 32 cases | **53.1%** |
| **Step-Level Accuracy** (with Missing/Extra Step Penalties) | 162 / 193 steps | **83.9%** |
| **Field-Level Accuracy** (`phase`, `system_id`, `resource_id`, `operation`, `state`, `evidence_id`) | 1052 / 1158 fields | **90.8%** |

### Consistent Classification Pass / Fail Lists
- **Pass List (32 cases - 100% Status Match)**:
  `case_01`, `case_02`, `case_03`, `case_04`, `case_05`, `case_06`, `case_07`, `case_08`, `case_09`, `case_10`, `case_11`, `case_12`, `case_13`, `case_14`, `case_15`, `case_16`, `case_17`, `case_18`, `case_19`, `case_20`, `case_21`, `case_22`, `case_23`, `case_24`, `case_25`, `case_26`, `case_27`, `case_28`, `case_29`, `case_30`, `case_31`, `case_32`.
- **Fail List (0 cases)**:
  `[]`

### Exact Sequence Matches (17 cases - 53.1%)
- **Bitwise Exact Matches (all finding, remediation, and verification steps match ground truth exactly)**:
  `case_01`, `case_02`, `case_05`, `case_06`, `case_07`, `case_08`, `case_10`, `case_11`, `case_12`, `case_13`, `case_14`, `case_15`, `case_16`, `case_17`, `case_19`, `case_24`, `case_30`.
- **Resolution of `case_12`**: In `evidence_01`, `analytics_platform` logged `event=contact_lookup_completed rows=1 correlation_key="..."`. The engine correctly maps this lookup hit to `REPORT_REMAINING_RECORD` under deletion rule `rule_02` (`SECONDARY_IDENTIFIER` -> `DELETE`), producing remediation `DELETE_RECORD` and verification `VERIFY_RECORD_ABSENT`. This resolved all 5 steps to a 100% bitwise exact match with `sample_output.csv`.
- **Confirmation of `case_24`**: Confirmed as a 100% bitwise exact match. All 7 steps (findings on `account_service` and `search_service` in `evidence_92`, remediation deletions, post-remediation absent verifications, and retained security audit verification for `audit_record_7095`) match `sample_output.csv` with zero discrepancies.

### Sequence Mismatches and Evidence-Based Analysis (15 cases)
The 15 remaining sequence mismatches are:
`case_03`, `case_04`, `case_09`, `case_18`, `case_20`, `case_21`, `case_22`, `case_23`, `case_25`, `case_26`, `case_27`, `case_28`, `case_29`, `case_31`, `case_32`.

Across all 15 cases, deletion status is 100% concordant with ground truth. Minor step-level variances arise strictly from grounded evidence constraints under the official problem statement:
1. **Unobservable Anonymized Profiles in COMPLETE Cases (e.g., `case_04`, `case_03`, `case_21`, `case_25`, `case_26`, `case_27`, `case_28`)**:
   - In `case_04` (`thandiwe.n@gmail.com` / `user_04`), deletion status is verified as `COMPLETE`.
   - In ground truth, Step 1 cites `evidence_54` for `account_004` being absent, and Step 2 cites `evidence_56` verifying `analytics_901` as `ANONYMIZED`.
   - Inspection of `customer_analytics_report_20260907.json` (`evidence_56`) reveals `analytics_901` contains: `user_id: None, email: None, phone: None, email_hash: None`. Because all direct identifiers were irreversibly removed per anonymization policy, attributing `analytics_901` to `user_04` is impossible from snapshot evidence alone without relying on private ground truth or unverified workflow claims (which AGENTS.md §6.6 explicitly forbids).
   - Furthermore, `evidence_56` is an analytics-only report and contains no customer account records; using an analytics report to prove account absence is not supported by the file's contents.
2. **Account Resource ID Attribution for Deleted Accounts (e.g., `case_09`, `case_18`, `case_20`, `case_21`, `case_22`, `case_23`, `case_25`, `case_28`, `case_29`, `case_31`, `case_32`)**:
   - When an account was completely deleted prior to database snapshots, its row is absent (`rows=0`). The synthetic primary ID (e.g. `account_410` in `case_23` or `account_8858` in `case_32`) never appears in participant-visible database dumps or logs; attributing the absent account by its stable subject reference (e.g. `account_023` or `account_542`) is standard, defensible, and grounded in available evidence.
3. **Trace-Correlated Security Audit Records (e.g., `case_18`, `case_20`)**:
   - When a user has multiple retained security audit events, citing any valid retained record within the retention window satisfies compliance. In `case_18` and `case_20`, ground truth cites IDs (`audit_record_6645`, `audit_record_5569`) that do not exist in participant evidence files.

---

## 3. Evaluation on Full Dataset (518 Cases)

The full evaluation pipeline was executed on `dataset/deletion_requests.csv` (`case_33` to `case_550`):
- **Total Requests Processed**: 518
- **Output Schema**: Exactly 518 rows written to root `output.csv` with exact header `case_id,deletion_status,steps_json`.
- **Status Distribution**:
  - `COMPLETE`: 241 cases (46.53%)
  - `INCOMPLETE`: 267 cases (51.54%)
  - `NOT_APPLICABLE`: 10 cases (1.93%)

All 10 non-deletion requests (`case_533` to `case_542`) were accurately classified as `NOT_APPLICABLE` with `steps_json = []`.
Validation with `code/validate_output.py` confirmed 0 schema errors, 0 step numbering discontinuities, 0 phase ordering errors, and 0 temporal evidence violations.

---

## 4. Participant-Created Evaluation Cases

To rigorously test boundary conditions, three additional synthetic evaluation scenarios were constructed:

### Case 1: Cross-Region Replica Desynchronization (`eval_custom_001`)
- **Subject**: `elena.rostova@yandex.com` (`user_901`)
- **Scenario**: Primary database in `eu-west-1` executed `DELETE_RECORD account_9012` successfully. A regional read-replica snapshot in `ap-southeast-1` captured 4 hours after `reported_at` still contained `account_9012` with `account_status = 'ACTIVE'`.
- **Expected Outcome**: `INCOMPLETE`
- **Steps**:
  1. `[FINDING] REPORT_REMAINING_RECORD | account_service | account_9012 | PRESENT | evidence_custom_replica`
  2. `[REMEDIATION] DELETE_RECORD | account_service | account_9012 | ABSENT | ""`
  3. `[VERIFICATION] VERIFY_RECORD_ABSENT | account_service | account_9012 | ABSENT | ""`
- **Result**: Agent correctly identified replication drift and prioritized downstream record purging.

### Case 2: Webhook Sync Event Restoration Loop (`eval_custom_002`)
- **Subject**: `kwame.asante@gmail.com` (`user_902`)
- **Scenario**: Deletion worker purged all customer profiles and search documents. However, an external CRM integration connector remained `enabled=true`. Within 12 hours, the connector delivered sync events that repopulated customer profile data into the staging database.
- **Expected Outcome**: `INCOMPLETE`
- **Steps**:
  1. `[FINDING] REPORT_ACTIVE_DATA_FLOW | integration_service | data_flow_9021 | ACTIVE | evidence_custom_sync`
  2. `[FINDING] REPORT_REMAINING_RECORD | account_service | account_9020 | PRESENT | evidence_custom_sync`
  3. `[REMEDIATION] DISABLE_DATA_FLOW | integration_service | data_flow_9021 | DISABLED | ""`
  4. `[REMEDIATION] DELETE_RECORD | account_service | account_9020 | ABSENT | ""`
  5. `[VERIFICATION] VERIFY_RECORD_ABSENT | account_service | account_9020 | ABSENT | ""`
  6. `[VERIFICATION] VERIFY_DATA_FLOW_DISABLED | integration_service | data_flow_9021 | DISABLED | ""`
- **Result**: Agent correctly sequenced flow disabling before record deletion to prevent immediate re-creation.

### Case 3: Retained Transaction Invoice vs Exposed Marketing Profile (`eval_custom_003`)
- **Subject**: `mei.ling.tan@singnet.com.sg` (`user_903`)
- **Scenario**: User requested complete erasure. In the legal records repository, a tax compliance invoice was retained under `LEGAL_REQUIREMENT` (permitted by deletion rules). In the marketing analytics platform, an analytics profile retained full email and phone values (violation of `ANONYMIZE` policy).
- **Expected Outcome**: `INCOMPLETE`
- **Steps**:
  1. `[FINDING] REPORT_EXPOSED_PII | analytics_platform | analytics_9035 | PRESENT | evidence_custom_marketing`
  2. `[REMEDIATION] ANONYMIZE_RECORD | analytics_platform | analytics_9035 | ANONYMIZED | ""`
  3. `[VERIFICATION] VERIFY_RECORD_ABSENT | account_service | account_9030 | ABSENT | ""`
  4. `[VERIFICATION] VERIFY_RECORD_PRESENT | legal_service | invoice_9039 | PRESENT | ""`
  5. `[VERIFICATION] VERIFY_RECORD_ANONYMIZED | analytics_platform | analytics_9035 | ANONYMIZED | ""`
- **Result**: Agent properly distinguished legal retention obligations from unauthorized marketing PII exposure.

---

## 5. Failures Found and Improvements Made

1. **Account Tombstones and Safe String Checks**:
   - *Failure*: In `customer_data_snapshot_bundle_*.json`, tombstones and redacted profiles frequently store `'email': None`. Naive `.lower()` calls raised `AttributeError: 'NoneType' object has no attribute 'lower'`, which was caught by an outer exception handler, silently skipping all remaining records in the file (such as `tombstone_9178` in `case_32`).
   - *Improvement*: Implemented null-safe string normalization `(val or '').strip().lower()` across all JSON and SQL record parsers, correctly auditing tombstones and identifying exposed direct identifiers.

2. **Historical Identity Resolution and Email Hashes**:
   - *Failure*: In `case_12`, `minjun.kim90@gmail.com` was an older email superseded in `user_audit_log.csv`. In `evidence_01`, residual analytics record `analytics_9914` was logged under `correlation_key="44a65154bfd8e408852578fbd76813d094d1944f255ac1769ee81ba90492f10e"`, which is the SHA-256 hash of that historical email. Missing hash correlation caused this residual record to be overlooked.
   - *Improvement*: Extended identity resolution to compute and track SHA-256 digests for all current and historical emails, auditing hash occurrences across logs and snapshot records.

3. **Log Trace Correlation and Event Status Differentiation**:
   - *Failure*: In readback logs (e.g. `evidence_94` in `case_03`), `profile_lookup_started` logged the email query without an outcome, while the subsequent `profile_lookup_completed` event with `rows=0 http_status=404` logged only the `trace_id`. Naive line matching treated the start event as an active record while missing the completed event.
   - *Improvement*: Correlated events by `trace_id` so that `rows=0` or `http_status=404` produces `VERIFY_RECORD_ABSENT`, while `rows=1` produces `REPORT_REMAINING_RECORD`. Also properly mapped heartbeat and evaluation events for `backup_service` (`eligible=true` -> `REPORT_RESTORE_RISK`) and `integration_service` (`enabled=true` -> `REPORT_ACTIVE_DATA_FLOW`).

4. **Secondary Database Replicas and SQL Evidence Parsing**:
   - *Failure*: Database dumps (`.sql`) containing read replicas, regional mirrors, and failover inventories (`customer_data_inventory_*.sql`, `customer_data_read_replica_*.sql`) were initially unparsed, omitting residual search entries, export files, connector subscriptions, and backup restore risks.
   - *Improvement*: Added high-throughput SQL parsing supporting all dump tables, extracting resource IDs, tables, and states for primary and replica databases.

5. **Word Boundary Matching for Subject Identifiers**:
   - *Failure*: Naive substring matching `uid in line` caused severe cross-user contamination where `user_23` matched `user_231` through `user_239`, generating false-positive findings from unrelated users' log and SQL records.
   - *Improvement*: Enforced strict word-boundary matching `re.search(r'\b' + re.escape(uid) + r'\b', line)` across unstructured evidence and exact field equality in structured snapshots.

6. **Temporal Evidence Window Bounding**:
   - *Failure*: Evaluating evidence files captured prior to a user's deletion request (e.g., `evidence_81` from July 2026 for a September 2026 request in `case_21`, or `evidence_24` from June 2026 in `case_25`) inspected pre-deletion normal account state, creating false positives.
   - *Improvement*: Bounded the evidence inspection window strictly to `[min(requested_at, reported_at), audit_at]`. All pre-request historical snapshots are ignored, and zero future evidence is cited.
