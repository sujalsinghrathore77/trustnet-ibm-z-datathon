# Synthetic repeated-login correlation prototype

## Scope

This is an isolated demonstration of correlation logic using deterministic, synthetic data. It is not detector output, not part of `/api/summary`, does not read the sample CSVs, makes no network requests, and does not change production category matching. A `correlated` result means only that two synthetic records satisfy this prototype's rules. It is not evidence of a real attack, common attacker, or production-grade privacy.

Implementation: `Backend/login_correlation_prototype.py`. Fixtures: `Backend/synthetic_login_fixtures.py`. Tests: `Backend/test_login_correlation_prototype.py`.

Deterministic demonstration runner: `Backend/demo_login_correlation.py`. Run it from `Backend` with `python demo_login_correlation.py`. It prints only scenario names, expected and actual outcome labels, pass/fail, and existing generic reason codes. It never prints evidence records, tokens, aggregation IDs, or raw identifiers.

## Versioned evidence schema

Every test record uses `schema_version = trustnet-synthetic-login-evidence/v1`, `event_type = repeated_failed_login`, and `synthetic = true`.

| Field | Type | Use and handling |
| --- | --- | --- |
| `schema_version` | string | Strict version check; unsupported versions are insufficient. |
| `event_type` | string | Must be `repeated_failed_login`; category alone never correlates. |
| `organization_id` | enum string | `SYNTHETIC_ORG_A` or `SYNTHETIC_ORG_B`, used to ensure comparison is cross-organization. |
| `local_aggregation_id` | synthetic-prefixed string | Deterministic deduplication key. It is local metadata and must not be returned or shared in a real deployment. |
| `window_start_utc`, `window_end_utc` | offset-aware ISO timestamp | Required UTC-normalizable time window; max duration 15 minutes. |
| `failed_login_count` | nonnegative integer | Count threshold input; booleans and other types are invalid. Both sides must have at least 5. |
| `protected_indicator_token` | string with `SYNTHETIC_ONLY_LOGIN_INDICATOR:` prefix | Fake exact-comparison token only. It is not derived from an IP, username, or telemetry and is not safe as a production token. |
| `synthetic` | literal `true` | Guards the synthetic-only module from accepting ordinary records by default. |

The strict allowlist rejects extra keys, including raw records, IPs, usernames, email addresses, credentials, and arbitrary unsalted hashes. `local_aggregation_id` is used only inside the in-process test prototype for deduplication. Results omit the IDs and tokens.

## Rules

1. Reject records with missing required keys, incorrect types, wrong version/category, `synthetic` other than true, invalid timestamps, reversed windows, windows longer than 15 minutes, or tokens outside the synthetic-only namespace. Rejected data is not compared; if no valid cross-organization pair remains, the outcome is `insufficient_evidence`.
2. Compare only records whose organization labels differ. Both counts must be at least 5. Counts do not establish a match.
3. Require exact equality of the fake synthetic indicator token. Different tokens mean `not_correlated`, even with equal counts and overlapping windows.
4. Require window intersection of at least 60 seconds and start-time skew no greater than 5 minutes. The configured bounds are 0–15 minutes for skew and more than 0–15 minutes for minimum overlap. The defaults are prototype policy, not empirically validated production thresholds.
5. Return `correlated` only if at least one valid pair satisfies all rules. Otherwise return `not_correlated` when valid pairs were evaluated, or `insufficient_evidence` when there is no usable cross-organization pair. Reasons are generic reason codes only.
6. Exact repeated records with the same organization-local ID are counted once. If one local ID has conflicting content, all records for that ID are quarantined as invalid. This is deterministic for input order and does not expose the ID in output.

## Synthetic fixtures and coverage

Fixtures include one compatible positive pair; different-indicator pairs; non-overlapping windows; a same-count/different-indicator case; below-threshold evidence; missing fields; unsupported version; malformed/reversed timestamps; wrong field types; exact duplicates; conflicting duplicate IDs; raw indicator rejection; and an input immutability/privacy-output check. The test also verifies that the existing category matcher still returns only its original category-level shape.

No fixture is inserted into the production CSVs or summary API. The fake tokens are static, public test strings and provide no confidentiality or integrity. They must never be replaced with ordinary SHA-256 hashes of real IP addresses or usernames.

## Evaluation matrix

| Evaluation dimension | Demo scenario | Expected result | Rule exercised |
| --- | --- | --- | --- |
| Same synthetic indicator, overlapping windows | `compatible_indicator_and_overlapping_windows` | `correlated` | All required evidence aligns. |
| Different synthetic indicators | `different_indicators` | `not_correlated` | Indicator equality is required even if time overlaps. |
| Same indicator, non-overlapping windows | `same_indicator_non_overlapping_windows` | `not_correlated` | Temporal compatibility is required. |
| Minimum failed-login count | `below_minimum_failed_login_count` | `not_correlated` | Both counts must be at least 5. |
| Count exactly at minimum threshold | `count_at_minimum_threshold` | `correlated` | Threshold comparison is inclusive (`>= 5`). |
| Allowed start-time skew | `start_skew_at_allowed_boundary` | `correlated` | Five-minute default boundary is inclusive. |
| Excessive start-time skew | `start_skew_above_allowed_boundary` | `not_correlated` | One second beyond the default boundary is rejected. |
| Duplicate evidence | `exact_duplicate_evidence` | `correlated` | Exact same-ID record is removed once, not counted as another pair. |
| Conflicting duplicate IDs | `conflicting_duplicate_identifier` | `insufficient_evidence` | All records with that conflicting local ID are quarantined. |
| Missing required field | `missing_required_field` | `insufficient_evidence` | Invalid evidence is not compared. |
| Invalid field type | `invalid_field_type` | `insufficient_evidence` | Type validation fails closed. |
| Repeated execution determinism | `repeated_execution_is_deterministic` | `correlated` | Identical synthetic inputs produce identical result objects. |

The runner returns/prints only aggregate outcomes. The existing reason-code vocabulary is `below_minimum_count`, `fields_outside_prototype_allowlist`, `invalid_or_missing_utc_timestamp`, `invalid_failed_login_count`, `invalid_records_ignored`, `invalid_synthetic_aggregation_id`, `invalid_synthetic_indicator_token`, `invalid_synthetic_organization`, `no_valid_cross_organization_pair`, `no_valid_evidence_pair`, `protected_indicators_do_not_match`, `record_must_be_object`, `required_fields_missing`, `synthetic_data_required`, `synthetic_evidence_compatible`, `time_windows_incompatible`, `unsupported_event_type`, `unsupported_schema_version`, `window_end_not_after_start`, and `window_exceeds_maximum`. The demo does not create scenario-specific reason codes.

Reproduce the full backend suite from `Backend` with `python -m unittest discover -v`; run the fixture smoke check with `python test_detector.py`. Frontend checks remain `npm run lint` and `npm run build` from `Frontend`.

## Before real use

Real deployment is blocked on authorized source telemetry with dated, timezone-aware aggregation windows; organization-local aggregation and deduplication; a reviewed schema and field governance; an organization-separated architecture; consent, access, retention, audit and abuse controls; and a threat-modeled protected-indicator comparison protocol reviewed by security specialists. The existing production detector aggregates failed logins per raw source IP across the CSV but emits no UTC window. The current sanitizer removes raw source IPs, and the API centrally analyzes both CSVs. This prototype neither fills those gaps nor demonstrates a privacy guarantee. No VirusTotal or other external service is involved.
