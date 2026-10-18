# TRUSTNET threat-correlation readiness design (v1)

## Status and scope

This document defines a versioned *candidate* production evidence contract and its validation boundary. A separate synthetic-only repeated-login prototype now exists in `Backend/login_correlation_prototype.py`; it does not implement production event-level correlation and is not called by the detector, API, or dashboard. The current detector and sanitizer do not provide enough compatible, reliably timestamped evidence to support defensible cross-organization event matching. The existing `fingerprint_matches` / `category_matches` remain category-level results; a shared category is not evidence that two alerts describe the same event, campaign, or actor.

The validator in `Backend/correlation_readiness.py` checks record shape and timestamps only. `VALID_SCHEMA_ONLY` means exactly that: structurally valid against this proposed contract. It does not establish truth, validate a protected-indicator comparison, or produce a match. Its synthetic schema fixtures exist only in tests.

## Existing source-data limitations

The current detector consumes local CSVs and the sanitizer removes source addresses. The available sanitized alerts include event category, severity, and generic reasons; outbound and port-scan alerts may include legacy clock-only timestamps. Repeated failed-login detection produces aggregate counts but no timestamp window or service class. Outbound alerts do not contain a destination indicator or transfer-size band. Port-scan alerts do not contain an aggregate interval or target/port sets. Legacy sample timestamps have no date or timezone. Consequently, current records assess as insufficient; the proposed evidence fields below cannot be populated from today's alerts without adding source telemetry and a locally reviewed aggregation step.

## Candidate versioned schemas and sharing allowlist

All records carry `schema_version = trustnet-correlation-evidence/v1` and one supported `event_type`. Unknown keys fail validation. These fields are a design target, not permission to export a field automatically. Any protected-overlap boolean requires a separately selected and reviewed comparison protocol; it is not currently generated.

| Event type | Candidate share allowlist | Candidate aggregation / comparison rule |
| --- | --- | --- |
| `repeated_failed_login` | `schema_version`, `event_type`, `window_start_utc`, `window_end_utc`, `failed_attempts_band`, `service_class`, `protected_origin_overlap` | Aggregate in aligned 15-minute UTC windows. A potential related-activity result would require compatible service class, overlapping window within clock tolerance, and a positive protected-origin set comparison. Counts are bands, not exact counts. |
| `outbound` | `schema_version`, `event_type`, `occurred_at_utc`, `destination_service_class`, `transfer_size_band`, `protected_destination_overlap` | Compare only when timestamps are within the configured pairwise tolerance and service class / transfer band are compatible, with a positive protected-destination comparison. One shared coarse category or common service alone is insufficient. |
| `port_scan` | `schema_version`, `event_type`, `window_start_utc`, `window_end_utc`, `scan_volume_band`, `protected_target_set_overlap`, `protected_port_set_overlap` | Aggregate in aligned 5-minute UTC windows. Require temporal overlap within tolerance and both target-set and port-set comparisons. A broad scan-volume band alone is insufficient. |

Field meanings and allowed values for bands and service classes must be governed in a future schema revision before producers emit them. Booleans above represent the result of a protected set comparison, not the protected values themselves. Version changes are required for incompatible field or semantic changes.

## Timestamp, windows, duplicates, and invalid evidence

- Timestamps must be ISO-8601 with an explicit UTC offset. The validator normalizes accepted timestamps to UTC (`Z`). Naive timestamps are not assumed to be UTC.
- Legacy time-only values (for example `10:05:00`) are classified as legacy and remain insufficient: there is no safe way to infer date, timezone, or which side of midnight applies.
- Missing required evidence is `INSUFFICIENT_EVIDENCE`; malformed timestamps, unsupported types/versions, extra fields, invalid types, and reversed/oversized windows are invalid. Neither status yields a match.
- Candidate aggregation windows are aligned UTC windows, 15 minutes for repeated failed logins and 5 minutes for port scans. Outbound uses event time. The current five-minute clock-skew tolerance is provisional; production use needs measured clock behavior, an explicit policy, and boundary tests. Do not silently widen windows to increase matches.
- Conflicting required evidence (such as incompatible services, disjoint protected indicators, or time outside tolerance) must result in no event-level correlation. A missing side is insufficient, not a wildcard.
- Deduplication must happen at each organization using a stable local event identifier and a documented detector-specific key. The identifier and raw event remain local. Until the source can supply that identifier and semantics are agreed, preserve input records; do not deduplicate merely because sanitized records look identical. Dedupe policy must avoid collapsing separate repeated activity.
- Reject malformed records at the validation boundary and record a non-sensitive reason code. Do not coerce malformed values into valid evidence.

## Privacy allowlist and local-only data

Only the schema table is eligible for consideration as shared evidence, and then only after protocol, consent, retention, and deployment review. The following remain local: raw source/destination IPs and other network addresses; usernames, emails, hostnames, MAC/device/user identifiers; credentials/passwords; raw logs/records; local event IDs; and any fields not explicitly allowlisted. They are necessary for local investigation and can identify people, systems, or network topology.

Raw IPs must not be shared because they directly expose infrastructure and may identify users or customers. Unsalted hashes of IP addresses must not be shared as a substitute: IP address spaces are enumerable, so an observer can hash candidate addresses and reverse the mapping; stable hashes also enable cross-dataset linkage. A hash alone does not establish cryptographic privacy. Any protected comparison must be selected and threat-modeled separately, including leakage from repeated queries, outputs, timing, and small sets.

## Organization-separated architecture target

Each organization should ingest and detect on its own systems, retain raw data and stable deduplication keys locally, aggregate and sanitize under a reviewed versioned allowlist, and send only minimum approved evidence to a separately governed coordinator or comparison service. The coordinator should enforce authentication, participant authorization, consent, purpose limitation, retention/deletion, audit, and rate limits. Current code centrally loads both organizations' CSVs, so it is a demonstration arrangement and does not establish organization-separated processing or privacy guarantees.

Protected comparison options to evaluate:

1. **Private set intersection / OPRF-based protocols:** can support overlap checks without either party simply publishing its set, but still require a vetted protocol and implementation, authentication, key management, abuse/query controls, and a leakage analysis. Output overlap itself may be sensitive. No such protocol exists in this project today.
2. **Shared-key HMAC tokens:** operationally simpler but expose equality and depend on key distribution, rotation, compromise handling, domain separation, and resistance to dictionary attacks. They are not a default privacy guarantee and are not equivalent to unsalted hashes.
3. **Trusted execution environment:** can keep inputs encrypted outside a hardware boundary, but adds hardware/vendor trust, attestation, side-channel, patching, and operational assumptions. It is not implemented or evaluated here.

No approach should be described as cryptographically private until an explicit threat model, protocol review, implementation review, and operational controls are complete.

## False positives and leakage risks

Common services, NAT/proxies, shared hosting, popular destinations, coarse time windows, detector duplication, clock drift, and broad count bands can make unrelated activity look similar. Requiring multiple independent sanitized evidence dimensions can reduce ambiguity but cannot establish common attribution. Rare service/time/volume combinations, boolean overlap outcomes, repeated queries, or small participant sets can leak information even without raw indicators. Correlation outputs should be described as possible related activity and require analyst review; they must not identify an attacker.

## Readiness tests and next milestone

`Backend/test_correlation_readiness.py` tests timestamp normalization and rejection, schema allowlists, missing/malformed evidence, and duplicate preservation using test-only contract fixtures. These fixtures do not represent production detector evidence and cannot be surfaced as detections.

Before implementing event-level correlation on production telemetry, the next milestone must: (1) obtain the missing event fields from authorized local telemetry, (2) define and validate category-specific aggregation and dedupe semantics, (3) choose an organization-separated deployment and protected-indicator protocol after threat modeling, (4) implement versioned producers and independent consumer validation, and (5) add end-to-end tests for actual producer output and negative/conflicting evidence. Until then, production retains category-only matching with explicit labeling and emits no event-level matches or confidence scores. The isolated test prototype is documented in `docs/synthetic-login-correlation-prototype.md`.
