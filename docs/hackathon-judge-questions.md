# TRUSTNET: likely hackathon judge questions

## Matching and evidence

### 1. What does the production matcher actually match?

It normalizes `event_type` by trimming whitespace and lowercasing it, hashes that category with SHA-256, and counts distinct categories present in both bundled organizations. The API currently reports three for these samples: `outbound`, `port_scan`, and `repeated_failed_login`.

### 2. Do three fingerprint matches mean three related attacks?

No. They are three shared categories, not event-level evidence. They do not prove the same incident, campaign, attack, or actor.

### 3. Why use SHA-256 if the categories are already visible?

The current prototype's fingerprint function uses SHA-256 over canonical JSON containing only normalized `event_type`. This is a deterministic category identifier, not a secret or privacy mechanism. The output count does not provide event-specific evidence.

### 4. How is the synthetic correlation different?

It is isolated from the detector, dashboard, and `/api/summary`. It evaluates fake, explicitly synthetic records using a matching synthetic-only token, failed-login counts, and time windows. Its output describes satisfaction of those test rules only; it is not production correlation.

### 5. What is the positive demo case?

`compatible_indicator_and_overlapping_windows` satisfies the prototype rules and returns `correlated` with the generic reason `synthetic_evidence_compatible`. The runner does not print the token or evidence record.

### 6. What is a rejected case?

`different_indicators` returns `not_correlated` with `protected_indicators_do_not_match`, even though other values can be compatible. `missing_required_field` instead produces `insufficient_evidence` because there is no valid pair to compare.

### 7. What are the synthetic thresholds and time rules?

Each synthetic record must have at least five failed logins. Evidence windows can be no longer than fifteen minutes; the default comparison requires at least one minute of overlap and start times at most five minutes apart. The overlap and skew boundaries are tested. These are prototype settings, not validated operational thresholds.

### 8. Is the production detector using the same five-login rule?

The production CSV detector groups `failed_login` rows by raw source IP across the whole file and emits a summary alert when summed `failed_attempts` is at least five. It does not create the UTC windows used by the synthetic prototype. The prototype's count threshold is applied separately to each synthetic record.

### 9. How are missing, malformed, or conflicting synthetic records handled?

Missing evidence is not treated as a wildcard. Invalid records are rejected; if no usable cross-organization pair remains, the result is `insufficient_evidence`. Exact duplicates with the same local synthetic ID are deduplicated; conflicting content under one ID is quarantined. Neither tokens nor IDs are emitted by the demo runner.

### 10. How do you address false positives?

Category overlap is deliberately described as category-only and is too broad to establish related activity. The synthetic rules reject mismatched tokens and incompatible times, but only in fake fixtures. The thresholds have not been validated against real data. Any future production result would need analyst review and measured evaluation; no precision or recall figures are available.

## Privacy and external services

### 11. Why use synthetic data?

The project does not yet have authorized, dated, timezone-aware telemetry and approved sharing rules for real cross-organization evaluation. Synthetic fixtures make deterministic positive, negative, malformed, duplicate, and boundary tests possible without presenting fake values as real detections.

### 12. What does the privacy check mean?

The sanitizer removes selected sensitive field names recursively and redacts selected IPv4/email patterns in strings. The report checks those patterns in sanitized output and whether record counts remain equal. A `PASSED` status is limited to those checks; it is not a guarantee of complete anonymization, confidentiality, or production security.

### 13. Are the organizations actually isolated from each other?

No. The current FastAPI process centrally reads both bundled CSV files. The project does not implement separate organization deployments, tenant authorization, or a coordinator protocol. Organization-separated processing is future architecture work.

### 14. Are raw IPs or hashes of IPs shared for matching?

The production category matcher ignores IPs. The current prototype does not use real indicators. Raw IPs must not be shared as correlation tokens; unsalted IP hashes are also unsafe because address spaces can be enumerated and stable values can be linked. The fake synthetic tokens are public test strings, not protected indicators.

### 15. What data can go to VirusTotal?

When effectively enabled, the API submits unique globally routable source-IP indicators from local alerts to VirusTotal's IP lookup endpoint, not complete logs. The API response can include indicator-level lookup results. Even with integration disabled, a public indicator may appear in the response as `SKIPPED` with its IP address. The current bundled response has zero public indicators. For this rehearsal, VirusTotal is explicitly disabled, so no lookup request is made. Do not display raw API output if the dataset or integration configuration is uncertain.

### 16. Is VirusTotal required?

No. It is an optional external integration. `VIRUSTOTAL_ENABLED=false` explicitly disables it even if a key is configured. A key is never returned in the summary. The 54-test backend suite mocks external HTTP calls; routine tests do not require live VirusTotal access.

## Product, operations, and roadmap

### 17. What does the current dashboard show?

It renders the live summary API's organization totals, category-match count, privacy-check results, shared categories, and VirusTotal status. In the current bundled-data response it reports two organizations, ten alerts, three category matches, and passed checks. These are local sample results, not customer or production results.

### 18. Has this been deployed or load-tested for many organizations?

No. The current API analyzes two local CSVs synchronously in one backend process. There are no deployment-scale, throughput, latency, or multi-tenant benchmark results to report.

### 19. What would be needed before real cross-organization correlation?

Authorized event data with reliable UTC timestamps; locally governed aggregation and deduplication; an agreed versioned allowlist; participant separation, consent, authentication, access, retention, and audit controls; and a threat-modeled protected-indicator comparison protocol. The readiness document proposes schemas but the detector does not emit them.

### 20. Is the proposed readiness schema already a correlation feature?

No. `correlation_readiness.py` validates candidate schema shape, allowlisted fields, and timestamps. `VALID_SCHEMA_ONLY` means a record passed those structural checks; it is not a match and does not establish evidence truth. Current sanitized alerts remain insufficient for event-level correlation.

### 21. Does TRUSTNET use AI or machine learning?

No machine-learning inference is used in the current path described here. The production detector uses explicit rules such as port lists, transfer-size thresholds, and failed-login aggregation. There are no trained-model claims or model benchmark results.

### 22. What is the realistic next milestone?

First obtain approved source telemetry and settle category-specific evidence, UTC window, and deduplication semantics. Then select and review an organization-separated architecture and protected-comparison design. Implement production evidence generation only after those decisions, with negative, malformed, privacy-regression, and end-to-end tests. Evaluate against authorized labeled data before reporting effectiveness.
