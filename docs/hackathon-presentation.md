# TRUSTNET hackathon presentation script

## Before the presentation

Use bundled sample CSVs for the dashboard and separate synthetic fixtures for the correlation demo. Do not replace them with real organization telemetry. Start the backend with VirusTotal explicitly disabled. Check port ownership first and do not stop a listener you did not start. The commands below use the available backend port 8001 and the frontend's allowed local origin at port 5173; change the backend port and `VITE_API_BASE_URL` together if 8001 is occupied.

Terminal 1 — from the repository root:

```bash
cd Backend
VIRUSTOTAL_ENABLED=false .venv/bin/python -m uvicorn api:app --host 127.0.0.1 --port 8001
```

Terminal 2:

```bash
cd Frontend
VITE_API_BASE_URL=http://127.0.0.1:8001 npm run dev -- --host 127.0.0.1 --port 5173 --strictPort
```

Open `http://127.0.0.1:5173`. Confirm that the dashboard is connected before presenting. Do not display a raw API response or logs on screen; show the aggregate dashboard only.

Terminal 3 — run the synthetic-only evaluation:

```bash
cd Backend
.venv/bin/python demo_login_correlation.py
```

The safe rehearsal command disables VirusTotal even if a key exists in `Backend/.env`; do not print environment contents or API keys. The current backend summary path only attempts VirusTotal lookups when integration is effectively enabled. If the backend cannot be started with the flag set, do not request `/api/summary` for this rehearsal.

## Timed script (about 4 minutes)

### 0:00–0:35 — Problem and approach

**Show:** TRUSTNET Overview dashboard.

**Say:** “Organizations can detect suspicious activity locally, but sharing raw security logs can expose addresses, accounts, and infrastructure. TRUSTNET is a prototype exploring a narrower workflow: run rule-based checks on bundled sample logs, sanitize alert copies, and compare high-level event categories. Today’s implementation is a demo, not a deployed multi-organization privacy system.”

### 0:35–1:20 — Current dashboard result

**Show:** Overview cards and the organization summary.

**Say:** “The current sample response reports two organizations and ten alerts: seven for Organization A and three for Organization B. Both backend privacy checks passed. That status means the sanitizer's configured checks passed for these records; it is not proof that every sensitive value is removed or that the system is production-safe. VirusTotal is explicitly disabled for this rehearsal.”

**Verified sample values:** 2 organizations; 10 alerts; 3 category matches; both organization privacy checks `PASSED`, with zero reported leaks. These were verified from a local `/api/summary` response on this workspace using `VIRUSTOTAL_ENABLED=false`. The values depend on the bundled sample CSVs and can change if those files change.

### 1:20–1:55 — Explain category matching

**Show:** Threat Matches page and its shared category labels.

**Say:** “The three matches are the distinct normalized categories `outbound`, `port_scan`, and `repeated_failed_login`, present in both sample organizations. A SHA-256 digest is generated from the category value, not from an event-specific indicator. Therefore, three means three shared categories—not three shared attacks, related incidents, or identified attackers.”

### 1:55–2:20 — State the architecture boundary

**Show:** Keep the dashboard visible; do not expose raw CSV or API result details.

**Say:** “The current API process reads both bundled CSVs centrally. Sanitized alert copies are used for category comparison, while local alerts remain available to the backend's optional VirusTotal path. This is not yet organization-separated processing. If enabled, VirusTotal receives unique globally routable source-IP indicators; it does not receive complete logs. We disabled it for this demo.”

### 2:20–3:25 — Run the synthetic correlation demo

**Show:** Terminal 3 running `python demo_login_correlation.py` (or the virtual-environment command above). Point only to scenario labels, outcomes, and reason codes; do not reveal fixture records or tokens.

**Say:** “This is a separate prototype that does not feed the dashboard or production API. One positive case is `compatible_indicator_and_overlapping_windows`: the two explicitly synthetic records satisfy the configured indicator, time, and minimum-count rules, so the runner prints `correlated` with `synthetic_evidence_compatible`. A rejected case is `different_indicators`, which prints `not_correlated` with `protected_indicators_do_not_match`. The runner evaluates twelve synthetic scenarios, including invalid and insufficient evidence.”

“In this prototype each side needs at least five failed logins, a matching fake synthetic token, at least one minute of window overlap, start times no more than five minutes apart, and windows no longer than fifteen minutes. These are demonstration settings, not empirically validated production thresholds. A `correlated` outcome means only that synthetic inputs satisfy those rules. It does not establish an actual attack or shared attacker identity.”

### 3:25–4:10 — Limitations and roadmap

**Show:** Return to the dashboard or show the readiness document's “Before real use” section.

**Say:** “The production matcher remains category-only. Current detector outputs do not contain the timestamped, event-specific evidence needed for defensible event correlation. The separate readiness validator checks a proposed schema; it does not correlate production evidence. The next work is to obtain authorized timestamped source data, define local aggregation and deduplication, decide an organization-separated deployment and consent/access controls, then threat-model and review any protected-indicator comparison protocol before implementing it. We have no real-telemetry benchmark, production privacy guarantee, or attribution result to claim.”

## Questions to invite

Use [hackathon-judge-questions.md](hackathon-judge-questions.md) for concise answers. If asked whether matching identifies a shared attacker, answer no: neither current category matching nor the synthetic test establishes identity or attribution.

## Recovery

- If the dashboard cannot connect, verify the selected backend's `/` health response and ensure Vite was started with `VITE_API_BASE_URL` pointing to that backend. Restart Vite after changing the variable.
- If port 8001 is occupied, inspect its owner; do not terminate it. Choose a free backend port, start with `VIRUSTOTAL_ENABLED=false`, and update `VITE_API_BASE_URL` to match.
- Backend CORS currently permits `http://localhost:5173` and `http://127.0.0.1:5173`. If no supported origin is available, do not silently claim the dashboard is connected; resolve the port/CORS constraint before presenting.
- If the correlation demo reports a failure, show the failure honestly. Do not alter fixtures or expected outcomes during the presentation.
- If dashboard verification is blocked, present the synthetic demo only as a separate synthetic prototype; do not call it a production API result.
