# TRUSTNET hackathon demo runbook

## What this demo shows

TRUSTNET has two distinct matching demonstrations:

1. **Production dashboard — category-only matching.** The dashboard reads `GET /api/summary`. Its `fingerprint_matches` / `category_matches` count represents distinct normalized event categories shared by the bundled organization samples. It does not mean matching individual events or attacks.
2. **Synthetic failed-login correlation — isolated prototype.** `Backend/demo_login_correlation.py` evaluates deterministic, explicitly synthetic records. It is not called by the detector, dashboard, or API. Its `correlated` outcome means only that the synthetic inputs satisfy the prototype's configured rules; it does not prove an actual attack or shared attacker identity.
3. **Future real cross-organization correlation.** This needs authorized telemetry with suitable UTC windows, local aggregation and deduplication, an organization-separated architecture, and a reviewed protected-indicator protocol. The existing static tokens do not provide privacy and must not be replaced with raw indicators or ordinary hashes.

No step in this runbook requires VirusTotal. Disable it before starting the backend. Do not paste `.env` values, API keys, logs, tokens, or local aggregation IDs into slides or chat.

## Prerequisites

- Run from the repository root, with the checked-in `Backend/.venv` or a prepared Python environment containing the backend dependencies.
- Node.js/npm and the repository's installed frontend packages (`Frontend/node_modules`). This workspace was checked with Python 3.9.6, Node 26.12.0, and npm 11.20.0; compatible versions may vary by operating system.
- Ports `127.0.0.1:8000` for FastAPI and `localhost:5173` for Vite. Identify any listener before starting a service; do not terminate a process you did not start.
- The bundled CSVs and synthetic fixtures are for this demonstration only. Do not substitute organization telemetry.

## Start the services

Use three terminals. Before starting, identify port listeners and their working directories. Reuse an existing service only when it is the expected TRUSTNET process and its runtime configuration is understood. Do not terminate existing processes. The frontend reads `VITE_API_BASE_URL` at Vite startup and defaults to `http://127.0.0.1:8000`; for an isolated rehearsal, use an available backend port and set the frontend variable to that backend's base URL. The backend CORS allowlist currently permits frontend origins on `localhost:5173` and `127.0.0.1:5173`.

### Terminal 1 — backend with external lookups disabled

macOS/Linux:

```bash
cd Backend
source .venv/bin/activate
VIRUSTOTAL_ENABLED=false python -m uvicorn api:app --host 127.0.0.1 --port 8001
```

Windows PowerShell:

```powershell
cd Backend
.\.venv\Scripts\Activate.ps1
$env:VIRUSTOTAL_ENABLED = "false"
python -m uvicorn api:app --host 127.0.0.1 --port 8001
```

The environment setting overrides `.env` for this process. Keep this terminal open. Confirm `http://127.0.0.1:8001/` returns `status: running` before opening `/api/summary`. The summary path only makes VirusTotal calls when effective integration is enabled; this command explicitly disables it.

### Terminal 2 — dashboard

```bash
cd Frontend
VITE_API_BASE_URL=http://127.0.0.1:8001 npm run dev -- --host 127.0.0.1 --port 5173 --strictPort
```

Open `http://127.0.0.1:5173`. Keep the Vite terminal open. Vite reads `VITE_API_BASE_URL` at startup; it is the backend base URL, and the app appends `/api/summary`. `--strictPort` prevents Vite silently selecting a port not covered by the backend CORS allowlist. On the verified macOS workspace, a pre-existing Vite process bound to IPv6 `::1:5173` coexisted with this new server bound to IPv4 `127.0.0.1:5173`; this behavior may vary by operating system.

### Terminal 3 — checks and synthetic correlation

macOS/Linux:

```bash
cd Backend
source .venv/bin/activate
python -m unittest discover -v
python test_detector.py
python demo_login_correlation.py
```

Windows PowerShell:

```powershell
cd Backend
.\.venv\Scripts\Activate.ps1
python -m unittest discover -v
python test_detector.py
python demo_login_correlation.py
```

The backend tests mock VirusTotal HTTP calls. The detector command reads only the bundled CSV fixtures. The correlation runner reads only deterministic synthetic fixtures and makes no network calls.

## Expected observations

- The dashboard reports the two bundled organizations and their alert totals. With the current checked-in samples, the detector smoke check reports 7 alerts for Organization A and 3 for Organization B (10 total).
- The dashboard's match number is a distinct shared-category count. For these samples it is expected to be 3 (`repeated_failed_login`, `outbound`, and `port_scan`); it is not a count of related incidents.
- Privacy cards display the backend's sanitizer checks, not a guarantee of anonymity. VirusTotal should show disabled/no lookups for this run because the backend was started with `VIRUSTOTAL_ENABLED=false`.
- The synthetic runner prints a successful example such as `compatible_indicator_and_overlapping_windows | expected: correlated | actual: correlated | PASS | reasons: synthetic_evidence_compatible`.
- It also prints rejected/insufficient examples such as `different_indicators | ... not_correlated ... protected_indicators_do_not_match` and `missing_required_field | ... insufficient_evidence ... no_valid_cross_organization_pair`.
- The runner prints scenario names, outcomes, pass/fail, and generic reason codes only. It must not print tokens, aggregation IDs, raw event records, or sensitive identifiers.

## Suggested 3–5 minute presentation

1. **0:00–0:40 — Set the boundary.** Explain that the dashboard uses bundled sample CSVs, while the correlation runner uses separate synthetic fixtures. Neither demonstrates production-grade privacy or attribution.
2. **0:40–1:40 — Show the dashboard.** Point to organization alert totals, privacy-check statuses, and shared categories. Explicitly call its matches category-only: same event type does not mean same event or attacker.
3. **1:40–2:10 — Show the detector smoke check.** Mention the 7/3 alert totals from bundled samples; do not present them as external organization telemetry.
4. **2:10–3:30 — Run the synthetic correlation demo.** Highlight the positive `synthetic_evidence_compatible` scenario, then contrast `protected_indicators_do_not_match` and/or the insufficient `no_valid_cross_organization_pair` case. Explain that counts alone do not correlate records and time compatibility is required.
5. **3:30–4:30 — Explain limits and next work.** Describe the missing production evidence, organization separation, and need for a reviewed protected-indicator comparison design. A `correlated` result is rule satisfaction by synthetic evidence only; it does not prove an attack or shared attacker identity.

## Recovery steps

- **Dashboard says backend unavailable:** confirm the backend URL configured by `VITE_API_BASE_URL` returns `status: running` from `/`, and that the frontend's configured value points to that same backend. Do not stop a process you did not start. Confirm VirusTotal is disabled before requesting `/api/summary`.
- **Port 8000 is occupied or its configuration is unknown:** do not terminate the listener. Start the rehearsal backend on another free port with `VIRUSTOTAL_ENABLED=false`, then set `VITE_API_BASE_URL` to that backend's base URL before starting Vite. This runbook uses 8001.
- **Port 5173 is occupied:** do not terminate the listener. Reuse a known TRUSTNET frontend only if its configuration is understood. Otherwise check whether binding Vite to the other loopback address on port 5173 is available, as in the verified macOS run. If no allowed 5173 origin is free, stop and explain the blocker; a different frontend port needs to be added to the backend CORS allowlist before it can call the API.
- **Backend tests fail:** keep the full output, fix/restart from the repository's existing environment, and do not claim the demo is verified. Do not install or upgrade dependencies during the presentation.
- **Synthetic scenario reports `FAIL`:** rerun `python demo_login_correlation.py` once. If it persists, present the failure honestly and use the test output for diagnosis; do not edit fixture expectations live.
- **No time to recover the dashboard:** run the detector and synthetic commands from Terminal 3 and explain that category matching and synthetic correlation are separate. Do not describe synthetic results as dashboard/API results.

## Verification record for this workspace

Milestone 9 rehearsal findings above record the state at that time, when the frontend API URL was hardcoded. The URL is now configurable; see the startup commands above.

Milestone 11 verification in this workspace: listeners on port 8000 and IPv6 `::1:5173` belonged to TRUSTNET processes in this checkout (`Backend/` and `Frontend/` working directories). Their configuration was not assumed, and neither process was terminated. A separate backend ran on `127.0.0.1:8001` with `VIRUSTOTAL_ENABLED=false`; health returned `running`, and `/api/summary` returned `SUCCESS`, 2 organizations, 10 alerts (7 and 3), 3 category matches, passed privacy checks, and VirusTotal `integration_requested=false`, `integration_enabled=false`, and zero lookups. Source inspection confirmed the summary calls VirusTotal only when effective integration is enabled. A separate Vite process ran on `127.0.0.1:5173` with `VITE_API_BASE_URL=http://127.0.0.1:8001`; its served `App.jsx` module exposed that configured value and retained the `/api/summary` request. The HTML and API were reachable by HTTP. Browser rendering and the in-browser request/result display were not verified: browser automation's localhost origin approval was declined, and it was not retried. The backend suite passed 54 tests; detector smoke check passed with 7/3 alerts; all 12 synthetic scenarios passed; frontend lint, default build, and alternate-URL build passed. Tests emitted a non-fatal urllib3/LibreSSL warning. Temporary processes started for this check were stopped; the pre-existing listeners were left running. These checks are local to this workspace and do not establish production privacy or event-level correlation.
