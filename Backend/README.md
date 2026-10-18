# TRUSTNET Backend
### Privacy-Aware Collaborative Threat Detection Prototype

TRUSTNET is a cybersecurity prototype that compares categories from two bundled organization samples. The current API loads both CSVs centrally. Sanitization removes common identifiers and checks for selected patterns, but does not guarantee complete anonymization or organization-separated processing.

## Features

- Threat detection from organization log data
- Heuristic privacy filtering and sensitive-data redaction
- Cross-organization threat-category comparison
- Threat fingerprint matching
- Optional VirusTotal IP reputation integration
- FastAPI REST API
- Automated testing and error handling

## Technology Stack

- Python
- FastAPI
- Uvicorn
- Requests
- python-dotenv
- VirusTotal API (optional)

## Project Structure

```text
TrustNet/
├── api.py
├── detector.py
├── privacy.py
├── fingerprint.py
├── collaboration.py
├── correlation_readiness.py
├── login_correlation_prototype.py
├── synthetic_login_fixtures.py
├── demo_login_correlation.py
├── virustotal.py
├── test_detector.py
├── test_fingerprint.py
├── test_api_summary.py
├── test_correlation_readiness.py
├── test_login_correlation_prototype.py
├── test_error_handling.py
├── test_virustotal.py
├── trustnet_summary.json
└── sample_data/
    ├── organization_a.csv
    └── organization_b.csv
```

## Tests

Run the complete assertion-based suite from this directory. VirusTotal HTTP calls are mocked:

```bash
python -m unittest discover -v
```

`python test_detector.py` prints a smoke-check summary for the bundled CSV fixtures.

`python demo_login_correlation.py` runs the deterministic synthetic-only repeated-login evaluation. The output contains scenario names, expected/actual statuses, pass/fail, and generic reason codes, never fixture tokens or local aggregation IDs. It does not use the detector, API, or network.

## VirusTotal configuration

Set `VIRUSTOTAL_API_KEY` in `Backend/.env` to configure credentials. Lookups are enabled by default when a key is present; set `VIRUSTOTAL_ENABLED=false` to disable them. When enabled, unique globally routable source-IP indicators are submitted to VirusTotal; full logs are not submitted. The API reports key presence and effective enablement separately and never returns the key. This optional integration is external data sharing and should be explicitly disabled for a no-egress demo.

## Matching and privacy limitations

Production fingerprint matches are category-only: normalized `event_type` values are SHA-256 hashed and shared categories are counted. They do not establish a shared event, attack, or actor. `login_correlation_prototype.py` is separate, synthetic-only code and is not used by the API or detector. The privacy report is a check for common field names and IP/email patterns in sanitized output, not a privacy guarantee. See the root README and `docs/threat-correlation-readiness-v1.md` for deployment blockers and candidate evidence schemas.
