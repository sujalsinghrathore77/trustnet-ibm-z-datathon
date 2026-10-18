# TRUSTNET
### Privacy-Aware Collaborative Threat Intelligence Prototype

TRUSTNET is a cybersecurity prototype that demonstrates rule-based alerts and sanitized category comparison using bundled sample logs. It does not implement organization-separated processing or event-level production correlation.

The project combines a Python-based threat analysis backend with a React dashboard to demonstrate a privacy-aware collaborative threat intelligence workflow.

## Key Features

- **Threat Detection:** Identifies suspicious events such as repeated failed logins, flagged destination ports, potential port scanning, and unusually large outbound transfers.
- **Privacy Filtering:** Removes common sensitive identifiers from alert data and checks sanitized outputs for potential IP address and email leaks.
- **Threat Fingerprinting:** Generates SHA-256 fingerprints based on normalized event categories.
- **Cross-Organization Matching:** Compares threat categories identified by two sample organizations.
- **Synthetic Correlation Prototype:** An isolated, synthetic-only repeated-login correlation demonstration; not used by the production detector or API.
- **VirusTotal Integration:** When explicitly enabled with a configured key, submits unique globally routable source-IP indicators for optional VirusTotal reputation lookups; it does not submit complete security logs.
- **REST API:** Exposes backend analysis results through FastAPI.
- **Interactive Dashboard:** Provides screens for threat detection, privacy and sharing, and illustrative threat matches.

## Technology Stack

**Frontend**
- React
- Vite
- JavaScript
- CSS
- Lucide React icons

**Backend**
- Python
- FastAPI
- Uvicorn
- CSV processing
- SHA-256 hashing
- Requests
- python-dotenv
- VirusTotal API (optional)

## Project Structure

```text
TrustNet/
├── Backend/
│   ├── api.py
│   ├── collaboration.py
│   ├── detector.py
│   ├── fingerprint.py
│   ├── privacy.py
│   ├── virustotal.py
│   ├── correlation_readiness.py
│   ├── login_correlation_prototype.py
│   ├── synthetic_login_fixtures.py
│   ├── demo_login_correlation.py
│   ├── test_detector.py
│   ├── test_fingerprint.py
│   ├── test_api_summary.py
│   ├── test_correlation_readiness.py
│   ├── test_login_correlation_prototype.py
│   ├── test_error_handling.py
│   ├── test_virustotal.py
│   ├── trustnet_summary.json
│   └── sample_data/
│       ├── organization_a.csv
│       └── organization_b.csv
├── Frontend/
│   ├── src/
│   ├── public/
│   ├── package.json
│   └── vite.config.js
├── docs/
│   ├── hackathon-demo-runbook.md
│   ├── hackathon-presentation.md
│   ├── hackathon-judge-questions.md
│   ├── synthetic-login-correlation-prototype.md
│   └── threat-correlation-readiness-v1.md
├── .gitignore
└── README.md
```

## Getting Started

### Prerequisites

Install the following before running the project:

- Python 3
- Node.js and npm
- Git (optional, for cloning the repository)

### 1. Set up the backend

Open a terminal in the project directory and run:

```powershell
cd Backend
python -m venv .venv
```

Activate the virtual environment on Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the required Python packages:

```powershell
python -m pip install fastapi "uvicorn[standard]" requests python-dotenv
```

Start the backend API:

```powershell
uvicorn api:app --reload
```

The API will be available at `http://127.0.0.1:8000`.

Interactive API documentation is available at `http://127.0.0.1:8000/docs`.

### 2. Set up the frontend

Open a second terminal in the project directory:

```powershell
cd Frontend
npm install
npm run dev
```

Open the local URL printed by Vite in your terminal, usually `http://localhost:5173`.
The dashboard requests `http://127.0.0.1:8000/api/summary` by default. To use a backend on another local port, set Vite's `VITE_API_BASE_URL` before starting the frontend. For example, in PowerShell:

```powershell
$env:VITE_API_BASE_URL = "http://127.0.0.1:8001"
npm run dev
```

On macOS or Linux, run `VITE_API_BASE_URL=http://127.0.0.1:8001 npm run dev` from `Frontend/`. Vite reads this setting at startup; restart the dev server after changing it. The value is the backend base URL (without `/api/summary`), and the frontend appends that route.

### 3. Optional: Configure VirusTotal

VirusTotal integration requires an API key. If you choose to enable it, create a `.env` file inside `Backend/` containing:

```text
VIRUSTOTAL_API_KEY=your_api_key_here
```

The lookup integration is enabled by default when a key is configured. Set `VIRUSTOTAL_ENABLED=false` in the same `.env` file to explicitly disable requests. The summary reports key presence separately from effective integration enablement; it never returns the key.

Replace the placeholder with your own key. Never commit your `.env` file or publish your API key.

Without a configured key, eligible public-IP indicators are reported as skipped and no VirusTotal request is made. Private/non-public indicators are also skipped.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Basic API status and endpoint information |
| GET | `/api/summary` | Analyze the two sample organizations and return summary results |

## Testing

From the `Backend` directory, run the complete automated backend suite (VirusTotal HTTP calls are mocked and no external requests are made):

```powershell
python -m unittest discover -v
```

To inspect the threat detection results for the sample organizations:

```powershell
python test_detector.py
```

To run the isolated synthetic-only correlation evaluation:

```powershell
python demo_login_correlation.py
```

The demo prints scenario names, expected/actual outcomes, pass/fail and generic reason codes. It does not read production CSVs or call the API or external services. See [`docs/synthetic-login-correlation-prototype.md`](docs/synthetic-login-correlation-prototype.md) for the evaluation matrix and limitations.

## Current Project Status

TRUSTNET is a prototype. The API centrally reads both bundled organization CSVs; it is not an organization-separated deployment. The React dashboard reads summary results from the FastAPI backend. Fingerprint matches indicate shared normalized event categories; they do not independently establish that two organizations experienced the same attack. Privacy filtering checks common identifiers and patterns, but it is not a guarantee of complete anonymization or production-grade security. If VirusTotal is enabled, unique globally routable source-IP indicators may be sent to that external service; raw logs are not submitted.

Fingerprint matches indicate shared event categories; they do not independently establish that two organizations experienced the same attack. Privacy filtering covers common identifiers and patterns, but it is not a guarantee of complete anonymization or production-grade security.

The isolated synthetic repeated-login correlation prototype and its limitations are documented in [`docs/synthetic-login-correlation-prototype.md`](docs/synthetic-login-correlation-prototype.md). It does not change the dashboard or production summary API.

For judge-facing startup, presentation, expected outputs, and recovery steps, see the [hackathon demo runbook](docs/hackathon-demo-runbook.md).

## Future Improvements

- Improve fingerprinting to compare richer threat characteristics.
- Expand privacy validation coverage for outgoing data.
- Add further tests and deployment documentation.

## License

No license has been specified yet. Reuse and redistribution permissions should be defined before the project is distributed publicly.
