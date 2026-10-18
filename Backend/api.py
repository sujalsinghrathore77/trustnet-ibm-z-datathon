from pathlib import Path
import ipaddress

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from detector import detect_threats
from privacy import sanitize_alerts, generate_privacy_report
from fingerprint import match_fingerprints
from virustotal import (
    check_ip_reputation,
    is_api_key_configured,
    is_integration_enabled,
    is_integration_requested,
)

app = FastAPI(
    title="TRUSTNET API",
    description="Privacy-preserving collaborative threat detection",
    version="1.0.0",
)

# Allow the local React + Vite dashboard to connect.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "sample_data"


def analyze_organization(filename: str):
    """Detect local threats, sanitize alerts, and validate shared output."""
    file_path = DATA_DIR / filename

    if not file_path.is_file():
        raise FileNotFoundError(f"Sample data file not found: {filename}")

    local_alerts = detect_threats(str(file_path))
    shared_alerts = sanitize_alerts(local_alerts)

    privacy_report = generate_privacy_report(
        local_alerts,
        shared_alerts,
    )

    if (
        privacy_report.get("privacy_check") != "PASSED"
        or privacy_report.get("leak_count", 0) != 0
    ):
        raise RuntimeError(
            f"Privacy validation failed for {filename}"
        )

    return local_alerts, shared_alerts, privacy_report


def lookup_public_ips(alert_groups):
    """
    Look up unique public source-IP indicators only.
    Raw logs and complete alerts are never sent to VirusTotal.
    """
    results = []
    checked_ips = set()
    seen_non_public = set()
    skipped_non_public = 0
    invalid_indicators = 0
    skipped_missing_key = 0
    skipped_disabled = 0
    lookup_attempts = 0
    integration_requested = is_integration_requested()
    api_key_configured = is_api_key_configured()
    integration_enabled = is_integration_enabled()

    for alerts in alert_groups:
        for alert in alerts:
            if not isinstance(alert, dict):
                invalid_indicators += 1
                continue

            raw_ip = alert.get("source_ip")

            if raw_ip is None:
                continue

            if not isinstance(raw_ip, str):
                invalid_indicators += 1
                continue

            try:
                parsed_ip = ipaddress.ip_address(raw_ip.strip())
            except ValueError:
                invalid_indicators += 1
                continue

            normalized_ip = str(parsed_ip)

            if not parsed_ip.is_global:
                if normalized_ip not in seen_non_public:
                    seen_non_public.add(normalized_ip)
                    skipped_non_public += 1
                continue

            if normalized_ip in checked_ips:
                continue

            checked_ips.add(normalized_ip)

            if not integration_enabled:
                if not integration_requested:
                    skipped_disabled += 1
                    message = "VirusTotal integration is disabled."
                else:
                    skipped_missing_key += 1
                    message = "VirusTotal API key is not configured."
                results.append({
                    "status": "SKIPPED",
                    "ip_address": normalized_ip,
                    "message": message,
                })
                continue

            try:
                lookup_attempts += 1
                result = check_ip_reputation(normalized_ip)

                # Ensure the result is JSON-serializable and identifies
                # the indicator being checked.
                if not isinstance(result, dict):
                    result = {
                        "status": "ERROR",
                        "ip_address": normalized_ip,
                        "message": "Unexpected VirusTotal response format",
                    }
                else:
                    result.setdefault("ip_address", normalized_ip)
                    result.setdefault("status", "UNKNOWN")

                results.append(result)

            except Exception:
                # Avoid exposing API keys, response bodies, or other
                # potentially sensitive details in error responses.
                results.append({
                    "status": "ERROR",
                    "ip_address": normalized_ip,
                    "message": "VirusTotal lookup failed",
                })

    return {
        "results": results,
        "public_ip_indicators": len(checked_ips),
        "public_ip_lookups": lookup_attempts,
        "successful_lookups": sum(
            1 for item in results
            if item.get("status") == "SUCCESS"
        ),
        "lookup_errors": sum(
            1 for item in results
            if item.get("status") == "ERROR"
        ),
        "skipped_non_public_indicators": skipped_non_public,
        "skipped_missing_key_indicators": skipped_missing_key,
        "skipped_disabled_indicators": skipped_disabled,
        "invalid_indicators": invalid_indicators,
        "api_key_configured": api_key_configured,
        "integration_requested": integration_requested,
        "integration_enabled": integration_enabled,
    }


@app.get("/")
def home():
    return {
        "project": "TRUSTNET",
        "status": "running",
        "docs": "/docs",
        "summary_endpoint": "/api/summary",
    }


@app.get("/api/summary")
def get_summary():
    try:
        local_a, alerts_a, privacy_a = analyze_organization(
            "organization_a.csv"
        )
        local_b, alerts_b, privacy_b = analyze_organization(
            "organization_b.csv"
        )

        categories_a = {
            alert.get("event_type")
            for alert in alerts_a
            if alert.get("event_type")
        }
        categories_b = {
            alert.get("event_type")
            for alert in alerts_b
            if alert.get("event_type")
        }

        common_categories = sorted(categories_a & categories_b)
        matches = match_fingerprints(alerts_a, alerts_b)

        # Privacy validation has passed before external indicator lookups.
        # Only individual globally routable source-IP indicators are sent;
        # raw alerts and log records are not sent to VirusTotal.
        vt = lookup_public_ips([local_a, local_b])

        return {
            "project": "TRUSTNET",
            "status": "SUCCESS",
            "organizations_connected": 2,
            "organizations": [
                {
                    "name": "Organization A",
                    "alert_count": len(alerts_a),
                    "privacy_check": privacy_a.get("privacy_check"),
                    "leak_count": privacy_a.get("leak_count", 0),
                },
                {
                    "name": "Organization B",
                    "alert_count": len(alerts_b),
                    "privacy_check": privacy_b.get("privacy_check"),
                    "leak_count": privacy_b.get("leak_count", 0),
                },
            ],
            "total_alerts": len(alerts_a) + len(alerts_b),
            "common_categories": common_categories,
            # Keep the existing key for clients; its value is explicitly
            # documented as a legacy alias for category-level matches.
            "category_matches": len(matches),
            "fingerprint_matches": len(matches),
            "match_type": "CATEGORY_MATCH",
            "match_description": (
                "Distinct normalized event_type categories present in both "
                "organizations. This is a category-level match, not evidence "
                "that the same event or attack occurred."
            ),
            "virustotal": {
                "api_key_configured": vt["api_key_configured"],
                "integration_requested": vt["integration_requested"],
                "integration_enabled": vt["integration_enabled"],
                "public_ip_indicators": vt["public_ip_indicators"],
                "public_ip_lookups": vt["public_ip_lookups"],
                "successful_lookups": vt["successful_lookups"],
                "lookup_errors": vt["lookup_errors"],
                "skipped_non_public_indicators": vt[
                    "skipped_non_public_indicators"
                ],
                "skipped_missing_key_indicators": vt[
                    "skipped_missing_key_indicators"
                ],
                "skipped_disabled_indicators": vt[
                    "skipped_disabled_indicators"
                ],
                "invalid_indicators": vt["invalid_indicators"],
                "results": vt["results"],
            },
            "note": (
                "Category matches indicate event_type values shared by both "
                "organizations, not proof of the same attack. VirusTotal checks only "
                "unique public source-IP indicators; raw logs are not sent."
            ),
        }

    except (FileNotFoundError, RuntimeError) as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        # Full details stay in the server terminal; do not leak internals
        # to the API caller.
        print(f"TRUSTNET API error: {type(exc).__name__}: {exc}")
        raise HTTPException(
            status_code=500,
            detail="Backend analysis failed. Check the VS Code terminal.",
        ) from exc
