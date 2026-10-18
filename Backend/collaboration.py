import json
import ipaddress
from pathlib import Path

from detector import detect_threats
from privacy import sanitize_alerts, generate_privacy_report
from fingerprint import match_fingerprints
from virustotal import (
    check_ip_reputation,
    is_api_key_configured,
    is_integration_enabled,
    is_integration_requested,
)


BASE_DIR = Path(__file__).resolve().parent
SUMMARY_PATH = BASE_DIR / "trustnet_summary.json"


def enrich_public_indicators(local_alerts):
    """Look up only globally routable public source IPs; skip private/internal IPs."""
    public_ips = set()

    for alert in local_alerts:
        value = alert.get("source_ip")
        if not value:
            continue
        try:
            parsed_ip = ipaddress.ip_address(str(value).strip())
        except ValueError:
            continue
        if parsed_ip.is_global:
            public_ips.add(str(parsed_ip))

    results = []
    for ip in sorted(public_ips):
        # Only the public IP indicator is sent; no alert or raw log is uploaded.
        results.append(check_ip_reputation(ip))
    return results


def run_organization(file_path, organization_name):
    """Detect locally, enrich public indicators, sanitize alerts, and verify privacy."""
    resolved_path = BASE_DIR / file_path
    print(f"\n===== {organization_name} =====")

    local_alerts = detect_threats(str(resolved_path))
    print("Local alerts detected:", len(local_alerts))

    vt_results = enrich_public_indicators(local_alerts)
    print("VirusTotal public-IP lookups:", len(vt_results))
    for result in vt_results:
        print(
            "VirusTotal lookup status:",
            result.get("status", "UNKNOWN"),
            "| malicious detections:",
            result.get("malicious_detections", "N/A"),
        )

    shared_alerts = sanitize_alerts(local_alerts)
    privacy_report = generate_privacy_report(local_alerts, shared_alerts)

    print("Privacy status:", privacy_report["privacy_check"])
    print("Potential leaks:", privacy_report["leak_count"])

    if privacy_report["privacy_check"] != "PASSED" or privacy_report["leak_count"] > 0:
        raise RuntimeError(
            f"Privacy check failed for {organization_name}. Shared alerts will not be used."
        )

    print("Sanitized alerts ready for sharing:", len(shared_alerts))
    return shared_alerts, vt_results


def compare_threat_categories(alerts_a, alerts_b):
    """Compare broad event categories seen by each organization."""
    categories_a = {alert.get("event_type", "unknown") for alert in alerts_a}
    categories_b = {alert.get("event_type", "unknown") for alert in alerts_b}
    common_categories = categories_a & categories_b

    print("\n===== TRUSTNET COLLABORATION RESULTS =====")
    print("Organization A categories:", sorted(categories_a))
    print("Organization B categories:", sorted(categories_b))
    print("\nCategories observed by both organizations:")

    if common_categories:
        for category in sorted(common_categories):
            print("-", category)
    else:
        print("No common threat categories found.")

    return common_categories


def show_fingerprint_matches(alerts_a, alerts_b):
    """Find matches using the normalized fields defined in fingerprint.py."""
    matches = match_fingerprints(alerts_a, alerts_b)

    print("\n===== TRUSTNET FINGERPRINT MATCHING =====")
    print("Matching threat categories:", len(matches))

    if not matches:
        print("No fingerprint matches found.")

    for match in matches:
        print("Event:", match.get("event_type", "unknown"))
        print("Status:", match.get("match_status", "UNKNOWN"))
        fingerprint = match.get("fingerprint", "")
        print("Fingerprint:", fingerprint[:12] + "..." if fingerprint else "Unavailable")

    return matches


def write_summary(common_categories, matches, vt_results):
    """Write a summary based on this run's actual results."""
    lookup_successes = sum(r.get("status") == "SUCCESS" for r in vt_results)
    lookup_errors = sum(r.get("status") == "ERROR" for r in vt_results)
    lookup_skipped = sum(r.get("status") == "SKIPPED" for r in vt_results)
    lookup_attempts = lookup_successes + lookup_errors

    summary = {
        "organizations_connected": 2,
        "privacy_filtering": "ENABLED",
        "common_categories": sorted(common_categories),
        "category_matches": len(matches),
        "fingerprint_matches": len(matches),
        "match_type": "CATEGORY_MATCH",
        "match_description": (
            "Distinct normalized event_type categories shared by both "
            "organizations; not evidence of the same event or attack."
        ),
        "virustotal": {
            "api_key_configured": is_api_key_configured(),
            "integration_requested": is_integration_requested(),
            "integration_enabled": is_integration_enabled(),
            "public_ip_lookups": lookup_attempts,
            "successful_lookups": lookup_successes,
            "skipped_indicators": lookup_skipped,
            "lookup_errors": lookup_errors,
        },
        "status": "SUCCESS",
    }

    SUMMARY_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nSummary JSON saved to: {SUMMARY_PATH}")
    return summary


if __name__ == "__main__":
    org_a_shared, org_a_vt = run_organization(
        "sample_data/organization_a.csv",
        "Organization A",
    )
    org_b_shared, org_b_vt = run_organization(
        "sample_data/organization_b.csv",
        "Organization B",
    )

    common_categories = compare_threat_categories(org_a_shared, org_b_shared)
    matches = show_fingerprint_matches(org_a_shared, org_b_shared)
    summary = write_summary(common_categories, matches, org_a_vt + org_b_vt)

    print("\n===== TRUSTNET SUMMARY =====")
    print("Organizations connected:", summary["organizations_connected"])
    print("Privacy filtering:", summary["privacy_filtering"].title())
    print("Common categories found:", len(summary["common_categories"]))
    print("Fingerprint matches:", summary["fingerprint_matches"])
    print("VirusTotal public-IP lookups:", summary["virustotal"]["public_ip_lookups"])
    print("Collaboration completed successfully!")
    print(
        "\nNote: Fingerprint matches reflect normalized alert attributes; "
        "they do not prove the same real-world attack occurred. VirusTotal lookups "
        "are performed only for globally routable public source IPs."
    )
