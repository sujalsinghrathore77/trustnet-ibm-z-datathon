import hashlib
import json


def normalize_event_type(alert):
    """Return a normalized category, or None when the alert is unusable."""
    if not isinstance(alert, dict):
        return None

    event_type = alert.get("event_type")
    if not isinstance(event_type, str):
        return None

    normalized = event_type.strip().lower()
    return normalized or None


def generate_fingerprint(alert):
    """
    Generate a normalized fingerprint based on the threat category.
    Ignores IP addresses, timestamps, and differences in alert wording.
    """
    event_type = normalize_event_type(alert)
    if event_type is None:
        return None

    # Normalize the threat category
    normalized_alert = {
        "event_type": event_type
    }

    canonical_data = json.dumps(
        normalized_alert,
        sort_keys=True,
        separators=(",", ":")
    )

    return hashlib.sha256(
        canonical_data.encode("utf-8")
    ).hexdigest()


def match_fingerprints(alerts_a, alerts_b):
    """Return distinct normalized event categories shared by both inputs.

    Invalid alerts and alerts without a non-empty string ``event_type`` are
    ignored. A match is category-level only; it is not an event-level match.
    """

    def fingerprints_by_category(alerts):
        try:
            iterator = iter(alerts)
        except TypeError:
            return {}

        fingerprints = {}
        for alert in iterator:
            event_type = normalize_event_type(alert)
            if event_type is None:
                continue
            fingerprint = generate_fingerprint(alert)
            fingerprints[fingerprint] = event_type
        return fingerprints

    fingerprints_a = fingerprints_by_category(alerts_a)
    fingerprints_b = fingerprints_by_category(alerts_b)

    common_fingerprints = fingerprints_a.keys() & fingerprints_b.keys()

    matches = []

    for fingerprint in sorted(common_fingerprints):
        matches.append({
            "fingerprint": fingerprint,
            "event_type": fingerprints_a[fingerprint],
            "match_status": "CATEGORY_MATCH"
        })

    return matches


if __name__ == "__main__":
    sample_a = [
        {"event_type": "outbound", "reasons": ["Large transfer detected"]},
        {"event_type": "port_scan", "reasons": ["Many ports accessed"]}
    ]

    sample_b = [
        {"event_type": "outbound", "reasons": ["Unusual outbound traffic"]},
        {"event_type": "port_scan", "reasons": ["Suspicious port activity"]}
    ]

    matches = match_fingerprints(sample_a, sample_b)

    print("\n===== TRUSTNET FINGERPRINTING =====")
    print("Matching threat categories:", len(matches))

    for match in matches:
        print("Event:", match["event_type"])
        print("Status:", match["match_status"])
        print("Fingerprint:", match["fingerprint"][:12] + "...")
