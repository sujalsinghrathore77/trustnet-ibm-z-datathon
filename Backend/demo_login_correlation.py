"""Deterministic text demo for synthetic-only login correlation."""

from copy import deepcopy

from login_correlation_prototype import correlate_repeated_failed_logins
from synthetic_login_fixtures import (
    SYNTHETIC_INDICATOR_B,
    organization_a_records,
    organization_b_records,
)


def _scenarios():
    """Build named cases without exposing their evidence in returned results."""
    a_records = organization_a_records()
    b_records = organization_b_records()
    a_positive = a_records[0]
    b_positive = b_records[0]

    different_indicator = dict(b_positive)
    different_indicator["protected_indicator_token"] = SYNTHETIC_INDICATOR_B

    low_count = dict(b_positive)
    low_count["failed_login_count"] = 4
    at_minimum_count_a = dict(a_positive)
    at_minimum_count_a["failed_login_count"] = 5
    at_minimum_count_b = dict(b_positive)
    at_minimum_count_b["failed_login_count"] = 5

    excessive_skew = dict(b_positive)
    excessive_skew["window_start_utc"] = "2026-10-18T10:05:01Z"
    excessive_skew["window_end_utc"] = "2026-10-18T10:20:01Z"

    missing_field = dict(b_positive)
    del missing_field["protected_indicator_token"]

    invalid_field = dict(b_positive)
    invalid_field["failed_login_count"] = "seven"

    conflicting_duplicate = dict(a_positive)
    conflicting_duplicate["failed_login_count"] += 1

    return [
        {
            "name": "compatible_indicator_and_overlapping_windows",
            "expected": "correlated",
            "a": [a_positive],
            "b": [b_positive],
        },
        {
            "name": "different_indicators",
            "expected": "not_correlated",
            "a": [a_positive],
            "b": [different_indicator],
        },
        {
            "name": "same_indicator_non_overlapping_windows",
            "expected": "not_correlated",
            "a": [a_positive],
            "b": [b_records[1]],
        },
        {
            "name": "below_minimum_failed_login_count",
            "expected": "not_correlated",
            "a": [a_positive],
            "b": [low_count],
        },
        {
            "name": "count_at_minimum_threshold",
            "expected": "correlated",
            "a": [at_minimum_count_a],
            "b": [at_minimum_count_b],
        },
        {
            "name": "start_skew_at_allowed_boundary",
            "expected": "correlated",
            "a": [a_positive],
            "b": [b_positive],
        },
        {
            "name": "start_skew_above_allowed_boundary",
            "expected": "not_correlated",
            "a": [a_positive],
            "b": [excessive_skew],
        },
        {
            "name": "exact_duplicate_evidence",
            "expected": "correlated",
            "a": [a_positive, dict(a_positive)],
            "b": [b_positive],
        },
        {
            "name": "conflicting_duplicate_identifier",
            "expected": "insufficient_evidence",
            "a": [a_positive, conflicting_duplicate],
            "b": [b_positive],
        },
        {
            "name": "missing_required_field",
            "expected": "insufficient_evidence",
            "a": [a_positive],
            "b": [missing_field],
        },
        {
            "name": "invalid_field_type",
            "expected": "insufficient_evidence",
            "a": [a_positive],
            "b": [invalid_field],
        },
        {
            "name": "repeated_execution_is_deterministic",
            "expected": "correlated",
            "a": [a_positive],
            "b": [b_positive],
            "repeat": True,
        },
    ]


def run_demo():
    """Return only safe scenario labels, outcomes, and existing reason codes."""
    results = []
    for scenario in _scenarios():
        first = correlate_repeated_failed_logins(
            deepcopy(scenario["a"]), deepcopy(scenario["b"])
        )
        actual = first["status"]
        deterministic = True
        if scenario.get("repeat"):
            second = correlate_repeated_failed_logins(
                deepcopy(scenario["a"]), deepcopy(scenario["b"])
            )
            deterministic = first == second

        results.append({
            "scenario": scenario["name"],
            "expected_outcome": scenario["expected"],
            "actual_outcome": actual,
            "passed": actual == scenario["expected"] and deterministic,
            "reason_codes": first["reason_codes"],
        })
    return results


def format_demo_output(results):
    """Render no evidence values, only scenario names and safe summary fields."""
    lines = [
        "TRUSTNET synthetic-only repeated-login correlation demo",
        "Outcomes describe configured synthetic rules only; no real telemetry.",
    ]
    for result in results:
        verdict = "PASS" if result["passed"] else "FAIL"
        reasons = ",".join(result["reason_codes"]) or "none"
        lines.append(
            "Scenario: {scenario} | expected: {expected} | actual: {actual} | "
            "{verdict} | reasons: {reasons}".format(
                scenario=result["scenario"],
                expected=result["expected_outcome"],
                actual=result["actual_outcome"],
                verdict=verdict,
                reasons=reasons,
            )
        )
    return "\n".join(lines)


def main():
    print(format_demo_output(run_demo()))


if __name__ == "__main__":
    main()
