from detector import detect_threats

organizations = {
    "Organization A": "sample_data/organization_a.csv",
    "Organization B": "sample_data/organization_b.csv",
}

for organization, file_path in organizations.items():
    alerts = detect_threats(file_path)

    print(f"\n===== {organization} =====")
    print("Total alerts:", len(alerts))

    for alert in alerts:
        print(
            alert["severity"],
            "|",
            alert["event_type"],
            "|",
            ", ".join(alert["reasons"]),
        )