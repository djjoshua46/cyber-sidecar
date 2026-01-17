import random
from typing import List, Dict

import pandas as pd

from db import engine as ENGINE          # when run as: python generate_commander_synthetic.py

# ---------- FEATURE HELPERS ----------

def _clip01(x: float) -> float:
    return max(0.0, min(1.0, x))


# ---------- SCENARIO SAMPLERS ----------

def sample_benign() -> Dict:
    """Calm, normal behavior window."""
    export_count = random.randint(0, 20)
    avg_export = random.randint(0, 50_000)  # bytes, small exports
    port_scan = random.randint(0, 3)
    dual_session = 0 if random.random() < 0.9 else 10
    tod = 0  # normal hours
    email_risk = 0

    distinct_countries = random.choice([1, 1, 1, 2])  # mostly 1, sometimes 2
    new_country_seen = 0
    high_risk_country = 0

    failed_login_count = random.randint(0, 3)
    total_logins = failed_login_count + random.randint(3, 20)
    failed_ratio = failed_login_count / total_logins if total_logins > 0 else 0.0
    concurrent_sessions = random.randint(1, 3)
    impersonation_score = random.randint(0, 2)

    critical_port_scan = random.randint(0, 2)
    exposed_critical_surfaces = random.randint(0, 1)
    new_service_exposed = 0

    distinct_tables = random.randint(1, 5)
    sensitive_reads = random.randint(0, 1)
    bulk_exports = 0

    malicious_emails = 0
    clicked_bad_links = 0
    attachment_score = 0

    return {
        "TenantId": "default",
        "UserId": None,
        "SurfaceId": None,
        "WindowMinutes": 15,

        "ExportCount": export_count,
        "AvgExportSize": avg_export,
        "GeoAnomalyScore": random.randint(0, 2),
        "DeviceChangeScore": random.randint(0, 2),
        "DualSessionScore": dual_session,
        "TimeOfDayScore": tod,
        "PortScanScore": port_scan,
        "EmailRiskScore": email_risk,

        "DistinctCountryCount": distinct_countries,
        "NewCountrySeen": new_country_seen,
        "HighRiskCountryFlag": high_risk_country,

        "FailedLoginCount": failed_login_count,
        "FailedLoginRatio": failed_ratio,
        "ConcurrentSessions": concurrent_sessions,
        "ImpersonationScore": impersonation_score,

        "CriticalPortScanScore": critical_port_scan,
        "ExposedCriticalSurfaceCount": exposed_critical_surfaces,
        "NewServiceExposed": new_service_exposed,

        "DistinctTablesTouched": distinct_tables,
        "SensitiveTableReads": sensitive_reads,
        "BulkExportEvents": bulk_exports,

        "MaliciousEmailCount": malicious_emails,
        "ClickedMaliciousLinks": clicked_bad_links,
        "AttachmentSandboxScore": attachment_score,

        "Label": "benign",
    }


def sample_watch() -> Dict:
    """Something feels off but not confirmed-breach."""
    export_count = random.randint(20, 80)
    avg_export = random.randint(50_000, 500_000)
    port_scan = random.randint(3, 8)
    dual_session = 10 if random.random() < 0.6 else 0
    tod = random.choice([0, 10])  # sometimes weird hours
    email_risk = random.choice([0, 5])

    distinct_countries = random.choice([1, 2, 3])
    new_country_seen = 1 if random.random() < 0.4 else 0
    high_risk_country = 1 if random.random() < 0.3 else 0

    failed_login_count = random.randint(3, 15)
    total_logins = failed_login_count + random.randint(5, 20)
    failed_ratio = failed_login_count / total_logins if total_logins > 0 else 0.0
    concurrent_sessions = random.randint(2, 6)
    impersonation_score = random.randint(2, 6)

    critical_port_scan = random.randint(3, 10)
    exposed_critical_surfaces = random.randint(1, 3)
    new_service_exposed = 1 if random.random() < 0.3 else 0

    distinct_tables = random.randint(3, 15)
    sensitive_reads = random.randint(1, 5)
    bulk_exports = random.randint(0, 2)

    malicious_emails = random.randint(0, 3)
    clicked_bad_links = random.randint(0, 2)
    attachment_score = random.randint(0, 5)

    return {
        "TenantId": "default",
        "UserId": None,
        "SurfaceId": None,
        "WindowMinutes": 15,

        "ExportCount": export_count,
        "AvgExportSize": avg_export,
        "GeoAnomalyScore": random.randint(2, 6),
        "DeviceChangeScore": random.randint(2, 6),
        "DualSessionScore": dual_session,
        "TimeOfDayScore": tod,
        "PortScanScore": port_scan,
        "EmailRiskScore": email_risk,

        "DistinctCountryCount": distinct_countries,
        "NewCountrySeen": new_country_seen,
        "HighRiskCountryFlag": high_risk_country,

        "FailedLoginCount": failed_login_count,
        "FailedLoginRatio": failed_ratio,
        "ConcurrentSessions": concurrent_sessions,
        "ImpersonationScore": impersonation_score,

        "CriticalPortScanScore": critical_port_scan,
        "ExposedCriticalSurfaceCount": exposed_critical_surfaces,
        "NewServiceExposed": new_service_exposed,

        "DistinctTablesTouched": distinct_tables,
        "SensitiveTableReads": sensitive_reads,
        "BulkExportEvents": bulk_exports,

        "MaliciousEmailCount": malicious_emails,
        "ClickedMaliciousLinks": clicked_bad_links,
        "AttachmentSandboxScore": attachment_score,

        "Label": "watch",
    }


def sample_lockdown() -> Dict:
    """Shit hits the fan: clear attack / exfil pattern."""
    export_count = random.randint(80, 400)
    avg_export = random.randint(500_000, 10_000_000)
    port_scan = random.randint(8, 20)
    dual_session = 10
    tod = random.choice([0, 10])  # off hours common
    email_risk = random.choice([5, 10])

    distinct_countries = random.choice([2, 3, 4])
    new_country_seen = 1
    high_risk_country = 1

    failed_login_count = random.randint(10, 40)
    total_logins = failed_login_count + random.randint(5, 30)
    failed_ratio = failed_login_count / total_logins if total_logins > 0 else 0.0
    concurrent_sessions = random.randint(3, 10)
    impersonation_score = random.randint(5, 10)

    critical_port_scan = random.randint(10, 30)
    exposed_critical_surfaces = random.randint(2, 8)
    new_service_exposed = 1

    distinct_tables = random.randint(10, 40)
    sensitive_reads = random.randint(5, 30)
    bulk_exports = random.randint(1, 10)

    malicious_emails = random.randint(1, 10)
    clicked_bad_links = random.randint(1, 5)
    attachment_score = random.randint(5, 10)

    return {
        "TenantId": "default",
        "UserId": None,
        "SurfaceId": None,
        "WindowMinutes": 15,

        "ExportCount": export_count,
        "AvgExportSize": avg_export,
        "GeoAnomalyScore": random.randint(6, 15),
        "DeviceChangeScore": random.randint(6, 15),
        "DualSessionScore": dual_session,
        "TimeOfDayScore": tod,
        "PortScanScore": port_scan,
        "EmailRiskScore": email_risk,

        "DistinctCountryCount": distinct_countries,
        "NewCountrySeen": new_country_seen,
        "HighRiskCountryFlag": high_risk_country,

        "FailedLoginCount": failed_login_count,
        "FailedLoginRatio": failed_ratio,
        "ConcurrentSessions": concurrent_sessions,
        "ImpersonationScore": impersonation_score,

        "CriticalPortScanScore": critical_port_scan,
        "ExposedCriticalSurfaceCount": exposed_critical_surfaces,
        "NewServiceExposed": new_service_exposed,

        "DistinctTablesTouched": distinct_tables,
        "SensitiveTableReads": sensitive_reads,
        "BulkExportEvents": bulk_exports,

        "MaliciousEmailCount": malicious_emails,
        "ClickedMaliciousLinks": clicked_bad_links,
        "AttachmentSandboxScore": attachment_score,

        "Label": "lockdown",
    }


# ---------- MAIN DRIVER ----------

def main():
    # crank this up if you want “bigger brain” training
    total_rows = 300_000

    labels = ["benign", "watch", "lockdown"]
    weights = [0.7, 0.2, 0.1]

    rows: List[Dict] = []

    for _ in range(total_rows):
        scenario = random.choices(labels, weights=weights, k=1)[0]
        if scenario == "benign":
            rows.append(sample_benign())
        elif scenario == "watch":
            rows.append(sample_watch())
        else:
            rows.append(sample_lockdown())

    df = pd.DataFrame(rows)

    print("Sample of generated data:")
    print(df.head())

    df.to_sql(
        "CommanderTrainingEvents",
        ENGINE,
        schema="dbo",
        if_exists="append",
        index=False,
    )

    print(f"Inserted {len(df)} synthetic rows into dbo.CommanderTrainingEvents")


if __name__ == "__main__":
    main()
