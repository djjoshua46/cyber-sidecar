import joblib
import pandas as pd

# ✅ Use your real engine from sidecar/db.py instead of a fake connection string
from sidecar.db import engine as ENGINE


def load_training_data():
    # We pull ALL the feature columns we care about plus Label.
    # DistinctCountryCount filter ensures we only use "rich" rows (new synthetic ones).
    query = """
        SELECT
          ExportCount,
          AvgExportSize,
          GeoAnomalyScore,
          DeviceChangeScore,
          DualSessionScore,
          TimeOfDayScore,
          PortScanScore,
          EmailRiskScore,

          DistinctCountryCount,
          NewCountrySeen,
          HighRiskCountryFlag,

          FailedLoginCount,
          FailedLoginRatio,
          ConcurrentSessions,
          ImpersonationScore,

          CriticalPortScanScore,
          ExposedCriticalSurfaceCount,
          NewServiceExposed,

          DistinctTablesTouched,
          SensitiveTableReads,
          BulkExportEvents,

          MaliciousEmailCount,
          ClickedMaliciousLinks,
          AttachmentSandboxScore,

          Label
        FROM dbo.CommanderTrainingEvents
        WHERE Label IS NOT NULL
          AND DistinctCountryCount IS NOT NULL;  -- filters out old rows without new fields
    """
    return pd.read_sql(query, ENGINE)


def main():
    from sklearn.ensemble import RandomForestClassifier

    df = load_training_data()
    if df.empty:
        print("No labeled rows with rich features in CommanderTrainingEvents yet.")
        return

    # ✅ Features = all columns except Label
    X = df.drop(columns=["Label"])
    y = df["Label"]

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=20,
        class_weight="balanced",
        random_state=42,
    )

    model.fit(X, y)

    joblib.dump(model, r"C:\Cybersecurity\cyber-sidecar\sidecar\commander_model.pkl")
    print("Commander model trained and saved on rich feature set.")


if __name__ == "__main__":
    main()
