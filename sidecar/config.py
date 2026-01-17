import os

# Change this to match your SQL Server instance / driver / login.
DEFAULT_DB_URL = (
    "mssql+pyodbc://CyberSidecarLogin:05$$jAF18"
    "@localhost/CyberSidecar"
    "?driver=ODBC+Driver+17+for+SQL+Server"
)

DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DB_URL)

TENANT_ID = os.getenv("TENANT_ID", "demo-tenant")
