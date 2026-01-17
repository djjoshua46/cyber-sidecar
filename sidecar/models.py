from __future__ import annotations
from datetime import datetime
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Text,
    text,
    Float,
    BigInteger,
    Boolean,
    func,
    ForeignKey,
)
from sqlalchemy.sql import func, text
from sqlalchemy.orm import relationship
from .db import Base
import sqlalchemy  as sa

# Base = declarative_base()


class Event(Base):
    __tablename__ = "Events"

    id = Column("Id", Integer, primary_key=True, autoincrement=True)
    tenant_id = Column("TenantId", String(100), nullable=False)
    user_id = Column("UserId", String(200), nullable=True)
    device_id = Column("DeviceId", String(200), nullable=True)
    session_id = Column("SessionId", String(200), nullable=True)
    source = Column("Source", String(100), nullable=False)
    event_type = Column("EventType", String(100), nullable=False)
    resource = Column("Resource", String(500), nullable=True)
    ip = Column("Ip", String(100), nullable=True)
    geo = Column("Geo", String(200), nullable=True)
    timestamp_utc = Column(
        "TimestampUtc",
        DateTime(timezone=False),
        server_default=func.sysutcdatetime(),
        nullable=False,
    )
    details = Column("Details", Text, nullable=True)
    client_ip = Column("ClientIp", String(64), nullable=True)
    user_agent = Column("UserAgent", String(500), nullable=True)

class Export(Base):
    __tablename__ = "Exports"

    id = Column("Id", Integer, primary_key=True, autoincrement=True)
    export_id = Column("ExportId", String(64), nullable=False, unique=True)
    tenant_id = Column("TenantId", String(100), nullable=False)
    user_id = Column("UserId", String(200), nullable=True)
    session_id = Column("SessionId", String(200), nullable=True)
    resource = Column("Resource", String(500), nullable=True)
    row_count = Column("RowCount", BigInteger, nullable=True)
    byte_size = Column("ByteSize", BigInteger, nullable=True)
    file_hash = Column("FileHash", String(128), nullable=True)
    created_at_utc = Column(
        "CreatedAtUtc",
        DateTime(timezone=False),
        server_default=func.sysutcdatetime(),
        nullable=False,
    )
    ip = Column("Ip", String(64), nullable=True)
    user_agent = Column("UserAgent", String(500), nullable=True)

    is_deception = Column(
        "IsDeception", Boolean, nullable=False, server_default=text("0")
    )
    deception_reason = Column("DeceptionReason", String(200), nullable=True)

class RiskFinding(Base):
    __tablename__ = "RiskFindings"

    id = Column("Id", Integer, primary_key=True, autoincrement=True)
    tenant_id = Column("TenantId", String(100), nullable=False)
    user_id = Column("UserId", String(200), nullable=True)
    session_id = Column("SessionId", String(200), nullable=True)
    export_id = Column("ExportId", String(64), nullable=True)
    resource = Column("Resource", String(500), nullable=True)
    risk_score = Column("RiskScore", Integer, nullable=False)
    risk_level = Column("RiskLevel", String(20), nullable=False)
    reason = Column("Reason", Text, nullable=True)
    finding_type = Column("FindingType", String(20), nullable=False, server_default=text("'export'"))
    correlation_id = Column("CorrelationId", String(128), nullable=True)
    created_at_utc = Column(
        "CreatedAtUtc",
        DateTime(timezone=False),
        server_default=func.sysutcdatetime(),
        nullable=False,
    )

    is_acknowledged = Column(
        "IsAcknowledged",
        Boolean,
        nullable=False,
        server_default="0",
    )
    acknowledged_by = Column("AcknowledgedBy", String(200), nullable=True)
    acknowledged_at_utc = Column("AcknowledgedAtUtc", DateTime(timezone=False), nullable=True)

class KnownUserIp(Base):
    __tablename__ = "KnownUserIps"

    id = Column("Id", Integer, primary_key=True, autoincrement=True)
    tenant_id = Column("TenantId", String(100), nullable=False)
    user_id = Column("UserId", String(200), nullable=False)
    ip = Column("Ip", String(64), nullable=False)

    first_seen_utc = Column("FirstSeenUtc", DateTime(timezone=False), nullable=False)
    last_seen_utc = Column("LastSeenUtc", DateTime(timezone=False), nullable=False)
    seen_count = Column("SeenCount", Integer, nullable=False)

class PolicySettings(Base):
    __tablename__ = "PolicySettings"

    id = Column("Id", Integer, primary_key=True, autoincrement=True)
    tenant_id = Column("TenantId", String(128), nullable=False, index=True)

    # Mode: "monitor", "block_high", "block_all"
    mode = Column("Mode", String(32), nullable=False, server_default=text("'monitor'"))

    # Optional thresholds that override defaults in policy.py
    high_threshold = Column("HighThreshold", Integer, nullable=True)
    medium_threshold = Column("MediumThreshold", Integer, nullable=True)

    created_at_utc = Column(
        "CreatedAtUtc",
        DateTime(timezone=True),
        nullable=False,
        server_default=text("SYSUTCDATETIME()"),
    )

class EphemeralSessionKey(Base):
    __tablename__ = "EphemeralSessionKeys"

    id = Column("Id", Integer, primary_key=True, autoincrement=True)

    tenant_id = Column("TenantId", String(128), nullable=False, index=True)
    session_id = Column("SessionId", String(128), nullable=False, index=True)
    user_id = Column("UserId", String(128), nullable=False, index=True)
    device_id = Column("DeviceId", String(128), nullable=False, index=True)

    user_tone = Column("UserTone", String(128), nullable=False)
    combined_tone = Column("CombinedTone", String(128), nullable=False)

    scope = Column("Scope", String(32), nullable=False, server_default=text("'session'"))

    expires_at = Column("ExpiresAt", DateTime, nullable=False, index=True)
    inserted_at = Column("InsertedAt", DateTime, nullable=False, server_default=func.now())

class UserDriftState(Base):
    __tablename__ = "UserDriftState"

    id = Column("Id", Integer, primary_key=True, autoincrement=True)
    tenant_id = Column("TenantId", String(100), nullable=False)
    user_id = Column("UserId", String(200), nullable=False)

    last_ip = Column("LastIp", String(64), nullable=True)
    last_seen_at = Column(
        "LastSeenAt",
        DateTime(timezone=False),
        server_default=func.sysutcdatetime(),
        nullable=False,
    )

    total_exports = Column(
        "TotalExports", BigInteger, nullable=False, server_default=text("0")
    )
    total_bytes = Column(
        "TotalBytes", BigInteger, nullable=False, server_default=text("0")
    )
    last_row_count = Column("LastRowCount", BigInteger, nullable=True)

    inserted_at = Column(
        "InsertedAt",
        DateTime(timezone=False),
        server_default=func.sysutcdatetime(),
        nullable=False,
    )
    updated_at = Column(
        "UpdatedAt",
        DateTime(timezone=False),
        server_default=func.sysutcdatetime(),
        nullable=False,
    )

class SqlSecurityScanHistory(Base):
    __tablename__ = "SQLSecurityScanHistory"

    Id = Column(Integer, primary_key=True, autoincrement=True)
    CreatedUtc = Column(
        DateTime,
        nullable=False,
        server_default=text("SYSUTCDATETIME()"),
    )

    # Engine / environment
    EngineDriver = Column(String(128), nullable=False)
    EngineHost = Column(String(255), nullable=False)
    EnginePort = Column(Integer, nullable=False)
    EngineDatabase = Column(String(255), nullable=False)

    # Issue counts
    IssueCount = Column(Integer, nullable=False)
    HighCount = Column(Integer, nullable=False)
    MediumCount = Column(Integer, nullable=False)
    LowCount = Column(Integer, nullable=False)

    # JSON payload with detailed issues
    IssuesJson = Column(Text, nullable=False)

    # Attribution (who triggered this scan)
    TriggeredByUserId = Column(String(128), nullable=True)
    TriggeredBySessionId = Column(String(128), nullable=True)
    TriggeredByDeviceId = Column(String(128), nullable=True)

    # Network & geo metadata
    TriggeredFromIp = Column(String(64), nullable=True)
    TriggeredFromCountry = Column(String(64), nullable=True)
    TriggeredFromRegion = Column(String(128), nullable=True)
    TriggeredFromCity = Column(String(128), nullable=True)
    TriggeredFromUrl = Column(Text, nullable=True)

    # Tone / behavioral metadata
    TriggeredTone = Column(String(128), nullable=True)

    # Risk & drift fields (what we added in SQL)
    RiskScore = Column(Float, nullable=True)
    RiskLevel = Column(String(32), nullable=True)  # "low" | "medium" | "high"

    DeceptionUsed = Column(Boolean, nullable=True)
    DeceptionReason = Column(String(256), nullable=True)

    DriftScore = Column(Float, nullable=True)
    BiometricRequired = Column(Boolean, nullable=True)
    ReauthReason = Column(String(256), nullable=True)


class ReplayHttpEvent(Base):
    __tablename__ = "ReplayHttpEvents"

    Id = Column(Integer, primary_key=True, autoincrement=True)

    CreatedUtc = Column(
        DateTime(timezone=True),
        server_default=sa.text("SYSUTCDATETIME()"),
        nullable=False,
    )

    # Identity / correlation
    RequestId = Column(String(64), nullable=False)
    CorrelationId = Column(String(128), nullable=True)

    # HTTP basics
    Method = Column(String(16), nullable=False)
    Path = Column(String(512), nullable=False)
    FullUrl = Column(String(2048), nullable=False)
    QueryString = Column(String(2048), nullable=True)

    # Request body (forensics)
    RequestBodyHash = Column(String(64), nullable=True)
    RequestBodyPreview = Column(String(512), nullable=True)

    # Response
    ResponseStatus = Column(Integer, nullable=True)
    ResponseMs = Column(Integer, nullable=True)

    # Who / what
    UserId = Column(String(128), nullable=True)
    SessionId = Column(String(128), nullable=True)
    DeviceId = Column(String(128), nullable=True)
    OriginIp = Column(String(64), nullable=True)
    ForwardedFor = Column(String(256), nullable=True)
    Country = Column(String(64), nullable=True)
    Region = Column(String(64), nullable=True)
    City = Column(String(64), nullable=True)

    Asn          = Column(String(32), nullable=True)
    AsOrg        = Column(String(128), nullable=True)

    UserAgent          = Column(String(512), nullable=True)
    UserAgentHash      = Column(String(64), nullable=True)
    HeaderFingerprint  = Column(String(64), nullable=True)
    ClientFingerprint  = Column(String(64), nullable=True)

    # Risk engines
    RiskScore = Column(Float, nullable=True)
    RiskLevel = Column(String(32), nullable=True)
    DriftScore = Column(Float, nullable=True)
    DeceptionUsed = Column(Boolean, nullable=True)
    DeceptionReason = Column(String(256), nullable=True)
    ToneHash = Column(String(128), nullable=True)

    # Extra JSON blob
    ExtraJson = Column(Text, nullable=True)


class Exposure(Base):
    __tablename__ = "Exposures"

    Id = Column(Integer, primary_key=True, autoincrement=True)
    Category = Column(String(64), nullable=False)
    Resource = Column(String(256), nullable=False)
    OpenedAt = Column(DateTime, nullable=False)
    OpenedBy = Column(String(128), nullable=True)
    Severity = Column(Integer, nullable=False)
    Notes = Column(Text, nullable=True)
    ClosedAt = Column(DateTime, nullable=True)
    LastSeenAt = Column(DateTime, nullable=False)
    CreatedAt = Column(DateTime, nullable=False, server_default=func.sysutcdatetime())

    Environment = Column(String(32), nullable=True)
    OwnerTeam = Column(String(64), nullable=True)

    Hits = relationship("ExposureHit", back_populates="Exposure")


class ExposureHit(Base):
    __tablename__ = "ExposureHits"

    Id = Column(Integer, primary_key=True, autoincrement=True)
    ExposureId = Column(Integer, ForeignKey("Exposures.Id"), nullable=False)
    EventId = Column(Integer, nullable=True)
    OriginIp = Column(String(64), nullable=False)
    Country = Column(String(32), nullable=True)
    RiskScore = Column(Integer, nullable=True)
    CreatedUtc = Column(DateTime, nullable=False, server_default=func.sysutcdatetime())

    Exposure = relationship("Exposure", back_populates="Hits")


class CommanderTrainingEvents(Base):
    __tablename__ = "CommanderTrainingEvents"

    Id = Column(Integer, primary_key=True, autoincrement=True)
    TenantId = Column(String(64), nullable=False)
    UserId = Column(String(128), nullable=True)
    SurfaceId = Column(Integer, nullable=True)
    WindowMinutes = Column(Integer, nullable=False)

    ExportCount = Column(Integer, nullable=False)
    AvgExportSize = Column(BigInteger, nullable=False)
    GeoAnomalyScore = Column(Integer, nullable=False)
    DeviceChangeScore = Column(Integer, nullable=False)
    DualSessionScore = Column(Integer, nullable=False)
    TimeOfDayScore = Column(Integer, nullable=False)
    PortScanScore = Column(Integer, nullable=False)
    EmailRiskScore = Column(Integer, nullable=False)

    Label = Column(String(16), nullable=True)
    CreatedUtc = Column(DateTime, nullable=False, server_default=func.sysutcdatetime())

class DeviceKey(Base):
    __tablename__ = "DeviceKeys"

    Id = Column(Integer, primary_key=True, autoincrement=True)
    TenantId = Column(String, nullable=False)
    UserId = Column(String, nullable=False)   # or FK if you have users table
    DeviceId = Column(String, nullable=False) # e.g. random UUID
    PublicKeyPem = Column(Text, nullable=False)
    UaHash = Column(String, nullable=True)
    HeaderFingerprint = Column(String, nullable=True)
    DisplayName = Column(String(200), nullable=True)
    CreatedAt = Column(DateTime, default=datetime.utcnow)
    LastSeenAt = Column(DateTime, default=datetime.utcnow)
    Revoked = Column(Boolean, default=False)