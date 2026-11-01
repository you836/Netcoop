import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    String,
    DateTime,
    Float,
    ForeignKey,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON
from app.core.database import Base


def generate_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Telemetry(Base):
    __tablename__ = "telemetry"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_id,
    )
    incident_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    user_id: Mapped[str] = mapped_column(
        String(36),
        index=True,
        default="noc-operator",
    )
    device_id: Mapped[str] = mapped_column(
        String(120),
        index=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )
    metrics: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )

    incident: Mapped["Incident | None"] = relationship("Incident", back_populates="telemetry_records")


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_id,
    )
    user_id: Mapped[str] = mapped_column(
        String(36),
        index=True,
        default="noc-operator",
    )
    title: Mapped[str] = mapped_column(String(250))
    status: Mapped[str] = mapped_column(
        String(30),
        default="completed",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )

    telemetry_records: Mapped[list["Telemetry"]] = relationship(
        "Telemetry",
        back_populates="incident",
        cascade="all, delete-orphan",
    )
    messages: Mapped[list["AgentMessage"]] = relationship(
        "AgentMessage",
        back_populates="incident",
        cascade="all, delete-orphan",
    )
    report: Mapped["DiagnosticReport | None"] = relationship(
        "DiagnosticReport",
        back_populates="incident",
        uselist=False,
        cascade="all, delete-orphan",
    )


class AgentMessage(Base):
    __tablename__ = "agent_messages"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_id,
    )
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        index=True,
    )
    run_id: Mapped[str] = mapped_column(
        String(36),
        index=True,
        default=generate_id,
    )
    agent_id: Mapped[str] = mapped_column(String(100))
    sender_agent: Mapped[str] = mapped_column(
        String(100),
        default="orchestrator",
    )
    receiver_agent: Mapped[str] = mapped_column(
        String(100),
        default="orchestrator",
    )
    message_type: Mapped[str] = mapped_column(
        String(50),
        default="agent_response",
    )
    schema_version: Mapped[str] = mapped_column(
        String(10),
        default="1.0",
    )
    payload: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )

    incident: Mapped["Incident"] = relationship("Incident", back_populates="messages")


class DiagnosticReport(Base):
    __tablename__ = "diagnostic_reports"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_id,
    )
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        unique=True,
        index=True,
    )
    user_id: Mapped[str] = mapped_column(
        String(36),
        index=True,
        default="noc-operator",
    )
    probable_cause: Mapped[str] = mapped_column(String(250))
    severity: Mapped[str] = mapped_column(String(30))
    confidence: Mapped[float] = mapped_column(Float)
    report: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow,
    )

    incident: Mapped["Incident"] = relationship("Incident", back_populates="report")
