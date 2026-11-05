from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class AccountRow(Base):
    __tablename__ = "cloud_accounts"
    __table_args__ = (UniqueConstraint("provider", "account_id", name="uq_account_provider_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(String(20), index=True)
    account_id: Mapped[str] = mapped_column(String(120), index=True)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    resources: Mapped[list["ResourceRow"]] = relationship(back_populates="account", cascade="all, delete-orphan")


class ResourceRow(Base):
    __tablename__ = "cloud_resources"
    __table_args__ = (UniqueConstraint("account_id", "resource_id", name="uq_resource_account_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("cloud_accounts.id", ondelete="CASCADE"), index=True)
    resource_id: Mapped[str] = mapped_column(String(300), index=True)
    resource_type: Mapped[str] = mapped_column(String(80), index=True)
    region: Mapped[str] = mapped_column(String(40), default="")
    config: Mapped[str] = mapped_column(Text, default="{}")
    tags: Mapped[str] = mapped_column(Text, default="{}")
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    account: Mapped[AccountRow] = relationship(back_populates="resources")
    findings: Mapped[list["FindingRow"]] = relationship(back_populates="resource", cascade="all, delete-orphan")


class FindingRow(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("resource_id", "rule_id", name="uq_finding_resource_rule"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    resource_id: Mapped[int] = mapped_column(ForeignKey("cloud_resources.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(80), index=True)
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(20), index=True)
    status: Mapped[str] = mapped_column(String(20), default="open")
    evidence: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resource: Mapped[ResourceRow] = relationship(back_populates="findings")


class AuditRow(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    actor: Mapped[str] = mapped_column(String(120), default="")
    reference: Mapped[str] = mapped_column(String(120), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
