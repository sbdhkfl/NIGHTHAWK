"""Database models for investigations, targets, findings, sources and notes."""

from __future__ import annotations

import datetime as _dt

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


class Investigation(Base):
    """A saved investigation containing targets, findings and notes."""

    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )

    targets: Mapped[list[Target]] = relationship(
        "Target", back_populates="investigation", cascade="all, delete-orphan"
    )
    sources: Mapped[list[Source]] = relationship(
        "Source", back_populates="investigation", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        "Finding", back_populates="investigation", cascade="all, delete-orphan"
    )
    notes: Mapped[list[Note]] = relationship(
        "Note", back_populates="investigation", cascade="all, delete-orphan"
    )
    activity_logs: Mapped[list[ActivityLog]] = relationship(
        "ActivityLog", back_populates="investigation", cascade="all, delete-orphan"
    )


class Target(Base):
    """An investigation target (username, domain, IP, email, ...)."""

    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)  # username, domain, ip, email, image
    value: Mapped[str] = mapped_column(String(1000), nullable=False)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    investigation: Mapped[Investigation] = relationship("Investigation", back_populates="targets")
    findings: Mapped[list[Finding]] = relationship(
        "Finding", back_populates="target", cascade="all, delete-orphan"
    )


class Finding(Base):
    """A single collected result from an intelligence module."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    module: Mapped[str] = mapped_column(String(100), nullable=False)
    target: Mapped[str] = mapped_column(String(1000), nullable=False)
    result_data: Mapped[str] = mapped_column(Text, nullable=False)  # JSON string
    source: Mapped[str | None] = mapped_column(String(500), nullable=True)
    confidence: Mapped[str | None] = mapped_column(String(50), nullable=True)
    collected_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    investigation: Mapped[Investigation] = relationship("Investigation", back_populates="findings")
    target: Mapped[Target] = relationship("Target", back_populates="findings")


class Source(Base):
    """A referenced source URL."""

    __tablename__ = "sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    investigation: Mapped[Investigation] = relationship("Investigation", back_populates="sources")
    url: Mapped[str] = mapped_column(String(2000), nullable=False)
    module: Mapped[str | None] = mapped_column(String(100), nullable=True)
    recorded_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class Note(Base):
    """A free-text note attached to an investigation."""

    __tablename__ = "notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    investigation: Mapped[Investigation] = relationship("Investigation", back_populates="notes")


class ActivityLog(Base):
    """Append-only activity log for an investigation."""

    __tablename__ = "activity_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action: Mapped[str] = mapped_column(String(200), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[_dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    investigation: Mapped[Investigation] = relationship("Investigation", back_populates="activity_logs")
