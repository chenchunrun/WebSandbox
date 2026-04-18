from __future__ import annotations

from datetime import datetime
import uuid
from sqlalchemy import DateTime, Float, String, JSON, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class AnalysisTask(Base):
    __tablename__ = "analysis_tasks"

    task_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    depth: Mapped[str] = mapped_column(String(16), nullable=False, default="standard")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")

    label: Mapped[str | None] = mapped_column(String(16), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    evidence: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    brand_target: Mapped[str | None] = mapped_column(String(128), nullable=True)

    layers: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    collected: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    metadata_json: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    processing_time_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class FeedbackRecord(Base):
    __tablename__ = "feedback_records"

    feedback_id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    task_id: Mapped[str] = mapped_column(String(64), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    predicted_label: Mapped[str | None] = mapped_column(String(16), nullable=True)
    human_label: Mapped[str] = mapped_column(String(16), nullable=False)
    is_false_positive: Mapped[bool] = mapped_column(nullable=False, default=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewer: Mapped[str | None] = mapped_column(String(128), nullable=True)
    features_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ModelEvent(Base):
    __tablename__ = "model_events"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ok")
    actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prev_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    event_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
