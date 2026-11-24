from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.core.config import MAX_TEXT_LENGTH


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @classmethod
    def for_score(cls, score: int) -> "RiskLevel":
        if score >= 60:
            return cls.HIGH
        if score >= 30:
            return cls.MEDIUM
        return cls.LOW


class ScamType(StrEnum):
    UNKNOWN = "unknown"
    NONE = "none"
    PHISHING = "phishing"
    BANK_KYC = "bank_kyc"
    UPI_FRAUD = "upi_fraud"
    IMPERSONATION = "impersonation"
    INVESTMENT = "investment"
    JOB = "job"
    DELIVERY = "delivery"
    LOTTERY = "lottery"
    TECH_SUPPORT = "tech_support"
    MALWARE = "malware"
    OTHER = "other"


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    text: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_TEXT_LENGTH)]


class Entities(BaseModel):
    urls: list[str] = Field(default_factory=list)
    phones: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    upi_ids: list[str] = Field(default_factory=list)
    flags: list[str] = Field(default_factory=list)


class ThreatResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    provider: str
    scope: Literal["url", "domain"]
    indicator: str
    status: Literal["hit", "clear", "unavailable", "skipped"]
    domain_age_days: int | None = Field(default=None, ge=0)


class AIResult(BaseModel):
    status: Literal["completed", "unavailable", "skipped"]
    scam_type: ScamType = ScamType.UNKNOWN
    explanation: str = ""
    actions: list[str] = Field(default_factory=list)
    confidence: float | None = Field(default=None, ge=0, le=1)


class ScoreAdjustment(BaseModel):
    rule: str
    delta: int


class ScoreBreakdown(BaseModel):
    starting_score: int = Field(ge=0, le=100)
    adjustments: list[ScoreAdjustment] = Field(default_factory=list)
    final_score: int = Field(ge=0, le=100)


class ScanResponse(BaseModel):
    scan_id: UUID
    created_at: datetime
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    scam_type: ScamType
    entities: Entities
    ml: dict[str, Any]
    threat_intel: list[ThreatResult]
    ai: AIResult
    score_breakdown: ScoreBreakdown
    warning_card_png_base64: str | None = None


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"


class ScanEvent(BaseModel):
    event: Literal[
        "entity_extraction", "ml_analysis", "threat_intel", "ai_verdict", "complete", "error"
    ]
    data: ScanResponse | dict[str, Any]
