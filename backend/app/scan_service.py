import asyncio
import logging
from base64 import b64encode
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import uuid4

from app.core.card_gen import render_warning_card
from app.core.config import MAX_TEXT_LENGTH, Settings
from app.core.redis_cache import RedisCache
from app.core.scan_store import ScanStore, ScanStoreUnavailableError
from app.engines.entity_rules import extract_entities, redact_text
from app.engines.llm_vision import GeminiResult, GeminiVision
from app.engines.ml_engine import MLEngine
from app.engines.threat_intel import ThreatIntel
from app.schemas import (
    AIResult,
    Entities,
    RiskLevel,
    ScanEvent,
    ScanResponse,
    ScamType,
    ScoreAdjustment,
    ScoreBreakdown,
    ThreatResult,
)


logger = logging.getLogger(__name__)
ENTITY_WEIGHTS = {"apk_link": 20, "url_shortener": 10, "urgent_kyc": 10}


class ScanError(Exception):
    def __init__(self, status_code: int, code: str, detail: str, retry_after: int | None = None):
        super().__init__(detail)
        self.status_code = status_code
        self.code = code
        self.detail = detail
        self.retry_after = retry_after


def merge_assessment(
    local_score: int, entities: Entities, intel: list[ThreatResult], ai: AIResult
) -> tuple[ScoreBreakdown, ScamType]:
    score = local_score
    adjustments: list[ScoreAdjustment] = []

    def add(rule: str, points: int) -> None:
        nonlocal score
        delta = min(points, 100 - score)
        if delta > 0:
            adjustments.append(ScoreAdjustment(rule=rule, delta=delta))
            score += delta

    rule_points = sum(ENTITY_WEIGHTS.get(flag, 0) for flag in set(entities.flags))
    add("Message and link rules", min(rule_points, 25))
    if any(item.domain_age_days is not None and item.domain_age_days < 14 for item in intel):
        add("Recently registered domain", 5)

    hits = [item for item in intel if item.status == "hit"]
    if hits:
        add("Threat intelligence match", 85 - score)

    scam_type = ScamType.PHISHING if hits else ScamType.UNKNOWN
    if ai.status == "completed" and ai.confidence is not None and ai.confidence >= 0.70:
        if ai.scam_type not in {ScamType.UNKNOWN, ScamType.NONE}:
            add("AI classification", round(20 * ai.confidence))
            scam_type = ai.scam_type
        elif ai.scam_type == ScamType.NONE and score < 30:
            scam_type = ScamType.NONE
    if scam_type == ScamType.UNKNOWN and "urgent_kyc" in entities.flags:
        scam_type = ScamType.BANK_KYC

    return ScoreBreakdown(
        starting_score=local_score, adjustments=adjustments, final_score=score
    ), scam_type


def public_ai_result(verdict: GeminiResult) -> AIResult:
    return AIResult(
        status=verdict.status,
        scam_type=verdict.scam_type,
        explanation=redact_text(verdict.explanation),
        actions=[redact_text(action) for action in verdict.actions],
        confidence=verdict.confidence,
    )


class ScanService:
    def __init__(
        self,
        settings: Settings,
        ml: MLEngine,
        intel: ThreatIntel,
        ai: GeminiVision,
        cache: RedisCache,
        store: ScanStore,
    ):
        self.settings = settings
        self.ml = ml
        self.intel = intel
        self.ai = ai
        self.cache = cache
        self.store = store

    async def admit(self, identity: str, payload: bytes) -> None:
        if not await self.cache.allow_scan(
            identity,
            limit=self.settings.scan_rate_limit,
            window_seconds=self.settings.scan_rate_window_seconds,
        ):
            raise ScanError(
                429, "rate_limited", "Scan rate limit exceeded.", self.settings.scan_rate_window_seconds
            )
        ttl = self.settings.dedup_seconds
        if ttl and not await self.cache.claim_scan(identity, payload, ttl_seconds=ttl):
            raise ScanError(409, "duplicate_scan", "This input was scanned recently.", ttl)

    async def scan(
        self, text: str = "", *, image: bytes | None = None, mime_type: str | None = None
    ) -> ScanResponse:
        async for event in self.events(text, image=image, mime_type=mime_type):
            if isinstance(event.data, ScanResponse):
                return event.data
        raise RuntimeError("The scan did not produce a verdict.")

    async def events(
        self, text: str = "", *, image: bytes | None = None, mime_type: str | None = None
    ) -> AsyncIterator[ScanEvent]:
        image_verdict = None
        if image is not None:
            if mime_type is None:
                raise ValueError("An image media type is required.")
            image_verdict = await self.ai.classify_image(image, mime_type)
            if image_verdict.status != "completed":
                raise ScanError(503, "image_analysis_unavailable", "Screenshot analysis is unavailable.")
            text = (image_verdict.extracted_text or "")[:MAX_TEXT_LENGTH]

        entities = Entities.model_validate(extract_entities(text, max_urls=self.settings.max_urls))
        yield ScanEvent(event="entity_extraction", data={"url_count": len(entities.urls)})

        ml = await asyncio.to_thread(self.ml.analyze, text, entities.urls)
        local_score = ml["risk_score"]
        yield ScanEvent(event="ml_analysis", data={"risk_score": local_score})

        intel = [ThreatResult.model_validate(item) for item in await self.intel.lookup(entities.urls)]
        hits = [item.provider for item in intel if item.status == "hit"]
        yield ScanEvent(event="threat_intel", data={"checks": len(intel), "hits": len(hits)})

        ai_verdict = image_verdict or await self.ai.classify_text(redact_text(text), sorted(set(hits)))
        ai = public_ai_result(ai_verdict)
        yield ScanEvent(event="ai_verdict", data={"status": ai.status, "scam_type": ai.scam_type})

        breakdown, scam_type = merge_assessment(local_score, entities, intel, ai)
        risk_score = breakdown.final_score
        risk_level = RiskLevel.for_score(risk_score)
        png = await asyncio.to_thread(render_warning_card, risk_score, risk_level, scam_type)
        result = ScanResponse(
            scan_id=uuid4(),
            created_at=datetime.now(UTC),
            risk_score=risk_score,
            risk_level=risk_level,
            scam_type=scam_type,
            entities=entities,
            ml=ml,
            threat_intel=intel,
            ai=ai,
            score_breakdown=breakdown,
            warning_card_png_base64=b64encode(png).decode("ascii") if png else None,
        )
        try:
            await self.store.save(
                scan_id=result.scan_id,
                risk_score=result.risk_score,
                risk_level=result.risk_level,
                scam_type=result.scam_type,
                created_at=result.created_at,
            )
        except ScanStoreUnavailableError:
            logger.warning("Scan metadata storage unavailable.")
        yield ScanEvent(event="complete", data=result)
