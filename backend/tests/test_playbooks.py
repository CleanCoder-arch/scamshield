import pytest

from app.engines.ml_engine import MLEngine
from app.engines.playbooks import (
    CURATED_CATEGORY_LABELS,
    CURATED_INDICATORS,
    CURATED_REPORTING_STEPS,
    CURATED_STEPS,
    build_guidance,
    local_scam_hint,
)


@pytest.mark.parametrize(("scam_type", "risk_level", "category", "advice"), [
    ("bank_kyc", "HIGH", "bank_kyc", "bank's official app"),
    ("upi_fraud", "HIGH", "upi_fraud", "UPI PIN"),
    ("digital_arrest", "MEDIUM", "digital_arrest", "do not arrest people over video calls"),
    ("fake_job", "HIGH", "fake_job", "official careers site"),
    ("job", "HIGH", "fake_job", "official careers site"),
    ("phishing", "MEDIUM", "suspicious_url", "official site or app"),
    ("investment", "MEDIUM", "investment", "Pause before replying"),
    ("unknown", "LOW", "low_risk", "Check the sender"),
    ("unknown", "HIGH", "generic", "Pause before replying"),
])
def test_guidance_categories_use_curated_indian_safety_steps(scam_type, risk_level, category, advice):
    guidance = build_guidance(scam_type=scam_type, risk_level=risk_level)
    assert guidance.category_id == category
    assert guidance.category_label == CURATED_CATEGORY_LABELS[category]
    assert any(advice in step for step in guidance.steps)
    assert set(guidance.steps) <= CURATED_STEPS
    assert set(guidance.reporting_steps) == CURATED_REPORTING_STEPS
    assert any("1930" in step and "first hour" in step and "lost money" in step for step in guidance.reporting_steps)
    assert any("cybercrime.gov.in" in step and "acknowledgement" in step for step in guidance.reporting_steps)
    assert any("private" in step for step in guidance.reporting_steps)


@pytest.fixture(scope="module")
def ml_engine():
    return MLEngine()


@pytest.mark.parametrize(("message", "expected"), [
    (
        "Your ₹2,499 refund is ready. Approve the pending UPI collect request from "
        "demo-refund@sampleupi and enter your UPI PIN to receive the money.",
        "upi_fraud",
    ),
    (
        "Congratulations! You were selected for a remote data entry job paying ₹5,000 per day. "
        "Pay a ₹999 registration fee today to confirm your position.",
        "fake_job",
    ),
    (
        "You are now under digital arrest. Stay on the video call and transfer funds to a safe account.",
        "digital_arrest",
    ),
])
def test_local_guidance_identifies_scam_without_gemini(ml_engine, message, expected):
    result = ml_engine.analyze(message, [])
    hint = local_scam_hint(message, result)
    guidance = build_guidance(
        scam_type="unknown", risk_level=result["risk_level"], ml=result, local_hint=hint,
    )
    assert hint == guidance.category_id == expected
    assert guidance.indicators
    assert set(guidance.indicators) <= CURATED_INDICATORS


@pytest.mark.parametrize("message", [
    "If someone says 'you are under digital arrest', end the call.",
    "People who say 'you are under digital arrest' are trying to scam you.",
    "Learn about digital arrest fraud and how to report it.",
])
def test_digital_arrest_guidance_ignores_safety_advice(message):
    assert local_scam_hint(message, {}) is None


def test_digital_arrest_hint_refines_a_broad_impersonation_verdict():
    guidance = build_guidance(
        scam_type="impersonation", risk_level="MEDIUM", local_hint="digital_arrest"
    )
    assert guidance.category_id == "digital_arrest"


def test_guidance_exports_static_indicators_without_raw_scan_content():
    private = "PrivatePerson 9812345678 demo@upi https://private.invalid/token"
    guidance = build_guidance(
        scam_type=private,
        risk_level="HIGH",
        entity_flags=[private, "url_shortener"],
        provider_hits=[private, "safe_browsing", "safe_browsing", "phishtank"],
        ml={
            "sms": {"reasons": [private], "ml_prediction": "PHISHING/SPAM"},
            "urls": [{"url": private, "ml_prediction": "MALICIOUS"}],
        },
        local_hint=private,
        ai_corroborated=True,
    )
    assert guidance.category_id == "suspicious_url"
    assert len(guidance.indicators) == 3
    assert "Google Safe Browsing flagged a link" in guidance.indicators
    assert "Shortened link obscures its destination" in guidance.indicators
    assert set(guidance.indicators) <= CURATED_INDICATORS
    assert all(part not in guidance.model_dump_json() for part in private.split())
