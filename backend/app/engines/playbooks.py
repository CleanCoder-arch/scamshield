from collections.abc import Iterable, Mapping
from typing import Any

from app.engines.entity_rules import (
    UPI_PIN_RULE_REASON,
    UPFRONT_JOB_RULE_REASON,
    has_digital_arrest_order,
)
from app.schemas import PlaybookGuidance


_GENERAL_STEPS = (
    "Pause before replying, clicking, or paying.",
    "Verify the request through an official app, website, or known number.",
    "Keep passwords, payment details, and verification codes private.",
)

_PLAYBOOKS = {
    # RBI KYC fraud advisory (PR 57244).
    "bank_kyc": ("Bank KYC scam", (
        "Verify the KYC request in your bank's official app or by calling the number on your card.",
        "Use a verified bank channel to update your KYC details.",
        "Keep OTPs, PINs, passwords, and KYC documents away from the sender.",
    )),
    # NPCI UPI FAQs and fraud-awareness guidance.
    "upi_fraud": ("UPI fraud", (
        "Approving a UPI collect request sends money. Decline unexpected requests.",
        "Verify the refund in the original merchant's app or through its official support.",
        "Receiving money does not require a UPI PIN or a QR code scan.",
    )),
    # MHA digital arrest alert (PIB release 2020570).
    "digital_arrest": ("Digital arrest scam", (
        "Indian authorities do not arrest people over video calls or demand payment to avoid arrest.",
        "End the call and tell someone you trust. Verify the claim using an official agency number you find yourself.",
        "Refuse screen sharing, demands to stay on video, or transfers to a 'safe account'.",
    )),
    # I4C's fake jobs advisory (TAU/ADV/004).
    "fake_job": ("Fake job offer", (
        "Check the role on the employer's official careers site.",
        "Verify the recruiter using contact details published by the employer.",
        "Decline upfront registration, training, or equipment fees for a job offer.",
    )),
    "suspicious_url": ("Suspicious link or phishing", (
        "Open the organisation's official site or app directly.",
        "Leave the supplied link unopened and keep login or payment details private.",
        "If you already entered a password, change it on the official site.",
    )),
    "low_risk": ("Low-risk check", (
        "Check the sender and the destination before you act.",
        "Use an official app or website for payments and account changes.",
    )),
    "generic": ("Suspicious activity", _GENERAL_STEPS),
    "impersonation": ("Impersonation", _GENERAL_STEPS),
    "investment": ("Investment fraud", _GENERAL_STEPS),
    "delivery": ("Delivery scam", _GENERAL_STEPS),
    "lottery": ("Lottery scam", _GENERAL_STEPS),
    "tech_support": ("Tech support scam", _GENERAL_STEPS),
    "other": ("Other scam", _GENERAL_STEPS),
}
_REPORTING_STEPS = (
    "If you lost money, call 1930 and contact your bank or payment provider immediately, ideally within the first hour.",
    "File at cybercrime.gov.in. Include the 1930 acknowledgement number if you received one.",
    "Keep screenshots, transaction references, and timestamps private for your bank or the authorities.",
)
_ENTITY_INDICATORS = {
    "urgent_kyc": "Pressure to update KYC quickly",
    "apk_link": "Link points to an Android app package",
    "url_shortener": "Shortened link obscures its destination",
}
_CATEGORY_INDICATORS = {
    "upi_fraud": "Request to enter a UPI PIN to receive money",
    "digital_arrest": "Claim of arrest or detention by digital means",
    "fake_job": "Upfront fee requested for a paid remote job",
}
_PROVIDER_INDICATORS = {
    "safe_browsing": "Google Safe Browsing flagged a link",
    "urlhaus": "URLhaus matched a threat listing",
    "phishtank": "PhishTank matched a known phishing link",
    "virustotal": "VirusTotal reported a suspicious link",
}
_MODEL_URL = "URL model flagged a link as potentially malicious"
_MODEL_SMS = "Message model detected possible phishing or spam"
_AI = "AI classification indicated a possible scam"
_ALIASES = {"job": "fake_job", "phishing": "suspicious_url", "malware": "suspicious_url"}

CURATED_CATEGORY_LABELS = {category: label for category, (label, _) in _PLAYBOOKS.items()}
CURATED_STEPS = frozenset(step for _, steps in _PLAYBOOKS.values() for step in steps)
CURATED_REPORTING_STEPS = frozenset(_REPORTING_STEPS)
CURATED_INDICATORS = frozenset((
    *_ENTITY_INDICATORS.values(), *_CATEGORY_INDICATORS.values(), *_PROVIDER_INDICATORS.values(),
    _MODEL_URL, _MODEL_SMS, _AI,
))


def _sms_result(ml: Mapping[str, Any]) -> Mapping[str, Any]:
    sms = ml.get("sms")
    return sms if isinstance(sms, Mapping) else {}


def _local_message_category(ml: Mapping[str, Any]) -> str | None:
    reasons = _sms_result(ml).get("reasons", [])
    if UPI_PIN_RULE_REASON in reasons:
        return "upi_fraud"
    if UPFRONT_JOB_RULE_REASON in reasons:
        return "fake_job"
    return None


def local_scam_hint(text: str, ml: Mapping[str, Any]) -> str | None:
    """Select a category for guidance when no specific classification is available."""
    if has_digital_arrest_order(text):
        return "digital_arrest"
    return _local_message_category(ml)


def build_guidance(
    *,
    scam_type: str,
    risk_level: str,
    entity_flags: Iterable[str] = (),
    provider_hits: Iterable[str] = (),
    ml: Mapping[str, Any] | None = None,
    local_hint: str | None = None,
    ai_corroborated: bool = False,
) -> PlaybookGuidance:
    """Return curated safety guidance based on completed checks and local signals."""
    signals = ml or {}
    flags = set(entity_flags)
    hits = set(provider_hits)
    provider_labels = [label for code, label in _PROVIDER_INDICATORS.items() if code in hits]
    malicious_url = any(
        isinstance(url, Mapping) and url.get("ml_prediction") == "MALICIOUS"
        for url in signals.get("urls", ())
    )
    category = _ALIASES.get(scam_type, scam_type)
    if category == "impersonation" and local_hint == "digital_arrest":
        category = "digital_arrest"
    if category not in _PLAYBOOKS or category in {"generic", "low_risk"}:
        if local_hint in _CATEGORY_INDICATORS:
            category = local_hint
        elif "urgent_kyc" in flags:
            category = "bank_kyc"
        elif provider_labels or (risk_level != "LOW" and (malicious_url or flags & {"apk_link", "url_shortener"})):
            category = "suspicious_url"
        else:
            category = "low_risk" if risk_level == "LOW" else "generic"

    indicators = []
    actual_category = local_hint or _local_message_category(signals)
    if actual_category in _CATEGORY_INDICATORS:
        indicators.append(_CATEGORY_INDICATORS[actual_category])
    indicators.extend(provider_labels)
    indicators.extend(label for code, label in _ENTITY_INDICATORS.items() if code in flags)
    if malicious_url:
        indicators.append(_MODEL_URL)
    if _sms_result(signals).get("ml_prediction") == "PHISHING/SPAM":
        indicators.append(_MODEL_SMS)
    if ai_corroborated:
        indicators.append(_AI)

    label, steps = _PLAYBOOKS[category]
    return PlaybookGuidance(
        category_id=category,
        category_label=label,
        indicators=indicators[:3],
        steps=list(steps),
        reporting_steps=list(_REPORTING_STEPS),
    )
