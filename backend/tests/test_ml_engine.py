import joblib
import pytest

from app.engines.entity_rules import extract_entities, redact_text
from app.engines.ml_engine import MODELS_DIR, MLEngine
from app.engines.url_features import FEATURE_NAMES, URLValidationError, extract_features, normalize_url


@pytest.fixture(scope="module")
def engine():
    return MLEngine()


def test_url_features_match_training_order_and_golden_row():
    url = "HTTPS://USER@www.xn--bank-42.example:00443/a12//app.apk?code=123&next=%2Fpay!#receipt"
    normalized, explicit_scheme = normalize_url(url)
    assert normalized == "https://USER@www.xn--bank-42.example:443/a12//app.apk?code=123&next=%2Fpay!#receipt"
    assert explicit_scheme
    features = extract_features(normalized)
    assert tuple(features) == FEATURE_NAMES == tuple(joblib.load(MODELS_DIR / "url_features.joblib"))
    assert list(features.values()) == pytest.approx([
        3.576617644908665, 2, 2 / 19, 4, 9, 0, 21, 7, 2, 1, 1, 1, 1, 1, 1, 2, 83, 23, 13, 2,
        3, 11, 11 / 83, 1, 0, 1, 0, 1, 0, 1, 7, 3, 19, 2, 7, 0, 1, 2, 4, 3,
    ])


@pytest.mark.parametrize("url", [
    "ftp://example.org/", "https://256.0.0.1/", "https://example.org:65536/", "https://bad_host.invalid/",
])
def test_normalization_rejects_invalid_urls(url):
    with pytest.raises(URLValidationError):
        normalize_url(url)


def test_url_scan_uses_the_tfidf_classifier_and_distinguishes_inferred_scheme(engine):
    url = "example.org/Case?value=123"
    result = engine.analyze_url(url)
    explicit = engine.analyze_url(f"http://{url}")
    vectorizer = joblib.load(MODELS_DIR / "url_tfidf_vectorizer.joblib")
    model = joblib.load(MODELS_DIR / "url_tfidf_model.joblib")
    vector = vectorizer.transform([f"http://{url}"])

    assert vector.shape == (1, 50000)
    assert result["model_variant"] == "url_tfidf_fallback"
    assert result["malicious_probability"] == pytest.approx(model.predict_proba(vector)[0, 1])
    assert result["ml_prediction"] == ("MALICIOUS" if model.predict(vector)[0] else "LEGITIMATE")
    assert result["scheme"] == "unknown"
    assert explicit["scheme"] == "http"
    assert result["features"] == explicit["features"]
    assert explicit["risk_score"] - result["risk_score"] == 10


def test_sms_scan_uses_the_sms_model_and_excludes_raw_message(engine):
    message = "  Urgent! Verify your bank account now. Send your OTP.  "
    result = engine.analyze_sms(message)
    vectorizer = joblib.load(MODELS_DIR / "sms_vectorizer.joblib")
    model = joblib.load(MODELS_DIR / "sms_model.joblib")
    vector = vectorizer.transform([message.strip()])

    assert vector.shape == (1, 10033)
    assert result["phishing_probability"] == pytest.approx(model.predict_proba(vector)[0, 1])
    assert result["ml_prediction"] == ("PHISHING/SPAM" if model.predict(vector)[0] else "LEGITIMATE")
    assert result["risk_level"] in {"MEDIUM", "HIGH"}
    assert any("Urgency is combined" in reason for reason in result["reasons"])
    assert "message" not in result


def test_combined_score_includes_the_extra_suspicious_link_bonus(engine):
    urls = ["http://github.com.example.invalid/login", "http://microsoft.com.example.invalid/verify"]
    result = engine.analyze("See " + " or ".join(urls), urls)
    url_scores = [url["risk_score"] for url in result["urls"]]
    assert all(score >= 30 for score in url_scores)
    assert result["risk_score"] == min(100, max(result["sms"]["risk_score"], *url_scores) + 10)
    assert result["score_breakdown"]["adjustments"][0] == {"rule": "Additional suspicious links", "delta": 10}
    assert engine.analyze(urls[0], urls[:1])["sms"] is None


def test_entities_deduplicate_and_redact_beyond_lookup_limit():
    text = (
        "Urgent KYC. Use (https://bit.ly/install.apk). Call +91 (98765) 43210 or 9876543210. "
        "Email Help@example.org. Pay sample@okicici. OTP 1234. Account 0000 1234. "
        "https://extra.example/path?token=secret"
    )
    assert extract_entities(text, max_urls=1) == {
        "urls": ["https://bit.ly/install.apk"],
        "phones": ["+919876543210"],
        "emails": ["Help@example.org"],
        "upi_ids": ["sample@okicici"],
        "flags": ["apk_link", "url_shortener", "urgent_kyc"],
    }
    redacted = redact_text(text)
    assert all(value not in redacted for value in ("bit.ly", "98765", "43210", "Help@", "sample@", "1234", "secret"))
    assert "Urgent KYC" in redacted


def test_upi_uri_and_bare_urls_are_kept_distinct_from_emails():
    entities = extract_entities(
        "Email help@example.org. Visit EXAMPLE.org/A or http://example.org/A. "
        "Pay upi://pay?pa=customer%40samplebank&pn=Example."
    )
    assert entities["urls"] == ["http://example.org/A"]
    assert entities["emails"] == ["help@example.org"]
    assert entities["upi_ids"] == ["customer@samplebank"]
