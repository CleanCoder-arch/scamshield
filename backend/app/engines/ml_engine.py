from collections.abc import Sequence
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from app.core.config import MODELS_DIR
from app.engines.entity_rules import analyze_sms_risk, extract_entities
from app.engines.url_features import FEATURE_NAMES, extract_features, normalize_url
from app.schemas import RiskLevel
from models.risk_engine import analyze_risk


SMS_FEATURES = 10033
URL_TFIDF_FEATURES = 50000


def _load_classifier(path: Path, columns: int) -> LogisticRegression:
    classifier = joblib.load(path)
    if (
        not isinstance(classifier, LogisticRegression)
        or classifier.n_features_in_ != columns
        or classifier.coef_.shape != (1, columns)
        or classifier.classes_.tolist() != [0, 1]
    ):
        raise ValueError(f"Unexpected classifier contract in {path.name}")
    return classifier


def _load_vectorizer(
    path: Path, columns: int, analyzer: str, ngram_range: tuple[int, int]
) -> TfidfVectorizer:
    vectorizer = joblib.load(path)
    if (
        not isinstance(vectorizer, TfidfVectorizer)
        or vectorizer.analyzer != analyzer
        or vectorizer.ngram_range != ngram_range
        or len(vectorizer.vocabulary_) != columns
        or vectorizer.idf_.shape != (columns,)
    ):
        raise ValueError(f"Unexpected vectorizer contract in {path.name}")
    return vectorizer


def _validate_hybrid_artifacts(models_dir: Path) -> None:
    features = tuple(joblib.load(models_dir / "url_features.joblib"))
    scaler = joblib.load(models_dir / "url_hybrid_scaler.joblib")
    if (
        features != FEATURE_NAMES
        or not isinstance(scaler, StandardScaler)
        or scaler.n_features_in_ != len(FEATURE_NAMES)
        or tuple(scaler.feature_names_in_) != FEATURE_NAMES
    ):
        raise ValueError("Unexpected CyberGuard URL feature or scaler contract")
    # Validate the paired artifacts while the URL TF-IDF model handles all scans.
    _load_vectorizer(models_dir / "url_hybrid_vectorizer.joblib", URL_TFIDF_FEATURES, "char", (2, 5))
    _load_classifier(models_dir / "url_hybrid_model.joblib", URL_TFIDF_FEATURES + len(FEATURE_NAMES))


class MLEngine:
    """Load the bundled CyberGuard artifacts once and score request data locally."""

    def __init__(self, models_dir: Path | None = None) -> None:
        root = models_dir if models_dir is not None else MODELS_DIR
        self._sms_model = _load_classifier(root / "sms_model.joblib", SMS_FEATURES)
        self._sms_vectorizer = _load_vectorizer(root / "sms_vectorizer.joblib", SMS_FEATURES, "word", (1, 2))
        self._url_model = _load_classifier(root / "url_tfidf_model.joblib", URL_TFIDF_FEATURES)
        self._url_vectorizer = _load_vectorizer(root / "url_tfidf_vectorizer.joblib", URL_TFIDF_FEATURES, "char", (2, 5))
        _validate_hybrid_artifacts(root)

    def analyze_url(self, url: str) -> dict:
        normalized, explicit_scheme = normalize_url(url)
        scheme = normalized.split(":", 1)[0] if explicit_scheme else "unknown"
        features = extract_features(normalized)
        vector = self._url_vectorizer.transform([normalized])
        prediction = self._url_model.predict(vector)[0]
        legitimate, malicious = map(float, self._url_model.predict_proba(vector)[0])
        result = analyze_risk(normalized, malicious, features, scheme=scheme)
        return {
            **result,
            "url": normalized if explicit_scheme else normalized.removeprefix("http://"),
            "scheme": scheme,
            "explicit_scheme": explicit_scheme,
            "ml_prediction": "MALICIOUS" if prediction == 1 else "LEGITIMATE",
            "model_variant": "url_tfidf_fallback",
            "legitimate_probability": legitimate,
            "features": features,
        }

    def analyze_sms(self, text: str, *, detected_urls: Sequence[str] | None = None) -> dict:
        text = text.strip()
        if detected_urls is None:
            detected_urls = extract_entities(text)["urls"]
        vector = self._sms_vectorizer.transform([text])
        prediction = self._sms_model.predict(vector)[0]
        legitimate, phishing = map(float, self._sms_model.predict_proba(vector)[0])
        risk = analyze_sms_risk(text, phishing, has_links=bool(detected_urls))
        return {
            **risk,
            "ml_prediction": "PHISHING/SPAM" if prediction == 1 else "LEGITIMATE",
            "model_variant": "sms_tfidf",
            "legitimate_probability": legitimate,
            "phishing_probability": phishing,
        }

    def analyze(self, text: str, urls: Sequence[str]) -> dict:
        url_results = [self.analyze_url(url) for url in urls]
        stripped = text.strip()
        is_url_only = len(urls) == 1 and stripped == urls[0]
        sms = self.analyze_sms(stripped, detected_urls=urls) if stripped and not is_url_only else None

        url_scores = [result["risk_score"] for result in url_results]
        base = max([sms["risk_score"] if sms else 0, *url_scores])
        extra_links = max(0, sum(score >= 30 for score in url_scores) - 1)
        bonus = 10 * extra_links
        score = min(100, base + bonus)
        adjustments = []
        if bonus:
            adjustments.append({"rule": "Additional suspicious links", "delta": bonus})
        if base + bonus > 100:
            adjustments.append({"rule": "Score capped at 100", "delta": score - base - bonus})
        return {
            "sms": sms,
            "urls": url_results,
            "risk_score": score,
            "risk_level": RiskLevel.for_score(score).value,
            "score_breakdown": {"starting_score": base, "adjustments": adjustments, "final_score": score},
        }
