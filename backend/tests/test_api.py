import json
from io import BytesIO

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from app.core.config import MAX_TEXT_BODY_BYTES, MAX_TEXT_LENGTH, Settings
from app.engines.llm_vision import GeminiResult
from app.main import create_app
from app.schemas import ScamType


def make_settings(**overrides):
    values = {
        "dedup_seconds": 0,
        "enable_whois": False,
        "gemini_api_key": None,
        "safe_browsing_api_key": None,
        "urlhaus_auth_key": None,
        "phishtank_api_key": None,
        "virustotal_api_key": None,
        "database_url": None,
        "upstash_redis_rest_url": None,
        "upstash_redis_rest_token": None,
        "allowed_origins": ["http://localhost:3000"],
    }
    return Settings(_env_file=None, **(values | overrides))


@pytest.fixture
def client():
    with TestClient(create_app(make_settings())) as api:
        yield api


@pytest.fixture
def screenshot():
    buffer = BytesIO()
    Image.new("RGB", (16, 16), "white").save(buffer, format="PNG")
    return buffer.getvalue()


def test_health_and_cors(client):
    assert client.get("/health").json() == {"status": "ok"}
    response = client.options(
        "/api/v1/scan",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


@pytest.mark.parametrize("body", [{}, {"text": "  "}, {"text": "x" * (MAX_TEXT_LENGTH + 1)}])
def test_text_validation(client, body):
    response = client.post("/api/v1/scan", json=body)
    assert response.status_code == 422
    assert response.headers["cache-control"] == "no-store"


def test_validation_does_not_echo_unknown_fields(client):
    response = client.post("/api/v1/scan", json={"text": "test", "private@example.test": "secret"})
    assert response.status_code == 422
    assert "private@example.test" not in response.text
    assert "secret" not in response.text


@pytest.mark.parametrize("chunked", [False, True])
def test_text_size_limit(client, chunked):
    body = b"x" * (MAX_TEXT_BODY_BYTES + 1)
    response = client.post(
        "/api/v1/scan",
        content=iter([body[:64], body[64:]]) if chunked else body,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413


def test_text_and_sse_verdicts_agree(client):
    request = {"text": "An update from your account team. Details at https://example.com/help."}
    direct = client.post("/api/v1/scan", json=request)
    assert direct.status_code == 200
    assert direct.headers["cache-control"] == "no-store"
    data = direct.json()
    assert data["entities"]["urls"] == ["https://example.com/help"]
    assert data["ml"]["urls"][0]["model_variant"] == "url_tfidf_fallback"

    with client.stream("POST", "/api/v1/scan/stream", json=request) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        assert response.headers["x-accel-buffering"] == "no"
        lines = [line for line in response.iter_lines() if line]
    names = [line.removeprefix("event: ") for line in lines[::2]]
    assert names == ["entity_extraction", "ml_analysis", "threat_intel", "ai_verdict", "complete"]
    streamed = json.loads(lines[-1].removeprefix("data: "))
    assert streamed.pop("scan_id") != data.pop("scan_id")
    streamed.pop("created_at")
    data.pop("created_at")
    assert streamed == data


def test_sse_reports_safe_error(client, monkeypatch):
    def fail(*_args):
        raise ValueError("sensitive detail")

    monkeypatch.setattr(client.app.state.scan_service.ml, "analyze", fail)
    response = client.post("/api/v1/scan/stream", json={"text": "test"})
    assert response.status_code == 200
    assert "event: error" in response.text
    assert "event: complete" not in response.text
    assert "sensitive detail" not in response.text


def test_image_requires_redaction_and_valid_mime(client, screenshot):
    files = {"file": ("example.png", screenshot, "image/png")}
    assert client.post("/api/v1/scan/image", files=files).status_code == 422
    assert client.post("/api/v1/scan/image", data={"redacted": "false"}, files=files).status_code == 422

    invalid = {"file": ("example.jpg", screenshot, "image/jpeg")}
    response = client.post("/api/v1/scan/image", data={"redacted": "true"}, files=invalid)
    assert response.status_code == 415

    corrupt = {"file": ("example.png", b"an invalid image", "image/png")}
    response = client.post("/api/v1/scan/image", data={"redacted": "true"}, files=corrupt)
    assert response.status_code == 415


def test_image_multipart_limits(screenshot):
    settings = make_settings(max_image_bytes=len(screenshot) - 1)
    with TestClient(create_app(settings)) as api:
        response = api.post(
            "/api/v1/scan/image",
            data={"redacted": "true"},
            files={"file": ("example.png", screenshot, "image/png")},
        )
    assert response.status_code == 413


def test_image_scan_and_unavailable_ocr(client, screenshot, monkeypatch):
    ai = client.app.state.scan_service.ai
    files = {"file": ("example.png", screenshot, "image/png")}
    unavailable = client.post("/api/v1/scan/image", data={"redacted": "true"}, files=files)
    assert unavailable.status_code == 503
    assert unavailable.json()["code"] == "image_analysis_unavailable"

    calls = []

    async def classify_image(content, mime_type):
        calls.append((content, mime_type))
        return GeminiResult(
            "completed", ScamType.BANK_KYC, "Review the sender.", confidence=0.91,
            extracted_text="Urgent: complete KYC today at https://example.com/update.",
        )

    async def classify_text(*_args):
        pytest.fail("Image scan made a second AI request.")

    monkeypatch.setattr(ai, "classify_image", classify_image)
    monkeypatch.setattr(ai, "classify_text", classify_text)
    response = client.post("/api/v1/scan/image", data={"redacted": "true"}, files=files)
    assert response.status_code == 200
    assert calls == [(screenshot, "image/png")]
    assert response.json()["entities"]["urls"] == ["https://example.com/update"]
    assert response.json()["scam_type"] == "bank_kyc"
    assert "extracted_text" not in response.json()["ai"]


def test_rate_limit_and_dedup_apply_to_both_text_routes():
    settings = make_settings(scan_rate_limit=2, dedup_seconds=60)
    with TestClient(create_app(settings)) as api:
        data = {"text": "Hello there."}
        assert api.post("/api/v1/scan", json=data).status_code == 200
        duplicate = api.post("/api/v1/scan/stream", json=data)
        assert duplicate.status_code == 409
        assert duplicate.headers["retry-after"] == "60"
        rate_limited = api.post("/api/v1/scan", json={"text": "Different content."})
        assert rate_limited.status_code == 429
        assert rate_limited.json()["code"] == "rate_limited"
