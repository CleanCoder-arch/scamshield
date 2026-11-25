import asyncio
import json
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import httpx
import pytest
from google.genai import errors as gemini_errors
from PIL import Image

from app.core import redis_cache, scan_store
from app.core.card_gen import render_warning_card
from app.core.config import Settings
from app.core.redis_cache import CachedVerdict, RedisCache
from app.core.scan_store import ScanStore, ScanStoreUnavailableError
from app.engines.llm_vision import GeminiResult, GeminiVision
from app.engines.threat_intel import ThreatFinding, ThreatIntel
from app.scan_service import ScanService, merge_assessment
from app.schemas import AIResult, Entities, RiskLevel, ScamType, ThreatResult


def test_local_score_survives_unavailable_providers():
    intel = [ThreatResult(provider="urlhaus", scope="url", indicator="example.com", status="unavailable")]
    score, category = merge_assessment(60, Entities(), intel, AIResult(status="unavailable"))
    assert score.starting_score == score.final_score == 60
    assert score.adjustments == []
    assert category == ScamType.UNKNOWN


def test_risk_fusion_uses_bounded_explainable_adjustments():
    intel = [
        ThreatResult(provider="phishtank", scope="url", indicator="example.com", status="hit"),
        ThreatResult(
            provider="whois", scope="domain", indicator="example.com", status="clear", domain_age_days=7
        ),
    ]
    ai = AIResult(status="completed", scam_type=ScamType.BANK_KYC, confidence=0.90)
    entities = Entities(flags=["url_shortener", "url_shortener", "urgent_kyc"])
    score, category = merge_assessment(12, entities, intel, ai)
    assert score.final_score == 100
    assert [item.delta for item in score.adjustments] == [20, 5, 48, 15]
    assert score.starting_score + sum(item.delta for item in score.adjustments) == score.final_score
    assert category == ScamType.BANK_KYC


@pytest.mark.parametrize("storage_fails", [False, True])
def test_service_redacts_ai_input_and_saves_only_metadata(storage_fails):
    text = "Urgent KYC. Send OTP 1234 to private@ybl or +91 98765 43210. See https://example.com."
    classify = AsyncMock(
        return_value=GeminiResult(
            status="completed", scam_type=ScamType.BANK_KYC,
            explanation="Avoid sending money to private@ybl.", confidence=0.95,
        )
    )
    save = AsyncMock(side_effect=ScanStoreUnavailableError if storage_fails else None)
    service = ScanService(
        Settings(_env_file=None, enable_whois=False),
        SimpleNamespace(analyze=Mock(return_value={"risk_score": 25})),
        SimpleNamespace(
            lookup=AsyncMock(return_value=[
                ThreatFinding(provider="safe_browsing", scope="url", indicator="https://example.com", status="hit")
            ]),
        ),
        SimpleNamespace(classify_text=classify),
        None,
        SimpleNamespace(save=save),
    )

    result = asyncio.run(service.scan(text))
    redacted, confirmed_sources = classify.await_args.args
    assert confirmed_sources == ["safe_browsing"]
    for value in ("private@ybl", "98765", "1234", "example.com"):
        assert value not in redacted
        assert value not in result.guidance.model_dump_json()
    assert "private@ybl" not in result.ai.explanation
    assert result.guidance.category_id == "bank_kyc"
    assert "Google Safe Browsing flagged a link" in result.guidance.indicators
    assert result.risk_score == 100
    assert result.warning_card_png_base64
    assert save.await_args.kwargs == {
        "scan_id": result.scan_id,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "scam_type": result.scam_type,
        "created_at": result.created_at,
    }


def test_threat_intel_checks_only_provider_endpoints_and_keeps_partial_results():
    async def exercise():
        requests = []
        stored = []

        class VerdictCache:
            async def get_verdict(self, provider, scope, indicator):
                return None

            async def put_verdict(self, provider, scope, indicator, verdict, *, ttl_seconds):
                stored.append((provider, scope, indicator, verdict, ttl_seconds))

        async def respond(request):
            requests.append(request)
            if request.url.host == "safebrowsing.googleapis.com":
                return httpx.Response(200, json={"matches": [{"cacheDuration": "5.5s"}]})
            if request.url.host == "urlhaus-api.abuse.ch":
                raise httpx.ReadTimeout("Synthetic timeout", request=request)
            if request.url.host == "checkurl.phishtank.com":
                return httpx.Response(302, headers={"Location": "https://untrusted.example.com/"})
            if request.url.host == "data.iana.org":
                return httpx.Response(200, json={"services": [[["com"], ["https://rdap.example.com/"]]]})
            assert request.url == "https://rdap.example.com/domain/example.com"
            return httpx.Response(
                200,
                json={"events": [{"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"}]},
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond), follow_redirects=True) as client:
            intel = ThreatIntel(
                client,
                safe_browsing_api_key="test-only",
                urlhaus_auth_key="test-only",
                phishtank_api_key="test-only",
                cache=VerdictCache(),
            )
            findings = await intel.lookup([
                "https://shop.example.com/review?q=product#client-fragment",
                "https://shop.example.com/review?q=product",
                "https://user:secret@example.com/",
                "https://example.com/?access_token=secret",
                "http://127.0.0.1/",
            ])

        by_provider = {item.provider: item for item in findings}
        assert {key: item.status for key, item in by_provider.items()} == {
            "safe_browsing": "hit", "urlhaus": "unavailable", "phishtank": "unavailable",
            "virustotal": "skipped", "whois": "clear",
        }
        assert by_provider["whois"].scope == "domain"
        assert by_provider["whois"].domain_age_days > 1_000
        assert len(requests) == 5
        safe_request = next(req for req in requests if req.url.host == "safebrowsing.googleapis.com")
        assert json.loads(safe_request.content)["threatInfo"]["threatEntries"] == [
            {"url": "https://shop.example.com/review?q=product"}
        ]
        safe_entry = next(entry for entry in stored if entry[0] == "safe_browsing")
        assert safe_entry[1] == "url"
        assert safe_entry[-1] == 5

    asyncio.run(exercise())


def test_virustotal_uses_read_only_reports_and_limits_requests():
    async def exercise():
        requests = []

        def respond(request):
            requests.append(request)
            return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            intel = ThreatIntel(client, virustotal_api_key="test-only", enable_whois=False)
            findings = await intel.lookup([f"https://example.com/item/{i}" for i in range(5)])

        statuses = [item.status for item in findings if item.provider == "virustotal"]
        assert statuses == ["clear", "clear", "clear", "clear", "skipped"]
        assert len(requests) == 4
        assert all(
            request.method == "GET" and request.url.host == "www.virustotal.com"
            and request.url.path.startswith("/api/v3/urls/")
            for request in requests
        )

    asyncio.run(exercise())


def test_gemini_image_uses_one_structured_call_with_inline_bytes():
    async def exercise():
        payload = {
            "scam_type": "bank_kyc", "confidence": 0.9, "explanation": "An urgent request.",
            "actions": ["Contact your bank directly."], "extracted_text": "Verify KYC today",
        }
        generate = AsyncMock(return_value=SimpleNamespace(parsed=None, text=json.dumps(payload)))
        client = SimpleNamespace(models=SimpleNamespace(generate_content=generate), aclose=AsyncMock())
        gemini = GeminiVision(client=client)
        result = await gemini.classify_image(b"synthetic-bytes", "image/png")
        assert result.status == "completed"
        assert result.extracted_text == "Verify KYC today"
        assert result.scam_type == ScamType.BANK_KYC
        generate.assert_awaited_once()
        request = generate.await_args.kwargs
        assert request["model"] == "gemini-3.5-flash-lite"
        assert request["contents"][1].inline_data.data == b"synthetic-bytes"
        assert request["config"].response_mime_type == "application/json"
        assert request["config"].tools is None
        await gemini.aclose()
        client.aclose.assert_awaited_once()

    asyncio.run(exercise())


def test_gemini_skips_absent_credentials_and_exhausted_quota_and_rejects_unknown_labels():
    async def exercise():
        missing = GeminiVision(api_key="   ")
        assert await missing.classify_text("A redacted message") == GeminiResult(
            "skipped", reason="missing_api_key"
        )
        payload = {
            "scam_type": "unlisted-label", "confidence": 0.9,
            "explanation": "Classification", "actions": [],
        }
        generate = AsyncMock(return_value=SimpleNamespace(parsed=None, text=json.dumps(payload)))
        client = SimpleNamespace(models=SimpleNamespace(generate_content=generate))
        limited = GeminiVision(client=client, requests_per_minute=1)
        assert await limited.classify_text("First redacted message") == GeminiResult(
            "unavailable", reason="invalid_response"
        )
        assert await limited.classify_text("Second redacted message") == GeminiResult(
            "skipped", reason="quota_exceeded"
        )
        generate.assert_awaited_once()

    asyncio.run(exercise())


def test_gemini_key_loads_from_absolute_backend_dotenv(tmp_path, monkeypatch):
    assert Settings.model_config["env_file"] == Path(__file__).resolve().parents[1] / ".env"

    env_file = tmp_path / "backend" / ".env"
    env_file.parent.mkdir()
    env_file.write_text("GEMINI_API_KEY=' fixture-file-key '\n", encoding="utf-8-sig")
    monkeypatch.setitem(Settings.model_config, "env_file", env_file)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GEMINI_API_KEY", " \t ")
    assert Settings().gemini_api_key.get_secret_value() == "fixture-file-key"

    monkeypatch.setenv("GEMINI_API_KEY", " fixture-environment-key ")
    assert Settings().gemini_api_key.get_secret_value() == "fixture-environment-key"


@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        (gemini_errors.ClientError(429, {"status": "RESOURCE_EXHAUSTED"}), "quota_exceeded"),
        (gemini_errors.ClientError(400, {"error": {"details": [{"reason": "API_KEY_INVALID"}]}}), "invalid_api_key"),
        (gemini_errors.ServerError(503, {"message": "private diagnostic"}), "provider_error"),
        (httpx.ConnectError("private diagnostic"), "network_error"),
        (TimeoutError("private diagnostic"), "network_error"),
    ],
)
def test_gemini_reports_safe_provider_failure_reasons(failure, reason):
    async def exercise():
        generate = AsyncMock(side_effect=failure)
        client = SimpleNamespace(models=SimpleNamespace(generate_content=generate))
        gemini = GeminiVision(client=client)
        assert await gemini.classify_text("A redacted message") == GeminiResult("unavailable", reason=reason)

    asyncio.run(exercise())



def test_postgres_accepts_only_typed_anonymized_scan_metadata(monkeypatch):
    pool = Mock(execute=AsyncMock(), close=AsyncMock())
    create_pool = AsyncMock(return_value=pool)
    monkeypatch.setattr(scan_store.asyncpg, "create_pool", create_pool)
    raw_scam_label = "private-contact@okbank"
    fields = {
        "scan_id": uuid4(),
        "risk_score": 57,
        "risk_level": RiskLevel.MEDIUM,
        "scam_type": ScamType.UPI_FRAUD,
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
    }

    async def check():
        store = ScanStore("postgresql://db.example.test/scans")
        with pytest.raises(ValueError, match="Invalid anonymized scan metadata"):
            await store.save(**{**fields, "scam_type": raw_scam_label})
        create_pool.assert_not_awaited()
        await store.save(**fields)
        await store.aclose()

    asyncio.run(check())

    create_pool.assert_awaited_once()
    pool.close.assert_awaited_once()
    assert len(pool.execute.await_args_list) == 2
    sql, *values = pool.execute.await_args_list[1].args
    assert "(scan_id, risk_score, risk_level, scam_type, created_at)" in sql
    assert "VALUES ($1, $2, $3, $4, $5)" in sql
    assert values == [fields["scan_id"], 57, "MEDIUM", "upi_fraud", fields["created_at"]]
    assert raw_scam_label not in repr(pool.execute.await_args_list)


def test_upstash_wire_commands_hash_inputs_and_separate_verdict_scopes():
    commands = []

    def respond(request: httpx.Request) -> httpx.Response:
        command = json.loads(request.content)
        commands.append(command)
        result = {"EVAL": 1, "SET": "OK", "GET": '{"status":"clear","domain_age_days":72}'}
        return httpx.Response(200, json={"result": result[command[0]]})

    async def check():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            cache = RedisCache(client, "https://redis.example.test", "test-token", "test-salt")
            assert await cache.allow_scan("192.0.2.10", limit=1, window_seconds=60)
            assert await cache.claim_scan("192.0.2.10", b"private@okbank", ttl_seconds=60)
            verdict = CachedVerdict(status="clear", domain_age_days=72)
            await cache.put_verdict("whois", "domain", "submitted.example", verdict, ttl_seconds=120)
            assert await cache.get_verdict("whois", "domain", "submitted.example") == verdict
            await cache.get_verdict("whois", "url", "submitted.example")

    asyncio.run(check())

    rate, claim, put, get_domain, get_url = commands
    assert rate[0] == "EVAL"
    assert claim[:1] + claim[2:] == ["SET", "1", "NX", "EX", 60]
    assert put[0] == "SET"
    assert put[1] == get_domain[1]
    assert get_domain[1] != get_url[1]
    assert json.loads(put[2]) == {"status": "clear", "domain_age_days": 72}
    assert put[3:] == ["EX", 120]
    assert all(key.startswith("scamshield:v1:") for key in (rate[3], claim[1], put[1], get_url[1]))
    for raw_input in ("192.0.2.10", "private@okbank", "submitted.example"):
        assert raw_input not in json.dumps(commands)


def test_redis_outage_retains_local_quota_and_dedup_until_expiry(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(redis_cache, "monotonic", lambda: now[0])

    def outage(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Unavailable", request=request)

    async def check():
        async with httpx.AsyncClient(transport=httpx.MockTransport(outage)) as client:
            cache = RedisCache(client, "https://redis.example.test", "test-token", "test-salt")
            assert await cache.allow_scan("client", limit=1, window_seconds=10)
            assert not await cache.allow_scan("client", limit=1, window_seconds=10)
            assert await cache.claim_scan("client", b"text", ttl_seconds=10)
            assert not await cache.claim_scan("client", b"text", ttl_seconds=10)
            now[0] += 11
            assert await cache.allow_scan("client", limit=1, window_seconds=10)
            assert await cache.claim_scan("client", b"text", ttl_seconds=10)

    asyncio.run(check())


def test_warning_card_is_valid_png_at_score_threshold():
    assert render_warning_card(39, RiskLevel.MEDIUM, ScamType.PHISHING) is None
    png = render_warning_card(40, RiskLevel.MEDIUM, ScamType.PHISHING)
    assert png is not None
    with Image.open(BytesIO(png)) as image:
        assert image.format == "PNG"
        image.verify()

