from io import BytesIO

import pytest
from PIL import Image, ImageDraw

from app.core.card_gen import render_warning_card
from app.engines.playbooks import build_guidance
from app.schemas import RiskLevel, ScamType


@pytest.fixture
def painted_text(monkeypatch):
    painted = []
    draw_text = ImageDraw.ImageDraw.text

    def record(draw, xy, text, *args, **kwargs):
        painted.append((xy, text, kwargs["font"], kwargs["anchor"]))
        return draw_text(draw, xy, text, *args, **kwargs)

    monkeypatch.setattr(ImageDraw.ImageDraw, "text", record)
    return painted


def _upi_guidance():
    return build_guidance(
        scam_type=ScamType.UPI_FRAUD,
        risk_level=RiskLevel.HIGH,
        local_hint="upi_fraud",
        provider_hits=("safe_browsing", "phishtank"),
    )


def test_card_renders_readable_guidance_and_reporting(painted_text):
    guidance = _upi_guidance()
    assert render_warning_card(39, RiskLevel.MEDIUM, ScamType.UPI_FRAUD, guidance=guidance) is None
    png = render_warning_card(84, RiskLevel.HIGH, ScamType.UPI_FRAUD, guidance=guidance)
    assert png is not None

    with Image.open(BytesIO(png)) as image:
        assert image.format == "PNG"
        assert image.width == 800
        for (x, y), text, font, anchor in painted_text:
            left, top, right, bottom = font.getbbox(text, anchor=anchor)
            assert 0 <= x + left < x + right <= image.width
            assert 0 <= y + top < y + bottom <= image.height
        image.verify()

    lines = [text for _, text, _, _ in painted_text]
    text = " ".join(lines)
    assert "84 / 100" in lines
    assert "HIGH RISK" in lines
    assert guidance.category_label in text
    assert "Key indicators" in lines
    assert all(item in text for item in guidance.indicators[:3])
    assert len(guidance.steps) == 3
    assert all(step in text for step in guidance.steps)
    assert any(step not in lines for step in guidance.steps)
    assert "Call 1930 for financial fraud" in lines
    assert "cybercrime.gov.in" in lines


def test_card_excludes_untrusted_guidance_fields(painted_text):
    guidance = _upi_guidance()
    private_text = "private-contact@okbank https://submitted.example/otp"
    injected = guidance.model_copy(update={
        "category_label": private_text,
        "indicators": [private_text, *guidance.indicators],
        "steps": [private_text, *guidance.steps],
        "reporting_steps": [private_text],
    })

    png = render_warning_card(84, RiskLevel.HIGH, ScamType.UPI_FRAUD, guidance=injected)
    assert png is not None
    text = " ".join(item for _, item, _, _ in painted_text)
    assert "private-contact@okbank" not in text
    assert "submitted.example" not in text
    assert all(step in text for step in guidance.steps)
    with Image.open(BytesIO(png)) as image:
        assert image.info == {}
