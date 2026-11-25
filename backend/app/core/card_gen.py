from io import BytesIO

from PIL import Image, ImageDraw, ImageFont

from app.engines.playbooks import CURATED_CATEGORY_LABELS, CURATED_INDICATORS, CURATED_STEPS
from app.schemas import PlaybookGuidance, RiskLevel, ScamType


_CARD_WIDTH = 800
_MARGIN = 40
_BULLET_INSET = 25
_SECTION_TITLE_HEIGHT = 40
_LINE_HEIGHT = 32
_BULLET_GAP = 9
_MAX_ITEMS = 3

_BACKGROUND = "#101827"
_PANEL = "#1D2A3E"
_PRIMARY_TEXT = "#F8FAFC"
_BODY_TEXT = "#E2E8F0"
_DEFAULT_STEPS = (
    "Pause before replying, clicking, or paying.",
    "Verify using an official app, website, or known number.",
    "If you sent money, contact your bank immediately.",
)


def _category_label(scam_type: ScamType, guidance: PlaybookGuidance | None) -> str:
    if guidance and CURATED_CATEGORY_LABELS.get(guidance.category_id) == guidance.category_label:
        return guidance.category_label
    return {
        ScamType.UNKNOWN: "Suspicious activity",
        ScamType.NONE: "Suspicious activity",
        ScamType.OTHER: "Suspicious activity",
        ScamType.BANK_KYC: "Bank KYC scam",
        ScamType.UPI_FRAUD: "UPI fraud",
    }.get(scam_type, scam_type.value.replace("_", " ").title())


def _wrap(text: str, font: ImageFont.FreeTypeFont, width: int) -> tuple[str, ...]:
    lines = []
    current = ""
    for word in text.split():
        next_line = f"{current} {word}" if current else word
        if current and font.getlength(next_line) > width:
            lines.append(current)
            current = word
        else:
            current = next_line
    if current:
        lines.append(current)
    return tuple(lines)


def render_warning_card(
    risk_score: int,
    risk_level: RiskLevel | str,
    scam_type: ScamType | str,
    *,
    guidance: PlaybookGuidance | None = None,
) -> bytes | None:
    """Render a warning from a score and allowlisted display copy."""
    if type(risk_score) is not int or not 0 <= risk_score <= 100:
        raise ValueError("A warning card risk score must be an integer from 0 to 100.")
    if risk_score < 40:
        return None

    risk = RiskLevel(risk_level)
    category = _category_label(ScamType(scam_type), guidance)
    indicators = ()
    steps = _DEFAULT_STEPS
    if guidance:
        indicators = tuple(dict.fromkeys(item for item in guidance.indicators if item in CURATED_INDICATORS))
        steps = tuple(dict.fromkeys(item for item in guidance.steps if item in CURATED_STEPS)) or steps

    accent = "#FDA4AF" if risk == RiskLevel.HIGH else "#FCD34D"
    label = ImageFont.load_default(size=22)
    heading = ImageFont.load_default(size=45)
    score_font = ImageFont.load_default(size=32)
    section_font = ImageFont.load_default(size=28)
    body = ImageFont.load_default(size=24)
    right_margin = _CARD_WIDTH - _MARGIN
    width = right_margin - _MARGIN

    category_lines = _wrap(category, heading, width)
    sections = []
    for title, items in (("Key indicators", indicators), ("What to do now", steps)):
        if items:
            rows = [_wrap(item, body, width - _BULLET_INSET) for item in items[:_MAX_ITEMS]]
            sections.append((title, rows))
    score_top = 90 + 54 * len(category_lines)
    body_top = score_top + 124
    footer_top = body_top + sum(
        _SECTION_TITLE_HEIGHT + sum(_LINE_HEIGHT * len(lines) + _BULLET_GAP for lines in rows) + 16
        for _, rows in sections
    )

    with Image.new("RGB", (_CARD_WIDTH, footer_top + 146), _BACKGROUND) as image:
        draw = ImageDraw.Draw(image)
        draw.rectangle((0, 0, _CARD_WIDTH - 1, 7), fill=accent)
        draw.text((_MARGIN, 36), "ScamShield warning", fill=accent, font=label, anchor="lt")
        for index, line in enumerate(category_lines):
            draw.text((_MARGIN, 76 + index * 54), line, fill=_PRIMARY_TEXT, font=heading, anchor="lt")

        draw.rounded_rectangle((_MARGIN, score_top, right_margin, score_top + 96), radius=17, fill=_PANEL)
        left = _MARGIN + 20
        right = right_margin - 20
        badge = f"{risk.value} RISK"
        badge_width = round(label.getlength(badge)) + 28
        draw.rounded_rectangle((left, score_top + 17, left + badge_width, score_top + 53), radius=9, fill=accent)
        draw.text((left + 14, score_top + 27), badge, fill=_BACKGROUND, font=label, anchor="lt")
        draw.text((right, score_top + 19), f"{risk_score} / 100", fill=_PRIMARY_TEXT, font=score_font, anchor="rt")
        draw.rounded_rectangle((left, score_top + 70, right, score_top + 79), radius=4, fill="#3B4B62")
        draw.rounded_rectangle(
            (left, score_top + 70, left + round((right - left) * risk_score / 100), score_top + 79),
            radius=4,
            fill=accent,
        )

        y = body_top
        for title, rows in sections:
            draw.text((_MARGIN, y), title, fill=_PRIMARY_TEXT, font=section_font, anchor="lt")
            y += _SECTION_TITLE_HEIGHT
            for lines in rows:
                draw.ellipse((_MARGIN + 2, y + 7, _MARGIN + 9, y + 14), fill=accent)
                for line in lines:
                    draw.text((_MARGIN + _BULLET_INSET, y), line, fill=_BODY_TEXT, font=body, anchor="lt")
                    y += _LINE_HEIGHT
                y += _BULLET_GAP
            y += 16

        draw.rounded_rectangle((_MARGIN, footer_top, right_margin, footer_top + 106), radius=17, fill=_PANEL)
        draw.text((left, footer_top + 19), "Report cyber fraud in India", fill=_PRIMARY_TEXT, font=section_font, anchor="lt")
        draw.text((left, footer_top + 63), "Call 1930 for financial fraud", fill=accent, font=body, anchor="lt")
        draw.text((right, footer_top + 63), "cybercrime.gov.in", fill=accent, font=body, anchor="rt")

        with BytesIO() as output:
            image.save(output, format="PNG")
            return output.getvalue()
