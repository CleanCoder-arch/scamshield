from io import BytesIO

from PIL import Image, ImageDraw, ImageFont

from app.schemas import RiskLevel, ScamType


def render_warning_card(
    risk_score: int, risk_level: RiskLevel | str, scam_type: ScamType | str
) -> bytes | None:
    """Render a shareable warning using only the score and fixed labels."""
    if risk_score < 40:
        return None

    risk = RiskLevel(risk_level)
    category = ScamType(scam_type)
    category_label = {
        ScamType.UNKNOWN: "Suspicious activity",
        ScamType.NONE: "Suspicious activity",
        ScamType.OTHER: "Suspicious activity",
        ScamType.BANK_KYC: "Bank KYC scam",
        ScamType.UPI_FRAUD: "UPI fraud",
    }.get(category, category.value.replace("_", " ").title())
    accent = "#FDA4AF" if risk == RiskLevel.HIGH else "#FCD34D"

    with Image.new("RGB", (800, 424), "#101827") as image:
        draw = ImageDraw.Draw(image)
        subtitle = ImageFont.load_default(size=22)
        heading = ImageFont.load_default(size=43)
        body = ImageFont.load_default(size=25)

        draw.rectangle((0, 0, 799, 7), fill=accent)
        draw.text((40, 37), "ScamShield warning", fill=accent, font=subtitle)
        draw.text((40, 79), category_label, fill="#F8FAFC", font=heading)
        draw.text((40, 138), f"{risk.value} RISK", fill=accent, font=subtitle)
        draw.text(
            (760, 140),
            f"{risk_score} / 100",
            fill="#F8FAFC",
            font=body,
            anchor="ra",
        )
        draw.rounded_rectangle((40, 188, 760, 201), radius=6, fill="#364156")
        draw.rounded_rectangle(
            (40, 188, 40 + round(720 * risk_score / 100), 201), radius=6, fill=accent
        )
        draw.line((40, 233, 760, 233), fill="#364156", width=1)

        for y, line in zip(
            (263, 308, 353),
            (
                "Pause before replying, clicking, or paying.",
                "Verify using an official app, website, or known number.",
                "If you sent money, contact your bank immediately.",
            ),
        ):
            draw.ellipse((42, y + 9, 50, y + 17), fill=accent)
            draw.text((64, y), line, fill="#E2E8F0", font=body)

        with BytesIO() as output:
            image.save(output, format="PNG")
            return output.getvalue()
