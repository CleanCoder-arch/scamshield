from collections.abc import Iterator
import re
from urllib.parse import parse_qs, urlsplit

from app.engines.url_features import SHORTENER_DOMAINS, URLValidationError, normalize_url
from app.schemas import RiskLevel


_SCHEME = r"(?ai:[a-z][a-z0-9+.-]{0,63}://)"
_URL_TAIL = r"""[^\s<>{}"']*"""
_DOMAIN = r"(?ai:(?:[a-z0-9-]+\.)+(?:xn--[a-z0-9-]+|[a-z]{2,}))"
_UNICODE_DOMAIN = r"(?:[^\W_](?:[^\W_]|-)*\.)+[^\W\d_]{2,63}"
_IP_LITERAL = r"(?:[0-9]+\.){3}[0-9]+|\[(?ai:[0-9a-f.]*):[^\s\[\]<>]*\]"
_BARE_HOST = rf"(?:{_DOMAIN}|{_UNICODE_DOMAIN}|{_IP_LITERAL})(?![\w@+%-]|\.[\w.-])"
_BARE_PORT = r"""(?::[^\s/?#()<>\[\]{}"',;!]*)?"""
_BARE_AUTHORITY = rf"(?<![\w@.+%-]){_BARE_HOST}{_BARE_PORT}"
_EMAIL_ATOM = r"""[\w.!#$%&'*+=^_`{|}~/-]"""
_EMAIL_LOCAL = rf"""(?:{_EMAIL_ATOM}+|"[^"\r\n]+")"""
_EMAIL_DOMAIN = r"(?:[\w-]+(?:\.[\w-]+)+|\[[^\s\[\]]+\])"
_EMAIL = rf"(?<!{_EMAIL_ATOM})(?ai:mailto:)?(?P<email>{_EMAIL_LOCAL}@{_EMAIL_DOMAIN})"
_CANDIDATE = re.compile(
    rf"(?P<explicit>(?<![\w@]){_SCHEME}{_URL_TAIL})"
    rf"|(?P<network>(?<![\w@:/])//{_URL_TAIL})"
    rf"|(?P<bare_path>{_BARE_AUTHORITY}[/?#]{_URL_TAIL})"
    rf"|{_EMAIL}|(?P<bare>{_BARE_AUTHORITY})"
)
_URL_PARTS = re.compile(rf"^({_SCHEME}|//)?([^/?#]*)(.*)$")
_WRAPPERS = {"<": ">", '"': '"', "'": "'"}

_PHONE = re.compile(
    r"(?<![\w+])(?:(?:\+91|0091|91|0)[ \t-]*)?"
    r"(\([6-9][0-9]{4}\)[ \t-]*[0-9]{5}|[6-9](?:[ \t.-]?[0-9]){9})(?!\w)"
)
_UPI = re.compile(r"(?<![\w.+@/-])([a-z0-9][a-z0-9._-]{0,127}@[a-z][a-z0-9-]{1,63})(?![\w-]|\.[\w-])", re.IGNORECASE | re.ASCII)
_UPI_CONTEXT = re.compile(r"\b(?:upi|vpa)\b", re.IGNORECASE)
_UPI_HANDLES = frozenset({
    "airtel", "apl", "axl", "axisbank", "fam", "hdfcbank", "ibl", "icici", "idfc",
    "jio", "kotak", "okaxis", "okhdfcbank", "okicici", "oksbi", "paytm", "pnb",
    "sbi", "slice", "upi", "ybl", "yesbank",
})
_KYC = re.compile(r"\b(?:kyc|know\s+your\s+customer)\b", re.IGNORECASE)
_LONG_NUMBER = re.compile(r"(?<![\d+])(?:\+?\d(?:[ \t.()-]{0,3}\d){5,})(?!\d)")
_LABELED_CODE = re.compile(
    r"(\b(?:otp|pin|cvv|passcode|(?:security|verification)\s+code)\b[ \t]*(?:is[ \t]+)?[:=-]?[ \t]*)\d{3,8}\b",
    re.IGNORECASE,
)
_SENTENCE_BREAK = re.compile(r"[!?;]+(?=\s|$)|(?<!\brs)\.(?=\s|$)|\n\s*\n")
_SAFETY_ADVICE = re.compile(
    r"\b(?:beware\s+of|watch\s+out\s+for|safety\s+(?:tip|advice|reminder)|red\s+flag|(?:is|are)\s+(?:a\s+)?scam|"
    r"trying\s+to\s+scam\s+you|(?:scammers?|fraudsters?)\s+(?:may|might|often|ask|tell))\b"
)
_NON_REQUEST_LEAD = re.compile(
    r"\b(?:(?:never|avoid|don['’]t|not|shouldn['’]t|won['’]t|no\s+(?:need|reason))"
    r"\s+(?:(?:ever|to|need\s+to|have\s+to|be\s+asked\s+to|(?:be\s+)?required\s+to)\s+)?|"
    r"(?:if\s+(?:you\s+(?:are|were)\s+)?(?:asked|told)|(?:anyone|someone)\s+(?:who\s+)?asks?\s+you)\s+to\s+|"
    r"(?:we|i|they|(?:the\s+|your\s+|our\s+)?(?:company|employer|team))\s+(?:(?:will|can|would|must)\s+)?)$"
)
_AMOUNT = r"(?:[₹$£€]\s*|(?:rs\.?|inr)\s*)?\d[\d,]*(?:\.\d+)?"
_UPI_PIN_REQUEST = re.compile(r"\b(?:enter|type|key\s+in|provide|share|submit|use)\s+(?:(?:your|the)\s+)?(?:upi\s+)?pin\b")
_UPI_INBOUND = re.compile(
    rf"\b(?:receive|get|claim|release|unlock)\s+(?:(?:your|the|this)\s+)?(?:{_AMOUNT}\s+)?"
    r"(?:refund|cashback|money|payment|funds|amount)\b"
)
_REFUND = re.compile(r"\b(?:refund|cashback)\b")
_REFUND_ACTION = re.compile(r"\b(?:collect\s+request|(?:receive|get|claim|release|unlock)\s+it)\b")
_REMOTE_WORK = re.compile(r"\b(?:remote|work[- ](?:from|at)[- ]home|wfh|home[- ]based|online\s+(?:work|job))\b")
_JOB_OFFER = re.compile(r"\b(?:jobs?|positions?|roles?|vacanc(?:y|ies)|hir(?:ing|ed)|employment)\b")
_JOB_COMPENSATION = re.compile(
    rf"\b(?:high[- ]pay(?:ing)?|(?:earn(?:ing)?|paying|salary(?:\s+of)?|pay\s+of)[\s:=]+"
    rf"(?:up\s+to\s+)?{_AMOUNT})\b|(?<![\w,]){_AMOUNT}\s*(?:per\s+|/|a\s+)(?:hour|day|week|month)\b"
)
_JOB_FEE_REQUEST = re.compile(
    r"\b(?:pay|send|deposit|transfer)\s+(?:us\s+)?(?:(?:an?|the|any|your)\s+)?"
    r"(?:(?:advance|up[- ]?front)\s+)?"
    rf"(?:{_AMOUNT}\s+(?:(?:for|as)\s+(?:(?:an?|the|your)\s+)?)?)?"
    r"(?:registration|training)\s+(?:fees?|charges?)\b"
)
_DIGITAL_ARREST_ORDER = re.compile(
    r"\b(?:(?:you\s+are|you['’]re)\s+(?:(?:now|being)\s+)?(?:under|placed\s+under)|"
    r"placing\s+you\s+under|this\s+is)\s+(?:a\s+)?(?:digital|virtual|online)\s+arrest\b"
)
_REPORTED_ARREST_ORDER = re.compile(
    r"\b(?:(?:someone|anyone|a\s+caller|a\s+scammer)\s+(?:says|claims|tells)|"
    r"(?:digital\s+arrest|scam|fraud)\s+(?:advisory|alert|warning))\b"
)
UPI_PIN_RULE_REASON = "Requests a UPI PIN to receive a refund or payment."
UPFRONT_JOB_RULE_REASON = "Requests an upfront registration or training fee for a paid remote job."


def _compile_keywords(terms: str) -> tuple[tuple[str, re.Pattern[str]], ...]:
    return tuple(
        (term, re.compile(r"\b" + r"\s+".join(map(re.escape, term.split())) + r"\b"))
        for term in sorted(terms.split("|"))
    )


_URGENCY = _compile_keywords(
    "urgent|immediately|now|hurry|asap|expires|expired|final warning|act now|within 24 hours"
)
_SMS_RULES = (
    (_URGENCY, 5, 15, "Urgency or pressure language detected"),
    (_compile_keywords(
        "account|bank account|login|signin|sign in|kyc|verification|verify|suspended|suspension|"
        "blocked|security|compromised"
    ), 4, 15, "Account/security-related language detected"),
    (_compile_keywords(
        "password|passcode|pin|otp|cvv|credential|username|card details|bank details"
    ), 8, 20, "Credential or sensitive-information language detected"),
    (_compile_keywords(
        "bank|payment|pay|transfer|refund|money|cash|loan|credit|debit|wallet|transaction"
    ), 3, 15, "Financial/payment-related language detected"),
    (_compile_keywords(
        "won|winner|winning|prize|reward|lucky draw|lottery|free prize|claim|cash prize"
    ), 5, 20, "Prize/reward or claim language detected"),
)


def _clean_candidate(candidate: str, opener: str, closer: str) -> str:
    if _WRAPPERS.get(opener) == closer:
        return candidate
    candidate = candidate.rstrip(".,")
    closing_pairs = {")": "("}
    if opener == "[":
        closing_pairs["]"] = "["
    if candidate and candidate[-1] in closing_pairs:
        unmatched = {
            close: candidate.count(close) - candidate.count(opening)
            for close, opening in closing_pairs.items()
        }
        end = len(candidate)
        while end and unmatched.get(candidate[end - 1], 0) > 0:
            unmatched[candidate[end - 1]] -= 1
            end -= 1
        candidate = candidate[:end]
    scheme, authority, path = _URL_PARTS.fullmatch(candidate).groups()
    if not path:
        authority = authority.rstrip("!;")
    return f"{scheme or ''}{authority}{path}"


def _upi_uri_value(candidate: str) -> str | None:
    if not candidate.lower().startswith("upi://"):
        return None
    try:
        values = parse_qs(urlsplit(candidate).query, max_num_fields=30).get("pa", [])
    except ValueError:
        return None
    if values and _UPI.fullmatch(values[0]):
        return values[0].lower()
    return None


def extract_entities(text: str, *, max_urls: int = 10) -> dict[str, list[str]]:
    """Extract distinct entities and flag common scam signals without network I/O."""
    urls: dict[str, tuple[str, bool]] = {}
    emails = {}
    upi_addresses = {}
    for match in _CANDIDATE.finditer(text):
        if email := match.group("email"):
            emails.setdefault(email.casefold(), email)
            continue
        start, end = match.span()
        candidate = _clean_candidate(match[0], text[start - 1:start], text[end:end + 1])
        if upi_address := _upi_uri_value(candidate):
            upi_addresses[upi_address] = None
        try:
            normalized, explicit_scheme = normalize_url(candidate)
        except URLValidationError:
            continue
        previous = urls.get(normalized)
        if previous is None and len(urls) < max_urls:
            urls[normalized] = (candidate, explicit_scheme)
        elif previous is not None and explicit_scheme and not previous[1]:
            urls[normalized] = (candidate, explicit_scheme)

    has_upi_context = bool(_UPI_CONTEXT.search(text))
    for match in _UPI.finditer(text):
        address = match[1].lower()
        if has_upi_context or address.split("@", 1)[1] in _UPI_HANDLES:
            upi_addresses[address] = None
    phones = dict.fromkeys(
        "+91" + re.sub(r"\D", "", match[1]) for match in _PHONE.finditer(text)
    )

    parsed_urls = [urlsplit(url) for url in urls]
    flags = []
    if any(parsed.path.lower().endswith(".apk") for parsed in parsed_urls):
        flags.append("apk_link")
    if any((parsed.hostname or "").removesuffix(".").removeprefix("www.") in SHORTENER_DOMAINS for parsed in parsed_urls):
        flags.append("url_shortener")
    lowered = text.lower()
    if _KYC.search(lowered) and any(pattern.search(lowered) for _, pattern in _URGENCY):
        flags.append("urgent_kyc")

    return {
        "urls": [candidate for candidate, _ in urls.values()],
        "phones": list(phones),
        "emails": list(emails.values()),
        "upi_ids": list(upi_addresses),
        "flags": flags,
    }


def redact_text(text: str) -> str:
    """Mask identifiers throughout the input, including links beyond the scan limit."""
    text = _CANDIDATE.sub(lambda match: "[email]" if match.group("email") else "[link]", text)
    text = _UPI.sub("[payment identifier]", text)
    text = _PHONE.sub("[phone]", text)
    text = _LABELED_CODE.sub(r"\1[code]", text)
    return _LONG_NUMBER.sub("[number]", text)


def _affirms(sentence: str, phrase: re.Pattern[str]) -> bool:
    return any(
        not _NON_REQUEST_LEAD.search(sentence[max(match.start() - 80, 0):match.start()])
        for match in phrase.finditer(sentence)
    )


def _request_sentences(text: str, request: re.Pattern[str]) -> Iterator[str]:
    for sentence in _SENTENCE_BREAK.split(text):
        if not _SAFETY_ADVICE.search(sentence) and _affirms(sentence, request):
            yield sentence


def has_digital_arrest_order(message: str) -> bool:
    """Recognise a direct claim of digital arrest for guidance selection."""
    return any(
        not _REPORTED_ARREST_ORDER.search(sentence)
        for sentence in _request_sentences(message.lower(), _DIGITAL_ARREST_ORDER)
    )


def analyze_sms_risk(message: str, phishing_probability: float, *, has_links: bool) -> dict:
    """Apply CyberGuard's SMS scoring rules to model probability and text signals."""
    text = message.lower()
    adjustments = []
    positive_signals = []

    def add_points(delta: int, reason: str) -> None:
        adjustments.append({"rule": reason, "delta": delta})

    if phishing_probability >= 0.80:
        add_points(35, "ML detector shows a high phishing probability.")
    elif phishing_probability >= 0.60:
        add_points(25, "ML detector shows an elevated phishing probability.")
    elif phishing_probability >= 0.40:
        add_points(10, "ML detector shows some phishing indicators.")
    else:
        positive_signals.append("ML detector shows a relatively low phishing probability.")

    matched_groups = []
    for keywords, points, cap, reason in _SMS_RULES:
        matched = [term for term, pattern in keywords if pattern.search(text)]
        matched_groups.append(bool(matched))
        if matched:
            add_points(min(len(matched) * points, cap), f"{reason}: {', '.join(matched)}.")

    urgency, account, credentials, finances, prize = matched_groups
    if has_links:
        add_points(15, "Message contains a web link or URL.")
    if urgency and (account or credentials or finances):
        add_points(15, "Urgency is combined with account, credential, or financial-related content.")
    if prize and has_links:
        add_points(15, "Prize/reward language is combined with a web link.")

    has_refund = _REFUND.search(text) is not None
    if _UPI_CONTEXT.search(text) and any(
        _affirms(sentence, _UPI_INBOUND) or (has_refund and _affirms(sentence, _REFUND_ACTION))
        for sentence in _request_sentences(text, _UPI_PIN_REQUEST)
    ):
        add_points(35, UPI_PIN_RULE_REASON)
    if _REMOTE_WORK.search(text) and _JOB_OFFER.search(text) and _JOB_COMPENSATION.search(text) and any(
        _request_sentences(text, _JOB_FEE_REQUEST)
    ):
        add_points(55, UPFRONT_JOB_RULE_REASON)

    raw_score = sum(step["delta"] for step in adjustments)
    score = min(raw_score, 100)
    reasons = [step["rule"] for step in adjustments]
    if raw_score > 100:
        add_points(100 - raw_score, "Score cap at 100.")
    return {
        "risk_score": score,
        "risk_level": RiskLevel.for_score(score).value,
        "score_breakdown": {"starting_score": 0, "adjustments": adjustments, "final_score": score},
        "reasons": reasons,
        "positive_signals": positive_signals,
    }
