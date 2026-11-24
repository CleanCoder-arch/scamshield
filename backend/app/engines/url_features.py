from collections import Counter
from ipaddress import IPv4Address, IPv6Address
from math import log2
import re
from urllib.parse import urlparse, urlsplit


# These formulas and column positions follow the CyberGuard 2.0 training extractor.
FEATURE_NAMES = (
    "domain_entropy", "domain_digits", "domain_digit_ratio", "domain_vowels",
    "domain_consonants", "domain_special_chars", "query_len", "fragment_len",
    "path_depth", "has_query", "has_fragment", "has_punycode", "encoded_chars",
    "exclamation", "question_mark", "equals", "url_len", "host_len", "path_len",
    "dots", "hyphens_host", "digits", "digit_ratio", "at_symbol", "has_ip",
    "https", "subdomains", "susp_words", "shortener", "double_slash",
    "special_chars", "suffix_len", "domain_len", "domain_parts", "tld_len",
    "is_common_tld", "has_www", "path_digits", "query_digits", "domain_hyphens",
)
SHORTENER_DOMAINS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "cutt.ly", "rb.gy",
})
_SUSPICIOUS_WORDS = (
    "login", "signin", "verify", "verification", "account", "update", "secure",
    "security", "bank", "payment", "confirm", "password", "credential", "authorize",
    "authentication", "wallet", "billing", "recover", "unlock", "suspend", "limited",
    "alert", "bonus", "free", "claim",
)
_COMMON_TLDS = frozenset({
    "com", "org", "net", "edu", "gov", "in", "co", "uk", "de", "fr", "au", "ca", "jp",
})
_SCHEME_PREFIX = re.compile(r"^([a-z][a-z0-9+.-]*):", re.IGNORECASE | re.ASCII)
_HOST_WITH_PORT = re.compile(r"(\[[^\[\]]+\]|[^:\[\]]+)(?::([0-9]+))?")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.IGNORECASE | re.ASCII)
_TRAINING_IPV4 = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
_ENCODED_CHAR = re.compile(r"%[0-9a-fA-F]{2}")


class URLValidationError(ValueError):
    """The supplied text cannot be scanned as an HTTP or HTTPS URL."""


def _normalize_host(host: str) -> str:
    if host.startswith("["):
        literal, separator, zone = host[1:-1].partition("%")
        if separator and not re.fullmatch(r"25[A-Za-z0-9._~-]+", zone):
            raise URLValidationError("Invalid IPv6 zone identifier.")
        try:
            IPv6Address(literal)
        except ValueError as error:
            raise URLValidationError("Invalid IPv6 address.") from error
        return f"[{literal.lower()}{separator}{zone}]"

    try:
        ascii_host = host.encode("idna").decode("ascii").removesuffix(".")
    except UnicodeError as error:
        raise URLValidationError("Invalid hostname.") from error
    labels = ascii_host.split(".")
    if len(ascii_host) > 253 or any(not _DNS_LABEL.fullmatch(label) for label in labels):
        raise URLValidationError("Invalid hostname.")
    # Browsers can interpret a numeric final label as IPv4.
    if labels[-1].isdigit() or re.fullmatch(r"0x[0-9a-f]+", labels[-1], re.IGNORECASE):
        try:
            IPv4Address(ascii_host)
        except ValueError as error:
            raise URLValidationError("Invalid IPv4 address.") from error
    return host.lower()


def normalize_url(url: str) -> tuple[str, bool]:
    """Return the CyberGuard model input and whether its scheme was supplied."""
    if url is None:
        raise URLValidationError("URL cannot be empty.")
    value = str(url).strip()
    if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
        value = value[1:-1]
    if not value:
        raise URLValidationError("URL cannot be empty.")
    if any(char.isspace() or not char.isprintable() or char == "\\" for char in value):
        raise URLValidationError("URL contains invalid characters.")

    match = _SCHEME_PREFIX.match(value)
    explicit_scheme = False
    if match:
        scheme = match[1].lower()
        suffix = value[match.end():]
        if scheme in {"http", "https"}:
            if not suffix.startswith("//"):
                raise URLValidationError("HTTP and HTTPS require '://'.")
            explicit_scheme = True
        elif suffix.startswith("//") or ("." not in scheme and scheme != "localhost"):
            raise URLValidationError("Unsupported URL scheme.")

    if not explicit_scheme:
        value = "http://" + value.removeprefix("//")
    try:
        parsed = urlsplit(value)
    except ValueError as error:
        raise URLValidationError("Invalid hostname or IPv6 address.") from error

    userinfo, separator, authority = parsed.netloc.rpartition("@")
    if separator and (not explicit_scheme or "@" in userinfo):
        raise URLValidationError("Invalid user information in hostname.")
    authority_match = _HOST_WITH_PORT.fullmatch(authority)
    if authority_match is None:
        raise URLValidationError("Invalid hostname or port.")
    host, port = authority_match.groups()
    host = _normalize_host(host)
    if port is not None:
        port = port.lstrip("0") or "0"
        if len(port) > 5 or not 1 <= int(port) <= 65535:
            raise URLValidationError("Port must be between 1 and 65535.")
        host += ":" + port

    # Keep empty delimiters and the original spelling of the path, query, and fragment.
    authority_end = value.index("://") + 3 + len(parsed.netloc)
    normalized = f"{parsed.scheme}://{userinfo}{separator}{host}{value[authority_end:]}"
    return normalized, explicit_scheme


def extract_features(url: str) -> dict[str, int | float]:
    """Compute CyberGuard's structural features in the fitted scaler's order."""
    value = str(url).strip()
    parsed = None
    if value:
        try:
            parsed = urlparse(value if "://" in value else f"http://{value}")
        except ValueError:
            pass

    hostname = (parsed.hostname or "").lower() if parsed else ""
    path = parsed.path if parsed else ""
    query = parsed.query if parsed else ""
    fragment = parsed.fragment if parsed else ""
    domain = hostname.removeprefix("www.")
    domain_digits = sum(char.isdigit() for char in domain)
    domain_parts = sum(bool(label) for label in domain.split("."))
    entropy = 0.0
    for count in Counter(domain).values():
        probability = count / len(domain)
        entropy -= probability * log2(probability)
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    digits = sum(char.isdigit() for char in value)
    lowered = value.lower()

    return {
        "domain_entropy": entropy,
        "domain_digits": domain_digits,
        "domain_digit_ratio": domain_digits / len(domain) if domain else 0.0,
        "domain_vowels": sum(char in "aeiou" for char in domain),
        "domain_consonants": sum(char.isalpha() and char not in "aeiou" for char in domain),
        "domain_special_chars": sum(not char.isalnum() and char not in ".-" for char in domain),
        "query_len": len(query),
        "fragment_len": len(fragment),
        "path_depth": sum(bool(segment) for segment in path.split("/")),
        "has_query": int(bool(query)),
        "has_fragment": int(bool(fragment)),
        "has_punycode": int("xn--" in hostname),
        "encoded_chars": len(_ENCODED_CHAR.findall(value)) if parsed else 0,
        "exclamation": value.count("!") if parsed else 0,
        "question_mark": value.count("?") if parsed else 0,
        "equals": value.count("=") if parsed else 0,
        "url_len": len(value),
        "host_len": len(hostname),
        "path_len": len(path),
        "dots": hostname.count(".") if parsed else value.count("."),
        "hyphens_host": hostname.count("-"),
        "digits": digits,
        "digit_ratio": digits / len(value) if value else 0.0,
        "at_symbol": int("@" in value),
        "has_ip": int(bool(_TRAINING_IPV4.fullmatch(hostname))),
        "https": int(parsed.scheme.lower() == "https" if parsed else lowered.startswith("https")),
        "subdomains": max(domain_parts - 2, 0),
        "susp_words": sum(word in lowered for word in _SUSPICIOUS_WORDS) if parsed else 0,
        "shortener": int(hostname in SHORTENER_DOMAINS),
        "double_slash": int("//" in value[8:]),
        "special_chars": sum(not char.isalnum() and char not in "/:.-_?" for char in value),
        "suffix_len": len(path.rsplit(".", 1)[-1]) if "." in path else 0,
        "domain_len": len(domain),
        "domain_parts": domain_parts,
        "tld_len": len(tld),
        "is_common_tld": int(tld in _COMMON_TLDS),
        "has_www": int(hostname.startswith("www.")),
        "path_digits": sum(char.isdigit() for char in path),
        "query_digits": sum(char.isdigit() for char in query),
        "domain_hyphens": domain.count("-"),
    }
