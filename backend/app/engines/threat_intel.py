import asyncio
import re
from base64 import urlsafe_b64encode
from collections import deque
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timezone
from ipaddress import ip_address
from time import monotonic
from typing import Literal
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

import httpx
import tldextract

from app.core.redis_cache import CachedVerdict, RedisCache

Scope = Literal["url", "domain"]
ThreatStatus = Literal["hit", "clear", "unavailable", "skipped"]

_DAY = 86_400
_IANA_RDAP = "https://data.iana.org/rdap/dns.json"
_SUFFIXES = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
_DNS_NAME = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}\Z", re.ASCII)
_SENSITIVE_KEY = re.compile(
    r"(?:auth|credential|password|passcode|token|session|cookie|secret|signature|"
    r"e-?mail|phone|mobile|account|upi|vpa|aadhaar|pan(?:card)?|otp|api.?key|reset|sso|saml)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE = re.compile(
    r"[\w.+-]+@[\w.-]+|(?<!\d)(?:\+?91[- .]?)?[6-9](?:[- .]?\d){9}(?!\d)", re.IGNORECASE
)
_OPAQUE_SEGMENT = re.compile(r"(?=.*[0-9])[a-zA-Z0-9_=-]{24,}\Z")
_CACHE_DURATION = re.compile(r"(?:\d{1,9})(?:\.\d{1,9})?s\Z")


@dataclass(frozen=True, slots=True)
class ThreatFinding:
    """A clear URL check means the provider found no match in its data."""

    provider: str
    scope: Scope
    indicator: str
    status: ThreatStatus
    domain_age_days: int | None = None


@dataclass(frozen=True, slots=True)
class _Verdict:
    status: ThreatStatus
    ttl_seconds: int = 0
    domain_age_days: int | None = None


_Lookup = Callable[[str], Awaitable[_Verdict]]


def _candidate(url: str) -> tuple[str, str | None] | None:
    """Prepare a URL as lookup data and a registrable domain for domain age."""
    value = url.strip()
    if not value or len(value) > 4096 or re.search(r"[\x00-\x20\x7f\\]", value):
        return None
    if value.startswith("//"):
        value = "http:" + value
    elif "://" not in value:
        value = "http://" + value

    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None:
            return None
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii")
        if len(host) > 253:
            return None
        port = parsed.port
        query = unquote(parsed.query, errors="strict")
        path = unquote(unquote(parsed.path, errors="strict"), errors="strict")
        parameters = parse_qsl(query, keep_blank_values=True, max_num_fields=80)
    except (ValueError, UnicodeError):
        return None

    sensitive_path = any(
        _SENSITIVE_KEY.fullmatch(segment) or _OPAQUE_SEGMENT.fullmatch(segment)
        for segment in path.split("/")
    )
    sensitive_query = any(
        _SENSITIVE_KEY.search(key) or _OPAQUE_SEGMENT.fullmatch(item)
        for key, item in parameters
    )
    if sensitive_path or sensitive_query or _SENSITIVE_VALUE.search(f"{path}?{unquote(query)}"):
        return None

    try:
        address = ip_address(host)
    except ValueError:
        if not _DNS_NAME.fullmatch(host):
            return None
        result = _SUFFIXES(host)
        domain = result.top_domain_under_public_suffix
        if not domain:
            return None
    else:
        if not address.is_global or address.is_multicast or "%" in host:
            return None
        host = f"[{address}]" if address.version == 6 else str(address)
        domain = None

    authority = f"{host}:{port}" if port is not None else host
    return urlunsplit((parsed.scheme, authority, parsed.path or "/", parsed.query, "")), domain


class ThreatIntel:
    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        safe_browsing_api_key: str | None = None,
        urlhaus_auth_key: str | None = None,
        phishtank_api_key: str | None = None,
        virustotal_api_key: str | None = None,
        timeout: float = 4.0,
        concurrency: int = 8,
        cache: RedisCache | None = None,
        enable_whois: bool = True,
    ) -> None:
        self._client = client
        self._safe_browsing_api_key = safe_browsing_api_key
        self._urlhaus_auth_key = urlhaus_auth_key
        self._phishtank_api_key = phishtank_api_key
        self._virustotal_api_key = virustotal_api_key
        self._timeout = timeout
        self._slots = asyncio.Semaphore(concurrency)
        self._cache = cache
        self._enable_whois = enable_whois
        self._virus_total_requests: deque[float] = deque()
        self._registry_servers: dict[str, str] = {}
        self._registry_expires = 0.0
        self._registry_lock = asyncio.Lock()

    async def lookup(self, urls: Sequence[str]) -> list[ThreatFinding]:
        candidates = dict.fromkeys(candidate for url in urls if (candidate := _candidate(url)))
        domains = dict.fromkeys(domain for _, domain in candidates if domain)
        url_checks = (
            ("safe_browsing", self._safe_browsing if self._safe_browsing_api_key else None),
            ("urlhaus", self._urlhaus if self._urlhaus_auth_key else None),
            ("phishtank", self._phishtank if self._phishtank_api_key else None),
            ("virustotal", self._virustotal if self._virustotal_api_key else None),
        )
        checks = [
            self._lookup_one(provider, "url", url, lookup)
            for url, _ in candidates
            for provider, lookup in url_checks
        ]
        checks.extend(
            self._lookup_one("whois", "domain", domain, self._domain_age if self._enable_whois else None)
            for domain in domains
        )
        return list(await asyncio.gather(*checks))

    async def _lookup_one(
        self, provider: str, scope: Scope, indicator: str, lookup: _Lookup | None
    ) -> ThreatFinding:
        if lookup is None:
            return ThreatFinding(provider, scope, indicator, "skipped")
        try:
            async with asyncio.timeout(self._timeout):
                async with self._slots:
                    if self._cache is not None:
                        cached = await self._cache.get_verdict(provider, scope, indicator)
                        if cached is not None:
                            return ThreatFinding(provider, scope, indicator, cached.status, cached.domain_age_days)
                    verdict = await lookup(indicator)
        except (TimeoutError, httpx.HTTPError, httpx.InvalidURL, ValueError, TypeError, KeyError):
            return ThreatFinding(provider, scope, indicator, "unavailable")
        if self._cache is not None and verdict.ttl_seconds and verdict.status in {"hit", "clear"}:
            await self._cache.put_verdict(
                provider,
                scope,
                indicator,
                CachedVerdict(status=verdict.status, domain_age_days=verdict.domain_age_days),
                ttl_seconds=verdict.ttl_seconds,
            )
        return ThreatFinding(provider, scope, indicator, verdict.status, verdict.domain_age_days)

    async def _request(self, method: str, endpoint: str, **kwargs) -> httpx.Response:
        return await self._client.request(
            method, endpoint, timeout=self._timeout, follow_redirects=False, **kwargs
        )

    @staticmethod
    def _object(response: httpx.Response) -> dict:
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("Expected a JSON object from provider")
        return payload

    async def _safe_browsing(self, url: str) -> _Verdict:
        response = await self._request(
            "POST",
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            headers={"x-goog-api-key": self._safe_browsing_api_key},
            json={
                "client": {"clientId": "scamshield", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
        )
        payload = self._object(response)
        matches = payload["matches"] if payload else []
        if not isinstance(matches, list) or any(not isinstance(match, dict) for match in matches):
            raise ValueError("Invalid Safe Browsing matches")
        if not matches:
            return _Verdict("clear")
        durations = [match.get("cacheDuration") for match in matches]
        seconds = max(
            (float(item[:-1]) for item in durations if isinstance(item, str) and _CACHE_DURATION.fullmatch(item)),
            default=0,
        )
        return _Verdict("hit", int(min(seconds, _DAY)))

    async def _urlhaus(self, url: str) -> _Verdict:
        response = await self._request(
            "POST",
            "https://urlhaus-api.abuse.ch/v1/url/",
            headers={"Auth-Key": self._urlhaus_auth_key},
            data={"url": url},
        )
        status = self._object(response).get("query_status")
        if status == "ok":
            return _Verdict("hit", 3_600)
        if status == "no_results":
            return _Verdict("clear", 900)
        return _Verdict("unavailable")

    async def _phishtank(self, url: str) -> _Verdict:
        response = await self._request(
            "POST",
            "https://checkurl.phishtank.com/checkurl/",
            headers={"User-Agent": "phishtank/scamshield"},
            data={"url": url, "format": "json", "app_key": self._phishtank_api_key},
        )
        result = self._object(response)["results"]
        if not isinstance(result, dict) or "in_database" not in result:
            return _Verdict("unavailable")
        confirmed = all(result.get(key) in (True, "y", "true") for key in ("in_database", "verified", "valid"))
        return _Verdict("hit", 3_600) if confirmed else _Verdict("clear", 900)

    async def _virustotal(self, url: str) -> _Verdict:
        now = monotonic()
        while self._virus_total_requests and self._virus_total_requests[0] <= now - _DAY:
            self._virus_total_requests.popleft()
        if len(self._virus_total_requests) >= 500 or (
            len(self._virus_total_requests) >= 4 and self._virus_total_requests[-4] > now - 60
        ):
            return _Verdict("skipped")
        self._virus_total_requests.append(now)
        identifier = urlsafe_b64encode(url.encode()).decode().rstrip("=")
        response = await self._request(
            "GET", f"https://www.virustotal.com/api/v3/urls/{identifier}",
            headers={"x-apikey": self._virustotal_api_key},
        )
        if response.status_code == 404:
            return _Verdict("clear", 900)
        stats = self._object(response)["data"]["attributes"]["last_analysis_stats"]
        if not isinstance(stats, dict) or type(stats.get("malicious")) is not int:
            return _Verdict("unavailable")
        return _Verdict("hit", 3_600) if stats["malicious"] > 0 else _Verdict("clear", 900)

    async def _domain_age(self, domain: str) -> _Verdict:
        # RDAP is the current registry protocol for the WHOIS domain-age check.
        servers = await self._rdap_registry()
        endpoint = servers.get(domain.rsplit(".", 1)[-1])
        if endpoint is None:
            return _Verdict("unavailable")
        response = await self._request("GET", f"{endpoint}domain/{domain}")
        events = self._object(response).get("events", [])
        if not isinstance(events, list):
            return _Verdict("unavailable")
        ages = []
        for event in events:
            if not isinstance(event, dict) or event.get("eventAction") != "registration":
                continue
            event_date = event.get("eventDate")
            if not isinstance(event_date, str):
                continue
            try:
                registered = date.fromisoformat(event_date[:10])
            except ValueError:
                continue
            age_days = (datetime.now(timezone.utc).date() - registered).days
            if age_days >= 0:
                ages.append(age_days)
        return _Verdict("clear", _DAY, max(ages)) if ages else _Verdict("unavailable")

    async def _rdap_registry(self) -> dict[str, str]:
        async with self._registry_lock:
            if monotonic() < self._registry_expires:
                return self._registry_servers
            response = await self._request("GET", _IANA_RDAP)
            services = self._object(response)["services"]
            if not isinstance(services, list):
                raise ValueError("Invalid RDAP registry services")
            servers = {}
            for service in services:
                if not isinstance(service, list) or len(service) != 2:
                    continue
                suffixes, endpoints = service
                if not isinstance(suffixes, list) or not isinstance(endpoints, list):
                    continue
                for endpoint in endpoints:
                    if isinstance(endpoint, str) and self._valid_rdap_endpoint(endpoint):
                        valid_suffixes = (suffix for suffix in suffixes if isinstance(suffix, str))
                        servers.update(dict.fromkeys(valid_suffixes, endpoint.rstrip("/") + "/"))
                        break
            self._registry_servers = servers
            self._registry_expires = monotonic() + _DAY
            return servers

    @staticmethod
    def _valid_rdap_endpoint(endpoint: str) -> bool:
        if re.search(r"[\x00-\x20\x7f\\]", endpoint):
            return False
        try:
            url = urlsplit(endpoint)
            port = url.port
        except ValueError:
            return False
        return bool(
            url.scheme == "https"
            and url.hostname
            and _DNS_NAME.fullmatch(url.hostname)
            and _SUFFIXES(url.hostname).top_domain_under_public_suffix
            and url.username is None
            and port in {None, 443}
            and not (url.query or url.fragment)
        )
