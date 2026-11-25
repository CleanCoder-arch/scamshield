from collections import deque
from hashlib import sha256
from hmac import new as new_hmac
from secrets import token_bytes
from time import monotonic, time
from typing import Literal
from uuid import uuid4

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError


class CachedVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    status: Literal["hit", "clear"]
    domain_age_days: int | None = Field(default=None, ge=0)


_UNAVAILABLE = object()
_MAX_LOCAL_KEYS = 4096
_SLIDING_WINDOW = """
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[3]) then
    return 0
end
redis.call('ZADD', KEYS[1], now, ARGV[4])
redis.call('PEXPIRE', KEYS[1], window)
return 1
"""


class RedisCache:
    """Keep identifiers and payloads out of Upstash keys and cached values."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        url: str | None,
        token: str | None,
        salt: str | None,
        *,
        timeout: float = 2.0,
    ) -> None:
        self._client = client
        self._url = url if url and url.startswith("https://") else ""
        self._token = token
        self._shared = bool(self._url and token and salt)
        self._key = salt.encode() if salt else token_bytes(32)
        self._timeout = timeout
        self._retry_at = 0.0
        self._rate_history: dict[str, deque[float]] = {}
        self._claims: dict[str, float] = {}

    def _digest_key(self, namespace: str, *parts: bytes) -> str:
        digest = new_hmac(self._key, namespace.encode(), sha256)
        for part in parts:
            digest.update(len(part).to_bytes(8, "big"))
            digest.update(part)
        return f"scamshield:v1:{namespace}:{digest.hexdigest()}"

    async def _command(self, *command: str | int) -> object:
        if not self._shared or monotonic() < self._retry_at:
            return _UNAVAILABLE
        try:
            response = await self._client.post(
                self._url,
                headers={"Authorization": f"Bearer {self._token}"},
                json=command,
                timeout=self._timeout,
                follow_redirects=False,
            )
            response.raise_for_status()
            body = response.json()
            if isinstance(body, dict) and "result" in body and "error" not in body:
                return body["result"]
        except (httpx.HTTPError, httpx.InvalidURL, ValueError):
            pass
        self._retry_at = monotonic() + 5.0
        return _UNAVAILABLE

    async def allow_scan(self, identity: str, *, limit: int, window_seconds: int) -> bool:
        if limit <= 0 or window_seconds <= 0:
            return False
        key = self._digest_key(
            "rate", identity.encode(), str(limit).encode(), str(window_seconds).encode()
        )
        now = monotonic()
        history = self._rate_history.get(key)
        if history is None:
            if len(self._rate_history) >= _MAX_LOCAL_KEYS:
                self._rate_history = {
                    item: hits
                    for item, hits in self._rate_history.items()
                    if hits[-1] > now
                }
                if len(self._rate_history) >= _MAX_LOCAL_KEYS:
                    return False
            history = self._rate_history.setdefault(key, deque())
        while history and history[0] <= now:
            history.popleft()
        if len(history) >= limit:
            return False
        history.append(now + window_seconds)

        result = await self._command(
            "EVAL",
            _SLIDING_WINDOW,
            1,
            key,
            int(time() * 1000),
            window_seconds * 1000,
            limit,
            uuid4().hex,
        )
        return result is _UNAVAILABLE or result == 1

    async def claim_scan(self, identity: str, payload: bytes, *, ttl_seconds: int) -> bool:
        if ttl_seconds <= 0:
            return True
        key = self._digest_key("dedup", identity.encode(), payload)
        now = monotonic()
        if self._claims.get(key, 0.0) > now:
            return False
        if len(self._claims) >= _MAX_LOCAL_KEYS:
            self._claims = {
                item: deadline for item, deadline in self._claims.items() if deadline > now
            }
            if len(self._claims) >= _MAX_LOCAL_KEYS:
                # The local cache is bounded. Exhausting it does not make a new input a duplicate.
                del self._claims[next(iter(self._claims))]
        self._claims[key] = now + ttl_seconds

        result = await self._command("SET", key, "1", "NX", "EX", ttl_seconds)
        return result is _UNAVAILABLE or result == "OK"

    async def get_verdict(
        self, provider: str, scope: Literal["url", "domain"], indicator: str
    ) -> CachedVerdict | None:
        key = self._digest_key("verdict", provider.encode(), scope.encode(), indicator.encode())
        result = await self._command("GET", key)
        if isinstance(result, str) and len(result) <= 512:
            try:
                return CachedVerdict.model_validate_json(result)
            except ValidationError:
                pass
        return None

    async def put_verdict(
        self,
        provider: str,
        scope: Literal["url", "domain"],
        indicator: str,
        verdict: CachedVerdict,
        *,
        ttl_seconds: int,
    ) -> None:
        if ttl_seconds <= 0:
            return
        key = self._digest_key("verdict", provider.encode(), scope.encode(), indicator.encode())
        payload = CachedVerdict(status=verdict.status, domain_age_days=verdict.domain_age_days)
        await self._command(
            "SET", key, payload.model_dump_json(exclude_none=True), "EX", ttl_seconds
        )
