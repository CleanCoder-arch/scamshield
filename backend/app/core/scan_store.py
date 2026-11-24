from asyncio import Lock, wait_for
from datetime import datetime
from uuid import UUID

import asyncpg

from app.schemas import RiskLevel, ScamType


def _sql_enum_values(enum: type[RiskLevel] | type[ScamType]) -> str:
    return ", ".join("'" + item.value.replace("'", "''") + "'" for item in enum)


_CREATE_TABLE = f"""
CREATE TABLE IF NOT EXISTS public.scan_metadata (
    scan_id UUID PRIMARY KEY,
    risk_score SMALLINT NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    risk_level TEXT NOT NULL CHECK (risk_level IN ({_sql_enum_values(RiskLevel)})),
    scam_type TEXT NOT NULL CHECK (scam_type IN ({_sql_enum_values(ScamType)})),
    created_at TIMESTAMPTZ NOT NULL
)
"""
_INSERT_METADATA = """
INSERT INTO public.scan_metadata (scan_id, risk_score, risk_level, scam_type, created_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (scan_id) DO NOTHING
"""


class ScanStoreUnavailableError(RuntimeError):
    pass


class ScanStore:
    """Optional PostgreSQL writer with an explicit metadata-only contract."""

    def __init__(self, database_url: str | None, *, timeout: float = 3.0) -> None:
        self._database_url = database_url
        self._timeout = timeout
        self._pool = None
        self._pool_lock = Lock()

    async def _get_pool(self) -> asyncpg.Pool:
        async with self._pool_lock:
            if self._pool is None:
                pool = await asyncpg.create_pool(
                    dsn=self._database_url,
                    min_size=1,
                    max_size=2,
                    timeout=self._timeout,
                    max_inactive_connection_lifetime=60,
                    statement_cache_size=0,
                )
                try:
                    await pool.execute(_CREATE_TABLE, timeout=self._timeout)
                except BaseException:
                    pool.terminate()
                    raise
                self._pool = pool
            return self._pool

    async def save(
        self,
        *,
        scan_id: UUID,
        risk_score: int,
        risk_level: RiskLevel,
        scam_type: ScamType,
        created_at: datetime,
    ) -> None:
        if (
            not isinstance(scan_id, UUID)
            or type(risk_score) is not int
            or not 0 <= risk_score <= 100
            or not isinstance(risk_level, RiskLevel)
            or not isinstance(scam_type, ScamType)
            or not isinstance(created_at, datetime)
            or created_at.utcoffset() is None
        ):
            raise ValueError("Invalid anonymized scan metadata.")
        if not self._database_url:
            return

        try:
            pool = await wait_for(self._get_pool(), timeout=self._timeout)
            await wait_for(
                pool.execute(
                    _INSERT_METADATA,
                    scan_id,
                    risk_score,
                    risk_level.value,
                    scam_type.value,
                    created_at,
                    timeout=self._timeout,
                ),
                timeout=self._timeout,
            )
        except (asyncpg.PostgresError, asyncpg.InterfaceError, OSError, TimeoutError, ValueError):
            raise ScanStoreUnavailableError("Scan metadata storage is unavailable.") from None

    async def aclose(self) -> None:
        async with self._pool_lock:
            if self._pool is not None:
                pool, self._pool = self._pool, None
                try:
                    await wait_for(pool.close(), timeout=self._timeout)
                except TimeoutError:
                    pool.terminate()
