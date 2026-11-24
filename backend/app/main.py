import asyncio
import json
import logging
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from io import BytesIO

import anyio
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from PIL import Image, UnidentifiedImageError
from pydantic import SecretStr
from python_multipart.exceptions import MultipartParseError
from starlette.datastructures import Headers, MutableHeaders, UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import MAX_TEXT_BODY_BYTES, Settings
from app.core.redis_cache import RedisCache
from app.core.scan_store import ScanStore
from app.engines.llm_vision import GeminiVision
from app.engines.ml_engine import MLEngine
from app.engines.threat_intel import ThreatIntel
from app.scan_service import ScanError, ScanService
from app.schemas import HealthResponse, ScanEvent, ScanRequest, ScanResponse


logger = logging.getLogger(__name__)
SCAN_PATH = "/api/v1/scan"
IMAGE_PATH = f"{SCAN_PATH}/image"
STREAM_PATH = f"{SCAN_PATH}/stream"
SCAN_PATHS = {SCAN_PATH, IMAGE_PATH, STREAM_PATH}
MULTIPART_OVERHEAD = 64 * 1024
IMAGE_MIME_TYPES = {"PNG": "image/png", "JPEG": "image/jpeg", "WEBP": "image/webp"}


def secret(value: SecretStr | None) -> str | None:
    return value.get_secret_value() if value else None


class ScanLimits:
    def __init__(self, app: ASGIApp, *, image_body_limit: int):
        self.app = app
        self.image_body_limit = image_body_limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] != "POST" or scope["path"] not in SCAN_PATHS:
            await self.app(scope, receive, send)
            return

        async def no_store(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["Cache-Control"] = "no-store"
            await send(message)

        image = scope["path"] == IMAGE_PATH
        limit = self.image_body_limit if image else MAX_TEXT_BODY_BYTES
        length = Headers(scope=scope).get("content-length", "")
        if length.isdecimal() and (len(length) > 12 or int(length) > limit):
            response = JSONResponse({"detail": "Scan payload is too large."}, status_code=413)
            await response(scope, receive, no_store)
            return

        limiter = scope["app"].state.scan_limiter
        try:
            limiter.acquire_nowait()
        except anyio.WouldBlock:
            response = JSONResponse(
                {"code": "scan_capacity", "detail": "Scan capacity is busy. Try again shortly."},
                status_code=503,
                headers={"Retry-After": "1"},
            )
            await response(scope, receive, no_store)
            return

        total = 0

        async def bounded_receive() -> Message:
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > limit:
                    raise HTTPException(413, "Scan payload is too large.")
            return message

        try:
            await self.app(scope, receive if image else bounded_receive, no_store)
        finally:
            limiter.release()


class UploadLimitExceeded(MultiPartException):
    pass


async def image_stream(request: Request, limit: int) -> AsyncIterator[bytes]:
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise UploadLimitExceeded("Scan payload is too large.")
        yield chunk


def check_image(content: bytes, declared_type: str | None, max_pixels: int) -> str:
    try:
        with Image.open(BytesIO(content), formats=list(IMAGE_MIME_TYPES)) as image:
            mime_type = IMAGE_MIME_TYPES[image.format]
            if mime_type != declared_type:
                raise HTTPException(415, "Image content does not match its media type.")
            if image.width * image.height > max_pixels:
                raise HTTPException(413, "Image dimensions are too large.")
            if getattr(image, "is_animated", False):
                raise HTTPException(415, "Upload a single-frame screenshot.")
            image.verify()
    except Image.DecompressionBombError:
        raise HTTPException(413, "Image dimensions are too large.") from None
    except (UnidentifiedImageError, OSError, SyntaxError, ValueError):
        raise HTTPException(415, "Upload a valid PNG, JPEG, or WebP screenshot.") from None
    return mime_type


async def read_image(request: Request, settings: Settings) -> tuple[bytes, str]:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].lower().strip()
    if content_type != "multipart/form-data":
        raise HTTPException(415, "Upload a screenshot as multipart/form-data.")
    limit = settings.max_image_bytes + MULTIPART_OVERHEAD
    parser = MultiPartParser(
        request.headers, image_stream(request, limit), max_files=1, max_fields=1, max_part_size=128
    )
    parser.spool_max_size = limit
    try:
        form = await parser.parse()
    except UploadLimitExceeded:
        raise HTTPException(413, "Scan payload is too large.") from None
    except (MultiPartException, MultipartParseError):
        raise HTTPException(422, "Invalid screenshot form.") from None
    try:
        upload = form.get("file")
        if not isinstance(upload, UploadFile) or str(form.get("redacted")).lower() != "true":
            raise HTTPException(422, "Provide file and confirm redacted=true.")
        if upload.content_type not in IMAGE_MIME_TYPES.values():
            raise HTTPException(415, "Upload a PNG, JPEG, or WebP screenshot.")
        content = await upload.read(settings.max_image_bytes + 1)
        if len(content) > settings.max_image_bytes:
            raise HTTPException(413, "Screenshot is too large.")
        declared_type = upload.content_type
    finally:
        await form.close()
    mime_type = await asyncio.to_thread(check_image, content, declared_type, settings.max_image_pixels)
    return content, mime_type


def encode_sse(event: ScanEvent) -> str:
    data = event.data.model_dump_json() if isinstance(event.data, ScanResponse) else json.dumps(event.data)
    return f"event: {event.event}\ndata: {data}\n\n"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        async with AsyncExitStack() as resources:
            transport = await resources.enter_async_context(
                httpx.AsyncClient(timeout=settings.threat_timeout_seconds, follow_redirects=False)
            )
            cache = RedisCache(
                transport,
                settings.upstash_redis_rest_url,
                secret(settings.upstash_redis_rest_token),
                secret(settings.app_api_salt),
            )
            store = ScanStore(secret(settings.database_url))
            resources.push_async_callback(store.aclose)
            ai = GeminiVision(
                api_key=secret(settings.gemini_api_key),
                timeout=settings.gemini_timeout_seconds,
                requests_per_minute=settings.gemini_requests_per_minute,
                requests_per_day=settings.gemini_requests_per_day,
            )
            resources.push_async_callback(ai.aclose)
            intel = ThreatIntel(
                transport,
                safe_browsing_api_key=secret(settings.safe_browsing_api_key),
                urlhaus_auth_key=secret(settings.urlhaus_auth_key),
                phishtank_api_key=secret(settings.phishtank_api_key),
                virustotal_api_key=secret(settings.virustotal_api_key),
                timeout=settings.threat_timeout_seconds,
                enable_whois=settings.enable_whois,
                cache=cache,
            )
            app.state.scan_limiter = anyio.CapacityLimiter(settings.max_concurrent_scans)
            app.state.scan_service = ScanService(settings, MLEngine(), intel, ai, cache, store)
            yield

    app = FastAPI(title="ScamShield API", version="1.0.0", lifespan=lifespan)
    app.add_middleware(ScanLimits, image_body_limit=settings.max_image_bytes + MULTIPART_OVERHEAD)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
        expose_headers=["Retry-After"],
    )

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request: Request, error: RequestValidationError):
        details = [{"type": item["type"]} for item in error.errors()]
        return JSONResponse(status_code=422, content={"detail": details})

    @app.exception_handler(ScanError)
    async def failed_scan(_request: Request, error: ScanError):
        headers = {"Retry-After": str(error.retry_after)} if error.retry_after else None
        return JSONResponse(
            {"code": error.code, "detail": error.detail}, status_code=error.status_code, headers=headers
        )

    def scanner(request: Request) -> ScanService:
        return request.app.state.scan_service

    def client_identity(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    @app.get("/health")
    async def health() -> HealthResponse:
        return HealthResponse()

    @app.post(SCAN_PATH)
    async def scan(payload: ScanRequest, request: Request) -> ScanResponse:
        service = scanner(request)
        await service.admit(client_identity(request), b"text\0" + payload.text.encode())
        return await service.scan(payload.text)

    @app.post(
        IMAGE_PATH,
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "multipart/form-data": {
                        "schema": {
                            "type": "object",
                            "required": ["file", "redacted"],
                            "properties": {
                                "file": {"type": "string", "format": "binary"},
                                "redacted": {
                                    "type": "boolean",
                                    "description": "Confirm sensitive details were removed before upload.",
                                },
                            },
                        }
                    }
                },
            }
        },
    )
    async def scan_image(request: Request) -> ScanResponse:
        image, mime_type = await read_image(request, settings)
        service = scanner(request)
        await service.admit(client_identity(request), b"image\0" + image)
        return await service.scan(image=image, mime_type=mime_type)

    @app.post(
        STREAM_PATH,
        response_class=StreamingResponse,
        responses={200: {"content": {"text/event-stream": {"schema": {"type": "string"}}}}},
    )
    async def stream(payload: ScanRequest, request: Request) -> StreamingResponse:
        service = scanner(request)
        await service.admit(client_identity(request), b"text\0" + payload.text.encode())

        async def events() -> AsyncIterator[str]:
            try:
                async for event in service.events(payload.text):
                    yield encode_sse(event)
            except ScanError as error:
                yield encode_sse(ScanEvent(event="error", data={"code": error.code, "detail": error.detail}))
            except Exception:
                logger.error("Streaming scan failed.")
                yield encode_sse(
                    ScanEvent(event="error", data={"code": "scan_failed", "detail": "The scan failed."})
                )

        return StreamingResponse(
            events(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"}
        )

    return app


app = create_app()
