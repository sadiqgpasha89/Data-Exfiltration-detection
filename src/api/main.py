"""FastAPI Main Application Entry Point."""

import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.api.routes.drift import router as drift_router
from src.api.routes.evaluate import router as evaluate_router
from src.api.routes.incidents import router as incidents_router
from src.api.routes.metrics import router as metrics_router
from src.api.routes.remediation import router as remediation_router
from src.api.routes.simulator import router as simulator_router
from src.api.routes.telemetry import router as telemetry_router
from src.core.config import settings
from src.core.crypto_audit import worm_ledger
from src.core.telemetry import logger
from src.data_engineering.graph_builder import iam_graph_builder
from src.data_engineering.ingestion import ingestion_service
from src.datascience.tier1_rules import reputation_filter
from src.evaluation.benchmark import benchmark_cache


@asynccontextmanager
async def lifespan(app: FastAPI):
    problems = settings.production_problems()
    if problems:  # refuse to serve production traffic with an unsafe configuration
        for problem in problems:
            logger.error("unsafe_configuration", problem=problem)
        raise RuntimeError("Refusing to start in production: " + "; ".join(problems))

    logger.info("platform_startup", env=settings.APP_ENV, app_name=settings.APP_NAME, version=settings.APP_VERSION,
                auto_remediation=settings.AUTO_REMEDIATION_MODE, auth_disabled=settings.AUTH_DISABLED, simulator=settings.simulator_enabled)
    if settings.AUTH_DISABLED:
        logger.warning("authentication_disabled", detail="AUTH_DISABLED is set: every caller is an administrator. Development only.")
    if settings.simulator_enabled:
        logger.info("seed_telemetry_loaded", count=len(ingestion_service.load_seed_telemetry()))
    if settings.BENCHMARK_ON_STARTUP:
        benchmark_cache.warm()
    yield
    logger.info("platform_shutdown")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs" if settings.simulator_enabled else None,  # the interactive docs are for development
    redoc_url=None,
    openapi_url="/openapi.json" if settings.simulator_enabled else None,
)

# CORS: only the origins you list. Credentials are not used (callers send an API key header), so no wildcard-with-credentials.
if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization", "X-API-Key"],
    )


class BodySizeLimitMiddleware:
    """Rejects request bodies larger than MAX_BODY_BYTES, whether or not the client declares a Content-Length."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = settings.MAX_BODY_BYTES
        declared = dict(scope["headers"]).get(b"content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            return await self._too_large(scope, receive, send)

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _BodyTooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            await self._too_large(scope, receive, send)

    @staticmethod
    async def _too_large(scope, receive, send):
        response = JSONResponse({"detail": "Request body too large"}, status_code=413)
        await response(scope, receive, send)


class _BodyTooLarge(Exception):
    pass


app.add_middleware(BodySizeLimitMiddleware)


@app.middleware("http")
async def request_context(request: Request, call_next):
    """Adds a request id and security headers, and logs one structured line per request (never the body)."""
    request_id = request.headers.get("x-request-id", "")[:64] or uuid.uuid4().hex
    request.state.request_id = request_id
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("unhandled_error", request_id=request_id, path=request.url.path)
        response = JSONResponse({"detail": "Internal server error", "request_id": request_id}, status_code=500)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    )
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    logger.info("request", request_id=request_id, method=request.method, path=request.url.path, status=response.status_code,
                ms=round((time.perf_counter() - started) * 1000, 2))
    return response


# Static files & templates
static_dir = Path(__file__).resolve().parent.parent / "frontend" / "static"
templates_dir = Path(__file__).resolve().parent.parent / "frontend" / "templates"

if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

templates = Jinja2Templates(directory=str(templates_dir))

# Mount API routers
for router in (telemetry_router, evaluate_router, incidents_router, remediation_router, metrics_router, drift_router, simulator_router):
    app.include_router(router, prefix="/api/v1")


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """Serves the Cyber SOC Cockpit frontend interface. The page itself holds no data; the API calls it makes need an API key."""
    return templates.TemplateResponse(request=request, name="index.html", context={"settings": settings})


@app.get("/healthz")
def liveness():
    """Liveness: the process is up. It says nothing about dependencies (see /readyz)."""
    return {"status": "ok", "version": settings.APP_VERSION}


@app.get("/readyz")
def readiness():
    """Readiness: the checks that decide whether this instance should receive traffic. Returns 503 with the failing checks."""
    ledger = worm_ledger.verify_chain()
    checks = {
        "audit_ledger_intact": ledger["valid"],
        "iam_directory_loaded": iam_graph_builder.graph.number_of_nodes() > 0,
        "threat_intel_loaded": bool(reputation_filter.malicious_ips or reputation_filter.malicious_domains),
        "ledger_durable": bool(worm_ledger.path),
    }
    required = ("audit_ledger_intact", "iam_directory_loaded", "threat_intel_loaded")
    ready = all(checks[name] for name in required)
    body = {"status": "ready" if ready else "not_ready", "checks": checks,
            "notes": [] if checks["ledger_durable"] else ["audit ledger is in memory only (LEDGER_PATH is not set)"]}
    return JSONResponse(body, status_code=200 if ready else 503)
