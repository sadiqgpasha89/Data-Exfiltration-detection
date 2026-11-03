"""FastAPI Main Application Entry Point."""

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
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
from src.core.telemetry import logger
from src.data_engineering.ingestion import ingestion_service


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-load initial seed telemetry
    logger.info("platform_startup", env=settings.ENVIRONMENT, app_name=settings.APP_NAME)
    events = ingestion_service.load_seed_telemetry()
    logger.info("seed_telemetry_loaded", count=len(events))
    yield
    logger.info("platform_shutdown")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files & templates
static_dir = Path(__file__).resolve().parent.parent / "frontend" / "static"
templates_dir = Path(__file__).resolve().parent.parent / "frontend" / "templates"

if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

templates = Jinja2Templates(directory=str(templates_dir))

# Mount API routers
app.include_router(telemetry_router, prefix="/api/v1")
app.include_router(evaluate_router, prefix="/api/v1")
app.include_router(incidents_router, prefix="/api/v1")
app.include_router(remediation_router, prefix="/api/v1")
app.include_router(metrics_router, prefix="/api/v1")
app.include_router(drift_router, prefix="/api/v1")
app.include_router(simulator_router, prefix="/api/v1")


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """Serves the Cyber SOC Cockpit frontend interface."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"settings": settings},
    )


@app.get("/healthz")
def health_check():
    return {
        "status": "HEALTHY",
        "hybrid_topology": {
            "openstack_edge": "ONLINE",
            "gcp_enclave": "CONNECTED",
            "worm_ledger": "SYNCED",
        },
    }
