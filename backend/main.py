"""
API VAPT Tool — Main FastAPI Application
"""
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from database import init_db
from routers import scans, targets, reports, auth as auth_router
from config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — initialise DB on startup."""
    await init_db()
    yield


app = FastAPI(
    title="API VAPT Tool",
    description="API Vulnerability Assessment & Penetration Testing Platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(auth_router.router, prefix="/api/auth", tags=["auth"])
app.include_router(targets.router, prefix="/api/targets", tags=["targets"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])

# Serve static files (built frontend)
try:
    app.mount("/", StaticFiles(directory="static", html=True), name="static")
except Exception:
    pass  # Static files not built yet


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}
