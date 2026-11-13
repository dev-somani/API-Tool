"""
Auth router — minimal local auth (placeholder; localhost trusted by default).
"""
from fastapi import APIRouter
router = APIRouter()

@router.get("/status")
async def auth_status():
    return {"authenticated": True, "mode": "local"}
