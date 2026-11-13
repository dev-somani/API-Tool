"""
Targets router — CRUD for Target + ConsentRecord.
"""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime

from database import get_db
from models.scan import Target, ConsentRecord

router = APIRouter()


class TargetCreate(BaseModel):
    name: str
    base_url: str
    description: Optional[str] = None
    allowed_domains: list[str] = []

    @field_validator("base_url")
    @classmethod
    def validate_url(cls, v):
        if not v.startswith(("http://", "https://")):
            raise ValueError("base_url must start with http:// or https://")
        return v.rstrip("/")


class ConsentCreate(BaseModel):
    target_id: str
    tester_name: str
    tester_email: str
    authorization_statement: str
    scope_description: str


class TargetOut(BaseModel):
    id: str
    name: str
    base_url: str
    description: Optional[str]
    allowed_domains: list[str]
    created_at: datetime

    class Config:
        from_attributes = True


class ConsentOut(BaseModel):
    id: str
    target_id: str
    tester_name: str
    tester_email: str
    authorization_statement: str
    scope_description: str
    consented_at: datetime

    class Config:
        from_attributes = True


@router.get("/", response_model=list[TargetOut])
async def list_targets(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Target).order_by(Target.created_at.desc()))
    return result.scalars().all()


@router.post("/", response_model=TargetOut, status_code=201)
async def create_target(data: TargetCreate, db: AsyncSession = Depends(get_db)):
    target = Target(**data.model_dump())
    db.add(target)
    await db.flush()
    await db.refresh(target)
    return target


@router.get("/{target_id}", response_model=TargetOut)
async def get_target(target_id: str, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    return target


@router.delete("/{target_id}", status_code=204)
async def delete_target(target_id: str, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    await db.delete(target)


@router.post("/{target_id}/consent", response_model=ConsentOut, status_code=201)
async def create_consent(
    target_id: str, data: ConsentCreate, db: AsyncSession = Depends(get_db)
):
    """Create a consent record — mandatory before any scan can run."""
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(404, "Target not found")

    if data.target_id != target_id:
        raise HTTPException(400, "target_id mismatch")

    if len(data.authorization_statement.strip()) < 20:
        raise HTTPException(
            400,
            "Authorization statement must be at least 20 characters. "
            "Please confirm you own or have written permission to test this target."
        )

    consent = ConsentRecord(**data.model_dump())
    db.add(consent)
    await db.flush()
    await db.refresh(consent)
    return consent


@router.get("/{target_id}/consents", response_model=list[ConsentOut])
async def list_consents(target_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ConsentRecord).where(ConsentRecord.target_id == target_id)
        .order_by(ConsentRecord.consented_at.desc())
    )
    return result.scalars().all()
