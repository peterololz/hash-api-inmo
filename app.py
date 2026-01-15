import os
from datetime import datetime, timezone
from typing import Optional, Dict, Any

import requests
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import (
    create_engine, Column, String, DateTime, Text,
    UniqueConstraint, Index
)
from sqlalchemy.orm import declarative_base, sessionmaker

# =========================
# Config
# =========================

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
API_KEY = os.getenv("API_KEY", "").strip()

# ✅ URL FIJA del webhook de n8n (como pediste)
N8N_WEBHOOK_URL = "https://automations.aigentixsolutions.com/webhook/hash-event"

if not DATABASE_URL:
    raise RuntimeError("Missing DATABASE_URL env var")
if not API_KEY:
    raise RuntimeError("Missing API_KEY env var")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

# =========================
# Helpers
# =========================

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def require_auth(authorization: Optional[str]) -> None:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing/invalid Authorization header")
    token = authorization.split(" ", 1)[1].strip()
    if token != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")

def notify_n8n_new_hash(hash_value: str, meta: Optional[Dict[str, Any]] = None) -> None:
    """
    Dispara n8n SOLO cuando el hash es nuevo (insertado).
    No rompe la API si n8n falla.
    """
    payload = {
        "hash": hash_value,
        "is_new": True,
        "meta": meta or {},
        "ts": now_utc().isoformat(),
    }

    try:
        requests.post(
            N8N_WEBHOOK_URL,
            json=payload,
            timeout=5,
            headers={"Content-Type": "application/json"},
        )
    except Exception:
        # No tumbamos la API si n8n no responde / SSL / etc.
        pass

# =========================
# DB Models
# =========================

class HashRecord(Base):
    __tablename__ = "hashes"
    hash = Column(String(64), primary_key=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=now_utc)
    url = Column(Text, nullable=True)
    telefono = Column(String(32), nullable=True)
    portal = Column(String(64), nullable=True)
    __table_args__ = (Index("idx_hashes_telefono", "telefono"),)

class Assignment(Base):
    __tablename__ = "assignments"
    hash = Column(String(64), primary_key=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=now_utc)
    telefono = Column(String(32), nullable=True, index=True)
    inmobiliaria = Column(String(128), nullable=False)
    sheet_id_inmo = Column(String(128), nullable=False)
    url = Column(Text, nullable=True)
    __table_args__ = (
        UniqueConstraint("telefono", "hash", name="uq_assignments_phone_hash"),
        Index("idx_assignments_phone", "telefono"),
    )

Base.metadata.create_all(bind=engine)

# =========================
# Schemas
# =========================

class HashCheckIn(BaseModel):
    hash: str = Field(min_length=64, max_length=64)
    meta: Optional[Dict[str, Any]] = None

class HashInsertIn(BaseModel):
    hash: str = Field(min_length=64, max_length=64)
    url: Optional[str] = None
    telefono: Optional[str] = None
    portal: Optional[str] = None

class AssignmentInsertIn(BaseModel):
    hash: str = Field(min_length=64, max_length=64)
    telefono: Optional[str] = None
    inmobiliaria: str
    sheet_id_inmo: str
    url: Optional[str] = None

# =========================
# App
# =========================

app = FastAPI(title="Hash API (Inmobiliaria)", version="1.0.0")

@app.get("/health")
def health():
    return {"ok": True}

# ✅ CHECK: solo comprueba, NO dispara n8n
@app.post("/hashes/check")
def hashes_check(payload: HashCheckIn, authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)
    with SessionLocal() as db:
        exists = db.query(HashRecord).filter(HashRecord.hash == payload.hash).first() is not None
        return {"exists": exists}

# ✅ INSERT: si es nuevo -> inserta + dispara n8n
# ✅ si ya existía -> no dispara n8n (se para)
@app.post("/hashes/insert")
def hashes_insert(payload: HashInsertIn, authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)
    with SessionLocal() as db:
        existing = db.query(HashRecord).filter(HashRecord.hash == payload.hash).first()
        if existing:
            return {"ok": True, "already_existed": True}

        rec = HashRecord(
            hash=payload.hash,
            created_at=now_utc(),
            url=payload.url,
            telefono=payload.telefono,
            portal=payload.portal,
        )
        db.add(rec)
        db.commit()

        # ✅ SOLO si es NUEVO: dispara n8n para seguir el flujo
        notify_n8n_new_hash(
            payload.hash,
            meta={
                "url": payload.url,
                "telefono": payload.telefono,
                "portal": payload.portal,
            }
        )

        return {"ok": True, "already_existed": False}

@app.post("/assignments/insert")
def assignments_insert(payload: AssignmentInsertIn, authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)
    with SessionLocal() as db:
        existing = db.query(Assignment).filter(Assignment.hash == payload.hash).first()
        if existing:
            return {
                "ok": True,
                "already_existed": True,
                "assignment": {
                    "hash": existing.hash,
                    "telefono": existing.telefono,
                    "inmobiliaria": existing.inmobiliaria,
                    "sheet_id_inmo": existing.sheet_id_inmo,
                    "url": existing.url,
                }
            }
        rec = Assignment(
            hash=payload.hash,
            created_at=now_utc(),
            telefono=payload.telefono,
            inmobiliaria=payload.inmobiliaria,
            sheet_id_inmo=payload.sheet_id_inmo,
            url=payload.url,
        )
        db.add(rec)
        db.commit()
        return {"ok": True, "already_existed": False}

@app.get("/assignments/by-phone")
def assignments_by_phone(phone: str, authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)
    phone_norm = phone.strip().replace(" ", "").replace("+34", "")
    with SessionLocal() as db:
        rec = db.query(Assignment).filter(Assignment.telefono == phone_norm).order_by(Assignment.created_at.desc()).first()
        if not rec:
            raise HTTPException(status_code=404, detail="Assignment not found for phone")
        return {
            "hash": rec.hash,
            "telefono": rec.telefono,
            "inmobiliaria": rec.inmobiliaria,
            "sheet_id_inmo": rec.sheet_id_inmo,
            "url": rec.url,
        }

@app.get("/assignments/by-hash")
def assignments_by_hash(hash: str, authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)
    h = hash.strip()
    with SessionLocal() as db:
        rec = db.query(Assignment).filter(Assignment.hash == h).first()
        if not rec:
            raise HTTPException(status_code=404, detail="Assignment not found for hash")
        return {
            "hash": rec.hash,
            "telefono": rec.telefono,
            "inmobiliaria": rec.inmobiliaria,
            "sheet_id_inmo": rec.sheet_id_inmo,
            "url": rec.url,
        }
@app.get("/hashes/list")
def hashes_list(
    limit: int = 50,
    telefono: Optional[str] = None,
    authorization: Optional[str] = Header(default=None),
):
    require_auth(authorization)

    with SessionLocal() as db:
        q = db.query(HashRecord)

        if telefono:
            q = q.filter(HashRecord.telefono == telefono)

        rows = (
            q.order_by(HashRecord.created_at.desc())
            .limit(min(limit, 200))
            .all()
        )

        return [
            {
                "hash": r.hash,
                "created_at": r.created_at,
                "telefono": r.telefono,
                "portal": r.portal,
                "url": r.url,
            }
            for r in rows
        ]

