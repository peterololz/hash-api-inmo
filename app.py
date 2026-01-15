import os
import re
import hashlib
import unicodedata
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
from sqlalchemy.exc import IntegrityError

# =========================
# Config
# =========================

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
API_KEY = os.getenv("API_KEY", "").strip()

# ✅ URL FIJA del webhook de n8n
N8N_WEBHOOK_URL = "https://automations.aigentixsolutions.com/webhook/hash-event"

if not DATABASE_URL:
    raise RuntimeError("Missing DATABASE_URL env var")
if not API_KEY:
    raise RuntimeError("Missing API_KEY env var")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

# =========================
# Helpers (time + auth)
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
        pass

# =========================
# Normalization helpers
# =========================

_HASH_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)

def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def normalize_text_basic(value: Optional[str]) -> Optional[str]:
    """Trim + lowercase + remove accents + collapse spaces."""
    if value is None:
        return None
    s = str(value).strip().lower()
    if not s:
        return None
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = re.sub(r"\s+", " ", s)
    return s

def normalize_portal(portal: Optional[str]) -> Optional[str]:
    """Portal: lowercase, remove accents, remove spaces."""
    s = normalize_text_basic(portal)
    if s is None:
        return None
    s = s.replace(" ", "")
    return s or None

def normalize_url(url: Optional[str]) -> Optional[str]:
    """
    URL canonical:
      - lowercase
      - remove fragment (#...)
      - remove common tracking params utm_*, fbclid, gclid
      - remove trailing slash
    """
    if url is None:
        return None
    u = str(url).strip()
    if not u:
        return None
    u = u.lower()
    u = u.split("#", 1)[0]

    # remove tracking parameters (utm_*, fbclid, gclid)
    u = re.sub(r"([?&])(utm_[^=]+|fbclid|gclid)=[^&]*", r"\1", u)
    u = u.replace("?&", "?")
    u = re.sub(r"[?&]+$", "", u)
    u = re.sub(r"&{2,}", "&", u)
    u = re.sub(r"\?{2,}", "?", u)

    if len(u) > 8:
        u = u.rstrip("/")
    return u or None

def normalize_phone_es(phone: Optional[str]) -> Optional[str]:
    """
    Spain canonical phone:
      - keep digits and '+'
      - 0034 -> +34
      - +34xxxxx -> 34xxxxx
      - if 9 digits -> prepend '34'
      - final format: '34XXXXXXXXX' (no '+')
    """
    if phone is None:
        return None
    p = str(phone).strip()
    if not p:
        return None

    p = re.sub(r"[^\d+]", "", p)

    if p.startswith("00"):
        p = "+" + p[2:]

    if p.startswith("+34"):
        p = "34" + p[3:]

    if re.fullmatch(r"\d{9}", p):
        p = "34" + p

    p = p.lstrip("+")
    p = re.sub(r"\D", "", p)

    if len(p) < 9:
        return None

    return p

def normalize_hash(hash_value: str) -> str:
    """Normalize and validate sha256 hex string."""
    h = str(hash_value).strip().lower()
    h = re.sub(r"\s+", "", h)
    if not _HASH_RE.fullmatch(h):
        raise HTTPException(status_code=422, detail="Invalid hash: must be 64 hex chars (sha256)")
    return h

def build_canonical_and_hash(
    *,
    portal: Optional[str],
    url: Optional[str],
    telefono: Optional[str],
    titulo: Optional[str],
    ciudad: Optional[str],
) -> Dict[str, Optional[str]]:
    """
    PRO canonical:
      - Siempre incluye portal
      - Preferimos URL si existe (suele ser única)
      - Añadimos telefono si existe
      - Añadimos ciudad y un título normalizado (recortado) para estabilidad si faltan cosas
    """
    portal_n = normalize_portal(portal)
    url_n = normalize_url(url)
    tel_n = normalize_phone_es(telefono)
    titulo_n = normalize_text_basic(titulo)
    ciudad_n = normalize_text_basic(ciudad)

    if not portal_n:
        raise HTTPException(status_code=422, detail="portal is required")

    # No obligamos a URL, pero si no hay URL, exigimos algo para distinguir anuncios.
    if not url_n and not (tel_n or titulo_n):
        raise HTTPException(
            status_code=422,
            detail="Provide at least url OR (telefono or titulo) to build a stable hash",
        )

    # recorte del título para evitar hashes distintos por textos larguísimos
    titulo_short = (titulo_n[:120] if titulo_n else None)

    parts = [
        f"portal={portal_n}",
        f"url={url_n or ''}",
        f"tel={tel_n or ''}",
        f"city={ciudad_n or ''}",
        f"title={titulo_short or ''}",
    ]
    canonical = "|".join(parts)
    h = sha256_hex(canonical)

    return {
        "hash": h,
        "canonical": canonical,
        "portal": portal_n,
        "url": url_n,
        "telefono": tel_n,
        "titulo": titulo_short,
        "ciudad": ciudad_n,
    }

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

# --- Compat (antiguo): n8n manda hash ya calculado ---
class HashCheckIn(BaseModel):
    hash: str = Field(min_length=64, max_length=128)

class HashInsertIn(BaseModel):
    hash: str = Field(min_length=64, max_length=128)
    url: Optional[str] = None
    telefono: Optional[str] = None
    portal: Optional[str] = None

# --- PRO: API calcula hash a partir de inputs ---
class HashAutoIn(BaseModel):
    portal: str
    url: Optional[str] = None
    telefono: Optional[str] = None
    titulo: Optional[str] = None
    ciudad: Optional[str] = None

class AssignmentInsertIn(BaseModel):
    hash: str = Field(min_length=64, max_length=128)
    telefono: Optional[str] = None
    inmobiliaria: str
    sheet_id_inmo: str
    url: Optional[str] = None

# =========================
# App
# =========================

app = FastAPI(title="Hash API (Inmobiliaria)", version="2.0.0-pro")

@app.get("/health")
def health():
    return {"ok": True}

# =========================
# HASHES (compat)
# =========================

@app.post("/hashes/check")
def hashes_check(payload: HashCheckIn, authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)
    h = normalize_hash(payload.hash)
    with SessionLocal() as db:
        exists = db.query(HashRecord).filter(HashRecord.hash == h).first() is not None
        return {"exists": exists, "hash": h}

@app.post("/hashes/insert")
def hashes_insert(payload: HashInsertIn, authorization: Optional[str] = Header(default=None)):
    """
    COMPAT: inserta usando hash ya calculado (pero lo normaliza/valida y normaliza url/telefono/portal).
    """
    require_auth(authorization)

    h = normalize_hash(payload.hash)
    url_norm = normalize_url(payload.url)
    tel_norm = normalize_phone_es(payload.telefono)
    portal_norm = normalize_portal(payload.portal)

    with SessionLocal() as db:
        existing = db.query(HashRecord).filter(HashRecord.hash == h).first()
        if existing:
            return {"ok": True, "already_existed": True, "hash": h}

        rec = HashRecord(
            hash=h,
            created_at=now_utc(),
            url=url_norm,
            telefono=tel_norm,
            portal=portal_norm,
        )
        db.add(rec)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return {"ok": True, "already_existed": True, "hash": h}

        notify_n8n_new_hash(
            h,
            meta={
                "url": url_norm,
                "telefono": tel_norm,
                "portal": portal_norm,
            }
        )

        return {"ok": True, "already_existed": False, "hash": h}

# =========================
# HASHES (PRO)
# =========================

@app.post("/hashes/check-auto")
def hashes_check_auto(payload: HashAutoIn, authorization: Optional[str] = Header(default=None)):
    """
    PRO: calcula hash internamente (normaliza inputs) y comprueba duplicado.
    """
    require_auth(authorization)

    built = build_canonical_and_hash(
        portal=payload.portal,
        url=payload.url,
        telefono=payload.telefono,
        titulo=payload.titulo,
        ciudad=payload.ciudad,
    )
    h = built["hash"]

    with SessionLocal() as db:
        exists = db.query(HashRecord).filter(HashRecord.hash == h).first() is not None

    return {
        "exists": exists,
        "hash": h,
        "canonical": built["canonical"],
        "normalized": {
            "portal": built["portal"],
            "url": built["url"],
            "telefono": built["telefono"],
            "titulo": built["titulo"],
            "ciudad": built["ciudad"],
        },
    }

@app.post("/hashes/insert-auto")
def hashes_insert_auto(payload: HashAutoIn, authorization: Optional[str] = Header(default=None)):
    """
    PRO: calcula hash internamente, inserta si es nuevo y dispara n8n.
    """
    require_auth(authorization)

    built = build_canonical_and_hash(
        portal=payload.portal,
        url=payload.url,
        telefono=payload.telefono,
        titulo=payload.titulo,
        ciudad=payload.ciudad,
    )
    h = built["hash"]
    url_norm = built["url"]
    tel_norm = built["telefono"]
    portal_norm = built["portal"]

    with SessionLocal() as db:
        existing = db.query(HashRecord).filter(HashRecord.hash == h).first()
        if existing:
            return {"ok": True, "already_existed": True, "hash": h}

        rec = HashRecord(
            hash=h,
            created_at=now_utc(),
            url=url_norm,
            telefono=tel_norm,
            portal=portal_norm,
        )
        db.add(rec)

        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return {"ok": True, "already_existed": True, "hash": h}

        # webhook a n8n con datos NORMALIZADOS (y extras útiles)
        notify_n8n_new_hash(
            h,
            meta={
                "url": url_norm,
                "telefono": tel_norm,
                "portal": portal_norm,
                "titulo": built["titulo"],
                "ciudad": built["ciudad"],
                "canonical": built["canonical"],
            }
        )

        return {"ok": True, "already_existed": False, "hash": h, "canonical": built["canonical"]}

# =========================
# ASSIGNMENTS
# =========================

@app.post("/assignments/insert")
def assignments_insert(payload: AssignmentInsertIn, authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)

    h = normalize_hash(payload.hash)
    tel_norm = normalize_phone_es(payload.telefono)
    url_norm = normalize_url(payload.url)

    with SessionLocal() as db:
        existing = db.query(Assignment).filter(Assignment.hash == h).first()
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
            hash=h,
            created_at=now_utc(),
            telefono=tel_norm,
            inmobiliaria=payload.inmobiliaria,
            sheet_id_inmo=payload.sheet_id_inmo,
            url=url_norm,
        )
        db.add(rec)

        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            existing = db.query(Assignment).filter(Assignment.hash == h).first()
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
            raise

        return {"ok": True, "already_existed": False, "hash": h}

@app.get("/assignments/by-phone")
def assignments_by_phone(phone: str, authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)

    phone_norm = normalize_phone_es(phone)
    if not phone_norm:
        raise HTTPException(status_code=422, detail="Invalid phone")

    with SessionLocal() as db:
        rec = (
            db.query(Assignment)
            .filter(Assignment.telefono == phone_norm)
            .order_by(Assignment.created_at.desc())
            .first()
        )
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

    h = normalize_hash(hash)
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

    tel_norm = normalize_phone_es(telefono) if telefono else None

    with SessionLocal() as db:
        q = db.query(HashRecord)

        if tel_norm:
            q = q.filter(HashRecord.telefono == tel_norm)

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
