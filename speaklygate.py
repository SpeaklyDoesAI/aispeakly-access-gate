import os
import time
import hmac
import hashlib

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

app = FastAPI(title="AI Speakly Access Gate", version="1.0.0")

# Required env vars:
# - PARTNER_EMBED_SECRET  (only needed if you want signed tokens ?t=...)
# - GHL_API_KEY
PARTNER_EMBED_SECRET = os.getenv("PARTNER_EMBED_SECRET", "")
GHL_API_KEY = os.getenv("GHL_API_KEY", "")

# Optional env vars:
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "60"))
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*")  # (unused for now)
PARTNER_EMBED_KEYS_RAW = os.getenv("PARTNER_EMBED_KEYS", "")  # e.g. "ari=KEY1,reilabs=KEY2"

# ---- Super-minimal in-memory rate limit (good enough to ship today) ----
_hits: dict[str, tuple[int, int]] = {}  # key -> (window_start_epoch_minute, count)


def rate_limit(key: str) -> None:
    now = int(time.time())
    window = now - (now % 60)  # minute window
    rec = _hits.get(key)
    if not rec or rec[0] != window:
        _hits[key] = (window, 1)
        return
    count = rec[1] + 1
    _hits[key] = (window, count)
    if count > RATE_LIMIT_PER_MIN:
        raise HTTPException(status_code=429, detail="Too many requests")


def verify_embed_token(token: str) -> dict:
    """
    Token format: partnerId.userId.exp.sig

    sig = hex(HMAC_SHA256(secret, f"{partnerId}.{userId}.{exp}"))
    exp is unix epoch seconds
    """
    if not PARTNER_EMBED_SECRET:
        raise HTTPException(status_code=500, detail="PARTNER_EMBED_SECRET not configured")

    try:
        partner_id, user_id, exp_str, sig = token.split(".", 3)
        exp = int(exp_str)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token format")

    if int(time.time()) > exp:
        raise HTTPException(status_code=401, detail="Token expired")

    msg = f"{partner_id}.{user_id}.{exp}".encode("utf-8")
    expected_sig = hmac.new(
        PARTNER_EMBED_SECRET.encode("utf-8"),
        msg,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, sig):
        raise HTTPException(status_code=401, detail="Bad signature")

    return {"partner_id": partner_id, "user_id": user_id, "exp": exp}


def _parse_partner_keys(raw: str) -> dict:
    """
    raw example: "ari=KEY1,reilabs=KEY2"
    returns: {"ari": "KEY1", "reilabs": "KEY2"}
    """
    mapping: dict[str, str] = {}
    if not raw:
        return mapping
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    for part in parts:
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip()
        v = v.strip()
        if k and v:
            mapping[k] = v
    return mapping


_PARTNER_KEYS = _parse_partner_keys(PARTNER_EMBED_KEYS_RAW)


def is_valid_partner_key(partner: str, key: str) -> bool:
    if not partner or not key:
        return False
    expected = _PARTNER_KEYS.get(partner)
    if not expected:
        return False
    return hmac.compare_digest(expected, key)


class AccessCheckIn(BaseModel):
    locationId: str = Field(..., min_length=3)
    phone: str = Field(..., min_length=7, max_length=30)

    # Support BOTH auth modes:
    # 1) Signed token: token
    # 2) Embed key: partner + key
    token: str = ""
    partner: str = ""
    key: str = ""


@app.get("/health")
async def health():
    return {"ok": True}


@app.post("/api/access/check")
async def access_check(payload: AccessCheckIn, request: Request):
    # Basic anti-abuse
    ip = request.client.host if request.client else "unknown"
    rate_limit(ip)

    # ---- AUTH: accept either signed token OR partner embed key ----
    authed_partner_id = None

    if payload.token:
        claims = verify_embed_token(payload.token)
        authed_partner_id = claims.get("partner_id")
    elif payload.partner and payload.key:
        if not _PARTNER_KEYS:
            raise HTTPException(status_code=500, detail="PARTNER_EMBED_KEYS not configured")
        if not is_valid_partner_key(payload.partner, payload.key):
            raise HTTPException(status_code=401, detail="Invalid partner embed key")
        authed_partner_id = payload.partner
    else:
        raise HTTPException(status_code=401, detail="Missing embed auth")

    # ---- GHL call ----
    if not GHL_API_KEY:
        raise HTTPException(status_code=500, detail="GHL_API_KEY not configured")

    url = (
        "https://services.leadconnectorhq.com/contacts/search/duplicate"
        f"?locationId={payload.locationId}&number={payload.phone}"
    )
    headers = {
        "Authorization": f"Bearer {GHL_API_KEY}",
        "Version": "2021-07-28",
        "Accept": "application/json",
    }

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url, headers=headers)

    if resp.status_code in (401, 403):
        raise HTTPException(status_code=500, detail="GHL auth failed (token/scopes)")

    if resp.status_code >= 400:
        return {"allowLaunch": False, "exists": False, "reason": f"lookup_failed_{resp.status_code}"}

    data = resp.json() if resp.content else {}

    # Response shapes can vary; keep forgiving
    contact = data.get("contact") or data.get("contacts") or data.get("data")
    exists = bool(contact)

    return {
        "allowLaunch": exists,  # minimal gating today: existence == access
        "exists": exists,
        "reason": "ok" if exists else "not_found",
        "partnerId": authed_partner_id,
    }
