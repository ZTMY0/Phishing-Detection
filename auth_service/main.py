import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import uvicorn
from fastapi import FastAPI, HTTPException, Header
from shared.config import get_settings
from shared.models import LoginRequest, RegisterRequest, RefreshRequest, TokenResponse, UserRole
from shared.logger import configure_logging
from shared.database import get_connection, init_schema, create_user, get_user_by_email, get_user_by_id, update_user_role
from shared.auth_tokens import hash_password, verify_password, create_access_token, create_refresh_token, decode_token

cfg = get_settings()
log = configure_logging("auth_service")
_conn = None


def db():
    global _conn
    if _conn is None:
        _conn = get_connection(cfg.database_path)
        init_schema(_conn)
    return _conn


app = FastAPI(title="AuthService", docs_url=None, redoc_url=None)


@app.on_event("startup")
async def startup():
    db()
    log.info("auth_service.started", port=8001)


def tokens(uid: str, role: UserRole) -> TokenResponse:
    r = role.value
    return TokenResponse(
        access_token=create_access_token(uid, r, cfg.jwt_secret, cfg.token_expire_minutes),
        role=role,
        uid=uid,
        refresh_token=create_refresh_token(uid, r, cfg.jwt_secret, cfg.refresh_expire_days),
        expires_in=cfg.token_expire_minutes * 60,
    )


@app.post("/auth/register", response_model=TokenResponse)
async def register(req: RegisterRequest):
    if get_user_by_email(db(), req.email):
        raise HTTPException(status_code=400, detail="Un compte existe déjà avec cet e-mail")
    uid = create_user(db(), req.email, hash_password(req.password), UserRole.user.value)
    return tokens(uid, UserRole.user)


@app.post("/auth/login", response_model=TokenResponse)
async def login(req: LoginRequest):
    user = get_user_by_email(db(), req.email)
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Identifiants invalides")
    return tokens(user["id"], UserRole(user["role"]))


@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh_token(req: RefreshRequest):
    try:
        payload = decode_token(req.refresh_token, cfg.jwt_secret, expected_type="refresh")
    except ValueError:
        raise HTTPException(status_code=401, detail="Session expirée")

    user = get_user_by_id(db(), payload["sub"])
    if not user:
        raise HTTPException(status_code=403, detail="Compte introuvable")
    return tokens(user["id"], UserRole(user["role"]))


@app.post("/auth/verify")
async def verify_token(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token mal formé")

    raw = authorization.removeprefix("Bearer ")
    try:
        payload = decode_token(raw, cfg.jwt_secret, expected_type="access")
    except ValueError:
        raise HTTPException(status_code=401, detail="Token invalide ou expiré")

    user = get_user_by_id(db(), payload["sub"])
    role = user["role"] if user else payload.get("role", UserRole.user.value)
    return {"uid": payload["sub"], "role": role}


@app.post("/auth/set-role")
async def set_role(target_uid: str, role: UserRole, authorization: str = Header(...)):
    caller = await verify_token(authorization)
    if caller["role"] != UserRole.admin.value:
        raise HTTPException(status_code=403, detail="Accès administrateur requis")
    if not get_user_by_id(db(), target_uid):
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    update_user_role(db(), target_uid, role.value)
    return {"ok": True}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "auth"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=False)
