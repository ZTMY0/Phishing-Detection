import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "proto"))

import time
import uuid
from datetime import datetime, timezone
from collections import defaultdict
from contextlib import asynccontextmanager

import grpc
import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from shared.config import get_settings
from shared.models import (
    LoginRequest, RegisterRequest, RefreshRequest, TokenResponse,
    SubmissionRequest, AuditEvent, UserRole,
)
from shared.logger import configure_logging
from shared.database import get_connection, init_schema, insert_report, list_reports, get_report, report_stats
import analysis_pb2
import analysis_pb2_grpc

cfg = get_settings()
log = configure_logging("api_gateway")

_rate_counts = defaultdict(list)
_db_conn = None
_grpc_channel = None
_analysis_stub = None

AUTH_DOWN = HTTPException(status_code=503, detail="Service d'authentification indisponible")
AUTH_TIMEOUT = HTTPException(status_code=504, detail="Délai d'attente dépassé")


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def check_rate_limit(ip: str):
    now = time.time()
    hits = [t for t in _rate_counts[ip] if now - t < 60]
    if len(hits) >= cfg.rate_limit_per_minute:
        raise HTTPException(status_code=429, detail="Trop de requêtes")
    hits.append(now)
    _rate_counts[ip] = hits


def db():
    global _db_conn
    if _db_conn is None:
        _db_conn = get_connection(cfg.database_path)
        init_schema(_db_conn)
    return _db_conn


def grpc_stub():
    global _grpc_channel, _analysis_stub
    if _analysis_stub is None:
        _grpc_channel = grpc.insecure_channel(f"{cfg.analysis_grpc_host}:{cfg.analysis_grpc_port}")
        _analysis_stub = analysis_pb2_grpc.AnalyzerStub(_grpc_channel)
    return _analysis_stub


def staff(role: str) -> bool:
    return role in (UserRole.admin.value, UserRole.analyst.value)


async def audit(event: AuditEvent):
    try:
        async with httpx.AsyncClient(timeout=3.0) as c:
            await c.post(f"{cfg.audit_service_url}/audit/log", json=event.model_dump())
    except Exception as e:
        log.warning("gateway.audit_failed", error=str(e))


async def auth_post(path: str, body: dict | None = None):
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            return await c.post(f"{cfg.auth_service_url}{path}", json=body)
    except httpx.ConnectError:
        raise AUTH_DOWN
    except httpx.TimeoutException:
        raise AUTH_TIMEOUT


async def verify_token(authorization: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            resp = await c.post(f"{cfg.auth_service_url}/auth/verify", headers={"Authorization": authorization})
    except httpx.ConnectError:
        raise AUTH_DOWN
    except httpx.TimeoutException:
        raise AUTH_TIMEOUT

    if resp.status_code == 401:
        raise HTTPException(status_code=401, detail="Token invalide ou expiré")
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail="Erreur du service d'authentification")
    return resp.json()


async def require_auth(authorization: str = Header(...)) -> dict:
    return await verify_token(authorization)


async def require_admin(auth: dict = Depends(require_auth)) -> dict:
    if auth["role"] != UserRole.admin.value:
        raise HTTPException(status_code=403, detail="Accès administrateur requis")
    return auth


@asynccontextmanager
async def lifespan(app: FastAPI):
    db()
    grpc_stub()
    log.info("gateway.started", port=cfg.gateway_port)
    yield
    if _grpc_channel:
        _grpc_channel.close()


app = FastAPI(title="PhishGuard API", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000", "http://localhost:8000"],
                   allow_methods=["*"], allow_headers=["*"])

client_dir = os.path.join(os.path.dirname(__file__), "..", "client")
if os.path.isdir(client_dir):
    app.mount("/app", StaticFiles(directory=client_dir, html=True), name="client")


@app.post("/api/auth/login", response_model=TokenResponse)
async def login(req: LoginRequest, request: Request):
    ip = client_ip(request)
    check_rate_limit(ip)
    resp = await auth_post("/auth/login", req.model_dump())
    if resp.status_code == 401:
        await audit(AuditEvent(event_type="login_failed", ip=ip, detail=f"email={req.email}", success=False))
        raise HTTPException(status_code=401, detail="Identifiants invalides")
    body = resp.json()
    await audit(AuditEvent(event_type="login_success", user_id=body.get("uid"), ip=ip))
    return body


@app.post("/api/auth/register", response_model=TokenResponse)
async def register(req: RegisterRequest, request: Request):
    ip = client_ip(request)
    check_rate_limit(ip)
    resp = await auth_post("/auth/register", req.model_dump())
    if resp.status_code != 200:
        detail = resp.json().get("detail", "Inscription échouée") if resp.content else "Inscription échouée"
        raise HTTPException(status_code=resp.status_code, detail=detail)
    body = resp.json()
    await audit(AuditEvent(event_type="register_success", user_id=body.get("uid"), ip=ip))
    return body


@app.post("/api/auth/refresh", response_model=TokenResponse)
async def refresh(req: RefreshRequest):
    resp = await auth_post("/auth/refresh", req.model_dump())
    if resp.status_code != 200:
        raise HTTPException(status_code=401, detail="Session expirée")
    return resp.json()


@app.post("/api/reports", status_code=201)
async def submit_report(req: SubmissionRequest, request: Request, auth: dict = Depends(require_auth)):
    ip = client_ip(request)
    check_rate_limit(ip)
    report_id = str(uuid.uuid4())

    try:
        result = grpc_stub().Analyze(analysis_pb2.AnalyzeRequest(
            declared_sender=req.declared_sender,
            subject=req.subject,
            body=req.body[:cfg.max_email_body_chars],
            urls=req.urls[:cfg.max_url_count],
            has_attachments=req.has_attachments,
        ), timeout=10.0)
    except grpc.RpcError as e:
        log.error("gateway.grpc_error", code=e.code(), detail=e.details())
        if e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
            raise HTTPException(status_code=504, detail="Délai d'analyse dépassé")
        raise HTTPException(status_code=502, detail="Service d'analyse indisponible")

    insert_report(db(), {
        "id": report_id,
        "declared_sender": req.declared_sender,
        "subject": req.subject,
        "body_excerpt": req.body[:500],
        "urls": req.urls,
        "has_attachments": req.has_attachments,
        "submitted_by": auth["uid"],
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "risk_level": result.risk_level,
        "score": result.score,
        "reasons": list(result.reasons),
        "flags": dict(result.flags),
    })

    await audit(AuditEvent(
        event_type="report_submitted", user_id=auth["uid"], report_id=report_id, ip=ip,
        detail=f"risk={result.risk_level} score={result.score}",
    ))
    return {"id": report_id, "risk_level": result.risk_level, "score": result.score, "reasons": list(result.reasons)}


@app.get("/api/reports")
async def list_reports_route(
    auth: dict = Depends(require_auth),
    sender: str | None = None,
    risk: str | None = None,
    keyword: str | None = None,
    limit: int = 50,
):
    rows = list_reports(
        db(),
        uid=None if staff(auth["role"]) else auth["uid"],
        sender=sender,
        risk=risk,
        keyword=keyword,
        limit=min(limit, 200),
    )
    return {"reports": rows, "count": len(rows)}


@app.get("/api/reports/{report_id}")
async def get_report_route(report_id: str, auth: dict = Depends(require_auth)):
    data = get_report(db(), report_id)
    if not data:
        raise HTTPException(status_code=404, detail="Signalement introuvable")
    if not staff(auth["role"]) and data["submitted_by"] != auth["uid"]:
        raise HTTPException(status_code=403, detail="Accès refusé")
    return data


@app.get("/api/admin/audit-logs")
async def admin_audit_logs(limit: int = 100, event_type: str | None = None, auth: dict = Depends(require_admin)):
    params = {"limit": limit, **({"event_type": event_type} if event_type else {})}
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            resp = await c.get(f"{cfg.audit_service_url}/audit/logs", params=params)
        return resp.json()
    except Exception:
        raise HTTPException(status_code=502, detail="Service d'audit indisponible")


@app.get("/api/admin/stats")
async def admin_stats(auth: dict = Depends(require_admin)):
    return report_stats(db())


@app.get("/health")
async def health():
    return {"status": "ok", "service": "gateway"}


@app.get("/")
async def root():
    return RedirectResponse("/app/index.html")


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=cfg.gateway_port, reload=False)
