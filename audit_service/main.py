import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
from datetime import datetime, timezone
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from shared.models import AuditEvent
from shared.logger import configure_logging

log = configure_logging("audit_service")
LOG_FILE = Path(__file__).resolve().parent / "data" / "audit.jsonl"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="AuditService", docs_url=None, redoc_url=None)


@app.on_event("startup")
async def startup():
    log.info("audit_service.started", port=8003)


@app.post("/audit/log", status_code=201)
async def write_event(event: AuditEvent):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **event.model_dump(),
    }
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError as e:
        log.error("audit.write_failed", error=str(e))
    return {"ok": True}


@app.get("/audit/logs")
async def get_logs(limit: int = 100, event_type: str | None = None):
    limit = min(limit, 500)
    try:
        lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return {"logs": []}

    out = []
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event_type and row.get("event_type") != event_type:
            continue
        out.append(row)
        if len(out) >= limit:
            break
    return {"logs": out}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "audit"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8003, reload=False)
