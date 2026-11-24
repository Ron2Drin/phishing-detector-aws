import json
import logging
import socket
import time
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse

from app.detector.scoring import analyze
from app.history import init_db, list_scans, save_scan

STATIC_DIR = Path(__file__).parent / "static"
MAX_EMAIL_BYTES = 5 * 1024 * 1024
INSTANCE = socket.gethostname()

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("phishing")


def log_event(event, **fields):
    log.info(json.dumps({"event": event, "instance": INSTANCE, **fields}))


app = FastAPI(title="Phishing Detector")
init_db()


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    if request.url.path != "/health":
        log_event("request", method=request.method, path=request.url.path,
                  status=response.status_code,
                  duration_ms=round((time.perf_counter() - start) * 1000, 1))
    return response


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health():
    return {"status": "ok", "instance": INSTANCE}


@app.post("/api/scan")
async def scan(file: UploadFile = File(...)):
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(data) > MAX_EMAIL_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 5 MB)")

    result = analyze(data)
    save_scan(file.filename, result)
    log_event("scan", source=file.filename, verdict=result["verdict"],
              score=result["score"], findings=len(result["findings"]))
    return result


@app.get("/api/history")
def history():
    rows = list_scans()
    for row in rows:
        row["findings"] = json.loads(row["findings"])
        row["scanned_at"] = row["scanned_at"].isoformat()
    return rows