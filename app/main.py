import json
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse

from app.detector.scoring import analyze
from app.history import init_db, list_scans, save_scan

STATIC_DIR = Path(__file__).parent / "static"
MAX_EMAIL_BYTES = 5 * 1024 * 1024

app = FastAPI(title="Phishing Detector")
init_db()


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/scan")
async def scan(file: UploadFile = File(...)):
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(data) > MAX_EMAIL_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 5 MB)")

    result = analyze(data)
    save_scan(file.filename, result)
    return result


@app.get("/api/history")
def history():
    rows = list_scans()
    for row in rows:
        row["findings"] = json.loads(row["findings"])
        row["scanned_at"] = row["scanned_at"].isoformat()
    return rows
