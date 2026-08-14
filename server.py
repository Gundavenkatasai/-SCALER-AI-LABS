"""
PII Redaction API
-----------------
FastAPI backend for the Scaler AI Labs challenge.

What it does: accepts .docx uploads, runs the redaction pipeline
locally (no data leaves the machine), and returns the sanitised
document plus a JSON mapping of what got replaced with what.

Extra features added beyond the basic redact/download flow:
  - /api/history  (GET / DELETE)  — persistent JSON-based job log
  - /api/health                   — quick liveness check
  - /api/evaluate                 — runs the 75-entity test harness
  - Rate limiting via slowapi (10 uploads/minute per IP)
  - Input validation (file type, size, filename sanitation)
  - Structured JSON logging for every request
"""

import json
import logging
import os
import re
import shutil
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from redact_pii import redact_document

# ---------------------------------------------------------------------------
# Logging — structured, goes to stdout so process supervisors can capture it
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "msg": %(message)s}',
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("api")

# ---------------------------------------------------------------------------
# Rate limiting — 10 redact requests per minute per IP.
# Chosen because the pipeline can take 5-15s on a large doc; 10/min
# is generous for real use but blocks naive scrapers.
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="PII Redaction Engine",
    version="2.1",
    description="Local-only document sanitisation for Indian corporate filings.",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Storage paths — use /tmp on Vercel (read-only filesystem in serverless),
# fall back to local paths for development.
# ---------------------------------------------------------------------------
ON_VERCEL = os.environ.get("VERCEL") == "1"
BASE_TMP   = Path("/tmp") if ON_VERCEL else Path("temp_files")
TEMP_DIR   = BASE_TMP / "pii_temp"
HISTORY_FILE = BASE_TMP / "history.json"
TEMP_DIR.mkdir(parents=True, exist_ok=True)


def _load_history() -> list:
    if not HISTORY_FILE.exists():
        return []
    try:
        return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def _save_history(records: list) -> None:
    HISTORY_FILE.write_text(
        json.dumps(records, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _append_history(record: dict) -> None:
    records = _load_history()
    records.append(record)
    _save_history(records)


def _safe_filename(name: str) -> str:
    """Strip anything that isn't alphanumeric, dot, dash, or underscore."""
    return re.sub(r"[^\w.\-]", "_", name)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    """Simple liveness probe. Returns 200 if the process is up."""
    return {"status": "ok", "version": app.version}


@app.post("/api/redact")
@limiter.limit("10/minute")
async def redact(
    request: Request,
    file: UploadFile = File(...),
    use_ner: bool = Form(True),
):
    # Validate file type before writing anything to disk.
    # Don't trust the Content-Type header alone — check the extension too.
    if not (file.filename or "").lower().endswith(".docx"):
        raise HTTPException(status_code=400, detail="Only .docx files are accepted.")

    # 50 MB hard limit — large RHP docs are ~2-5 MB; 50 MB is a safe ceiling.
    MAX_BYTES = 50 * 1024 * 1024
    contents = await file.read()
    if len(contents) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds the 50 MB limit.")

    safe_name = _safe_filename(file.filename)
    job_id = str(uuid.uuid4())
    input_path = TEMP_DIR / f"{job_id}_input_{safe_name}"
    output_name = f"REDACTED_{safe_name}"
    output_path = TEMP_DIR / f"{job_id}_{output_name}"
    started_at = datetime.now(timezone.utc).isoformat()

    input_path.write_bytes(contents)
    log.info('"event": "upload", "job": "%s", "file": "%s"', job_id, safe_name)

    try:
        t0 = time.perf_counter()
        result = redact_document(
            input_path=str(input_path),
            output_path=str(output_path),
            use_ner=use_ner,
            dry_run=False,
            export_mapping=True,
        )
        elapsed = round(time.perf_counter() - t0, 2)
    except Exception as exc:
        log.error('"event": "redact_error", "job": "%s", "error": "%s"', job_id, exc)
        input_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        # Always remove the uploaded original — we only keep the redacted copy.
        input_path.unlink(missing_ok=True)

    mapping_path = output_path.with_suffix(".mapping.json")
    mapping_data: dict = {}
    if mapping_path.exists():
        mapping_data = json.loads(mapping_path.read_text(encoding="utf-8"))

    summary = {
        "paragraphs_scanned": result["paragraphs_scanned"],
        "unique_entities_redacted": result["unique_entities_redacted"],
        "category_breakdown": result["category_breakdown"],
        "spacy_used": result["spacy_used"],
        "processing_time_s": elapsed,
    }

    download_id = f"{job_id}_{output_name}"

    # Persist to history
    _append_history({
        "id": job_id,
        "filename": safe_name,
        "timestamp": started_at,
        "status": "success",
        "download_id": download_id,
        "summary": summary,
    })

    log.info(
        '"event": "redact_done", "job": "%s", "entities": %d, "time_s": %s',
        job_id, summary["unique_entities_redacted"], elapsed,
    )

    return {
        "status": "success",
        "job_id": job_id,
        "summary": summary,
        "download_id": download_id,
        "mapping": mapping_data,
    }


@app.get("/api/download/{download_id:path}")
async def download_file(download_id: str):
    # Prevent path traversal
    if ".." in download_id or "/" in download_id.replace("\\", "/").lstrip("/"):
        raise HTTPException(status_code=400, detail="Invalid download ID.")

    file_path = TEMP_DIR / download_id
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found. It may have been deleted.")

    # The download_id format is "{uuid}_{original_name}" — strip the UUID prefix
    # so the user gets a clean filename like "REDACTED_resume.docx".
    clean_name = "_".join(download_id.split("_")[1:]) or download_id

    return FileResponse(
        path=file_path,
        filename=clean_name,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )


# ---------------------------------------------------------------------------
# History endpoints
# ---------------------------------------------------------------------------

@app.get("/api/history")
async def list_history():
    """Returns all past jobs, newest first."""
    records = _load_history()
    return {"history": list(reversed(records))}


@app.get("/api/history/{job_id}")
async def get_history_entry(job_id: str):
    records = _load_history()
    entry = next((r for r in records if r["id"] == job_id), None)
    if not entry:
        raise HTTPException(status_code=404, detail="Job not found.")
    return entry


@app.delete("/api/history/{job_id}")
async def delete_history_entry(job_id: str):
    records = _load_history()
    updated = [r for r in records if r["id"] != job_id]
    if len(updated) == len(records):
        raise HTTPException(status_code=404, detail="Job not found.")

    # Also clean up any leftover temp files for this job
    for f in TEMP_DIR.glob(f"{job_id}_*"):
        f.unlink(missing_ok=True)

    _save_history(updated)
    return {"status": "deleted", "job_id": job_id}


# ---------------------------------------------------------------------------
# Evaluation endpoint (runs the built-in 75-entity test harness)
# ---------------------------------------------------------------------------

@app.get("/api/evaluate")
async def evaluate():
    from redact_pii import run_evaluation
    try:
        summary = run_evaluation(verbose=False)
        return {"status": "success", "summary": summary}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
