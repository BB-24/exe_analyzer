import os
import hashlib
import tempfile
from fastapi import APIRouter, UploadFile, File, Form, BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from pubsub import pub
from database.database import SessionLocal
from database.models import AnalysisHistory

router = APIRouter()

TEMP_WORKSPACE = os.path.join(tempfile.gettempdir(), "mars_workspace")
QUARANTINE_DIR = os.path.join(TEMP_WORKSPACE, "01_quarantine")
EXTRACTED_DIR = os.path.join(TEMP_WORKSPACE, "02_extracted")
DOSSIERS_DIR = os.path.join(TEMP_WORKSPACE, "03_dossiers")
PCAPS_DIR = os.path.join(TEMP_WORKSPACE, "04_pcaps")
PIPELINE_EXTRACTED_DIR = os.path.join(TEMP_WORKSPACE, "extracted")

os.makedirs(QUARANTINE_DIR, exist_ok=True)


def _publish_trigger(sha256_hash: str, filename: str, filepath: str, workflow_type: str, duration_seconds: int):
    pub.sendMessage("analysis.log", sha256_hash=sha256_hash, filename=filename, status="Queued")
    pub.sendMessage(
        "analysis.trigger",
        filepath=filepath,
        sha256_hash=sha256_hash,
        filename=filename,
        workflow_type=workflow_type,
        duration_seconds=duration_seconds,
    )


@router.post("/upload")
async def upload_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    analysis_type: str = Form("full_detonation"),
    analysis_duration: int = Form(120),
):
    try:
        content = await file.read()
        sha256_hash = hashlib.sha256(content).hexdigest()

        # Validate duration (seconds)
        if analysis_duration not in (120, 540, 900):
            analysis_duration = 120

        dest_filename = f"{sha256_hash}.malz"
        dest_filepath = os.path.join(QUARANTINE_DIR, dest_filename)
        if not os.path.exists(dest_filepath):
            with open(dest_filepath, "wb") as f:
                f.write(content)

        background_tasks.add_task(
            _publish_trigger,
            sha256_hash=sha256_hash,
            filename=file.filename,
            filepath=dest_filepath,
            workflow_type=analysis_type,
            duration_seconds=analysis_duration,
        )

        return JSONResponse(
            status_code=202,
            content={
                "status": "Queued",
                "sha256": sha256_hash,
                "filename": file.filename,
                "analysis_type": analysis_type,
                "analysis_duration": analysis_duration,
                "message": f"File queued for {analysis_type} analysis (Unified Agent Runtime: {analysis_duration}s).",
            },
        )
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/api/history")
def get_history():
    session = SessionLocal()
    try:
        records = session.query(AnalysisHistory).order_by(AnalysisHistory.timestamp.desc()).all()
        return [
            {
                "id":          r.id,
                "sha256_hash": r.sha256_hash,
                "filename":    r.filename,
                "timestamp":   r.timestamp.strftime("%Y-%m-%d %H:%M:%S") if r.timestamp else "",
                "status":      r.status,
                "risk_score":  r.risk_score if r.risk_score is not None else "-",
            }
            for r in records
        ]
    finally:
        session.close()


@router.get("/download/pcap/{sha256}")
def download_pcap(sha256: str):
    path = os.path.join(PCAPS_DIR, f"{sha256}_traffic.pcap")
    if not os.path.exists(path):
        return JSONResponse(status_code=404, content={"error": "PCAP not found"})
    return FileResponse(path, media_type="application/vnd.tcpdump.pcap", filename=f"{sha256}_traffic.pcap")


@router.get("/download/extracted/{sha256}/{filename:path}")
def download_extracted(sha256: str, filename: str):
    path = os.path.join(EXTRACTED_DIR, sha256, filename)
    if not os.path.exists(path):
        return JSONResponse(status_code=404, content={"error": "File not found"})
    return FileResponse(path, media_type="application/octet-stream", filename=os.path.basename(filename))
