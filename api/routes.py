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


def _publish_trigger(
    sha256_hash: str,
    filename: str,
    filepath: str,
    workflow_type: str,
    duration_seconds: int,
    mode: str = "detonate",
    phase1_duration: int = 300,
    phase2_duration: int = 600,
):
    pub.sendMessage("analysis.log", sha256_hash=sha256_hash, filename=filename, status="Queued")
    pub.sendMessage(
        "analysis.trigger",
        filepath=filepath,
        sha256_hash=sha256_hash,
        filename=filename,
        workflow_type=workflow_type,
        duration_seconds=duration_seconds,
        headless=False,
        mode=mode,
        phase1_duration=phase1_duration,
        phase2_duration=phase2_duration,
    )


@router.post("/upload")
async def upload_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    analysis_type: str = Form("full_detonation"),
    analysis_duration: int = Form(120),
    analysis_mode: str = Form("detonate"),
    phase1_duration: int = Form(300),
    phase2_duration: int = Form(600),
):
    try:
        content = await file.read()
        sha256_hash = hashlib.sha256(content).hexdigest()

        # Validate duration (seconds)
        if analysis_type == "bifurcated":
            # validate phase1_duration and phase2_duration are between 60 and 1800 (1 min to 30 min)
            if not (60 <= phase1_duration <= 1800):
                phase1_duration = 300
            if not (60 <= phase2_duration <= 1800):
                phase2_duration = 600
            analysis_duration = phase1_duration + phase2_duration
        else:
            # validate analysis_duration is between 60 and 1800 (1 min to 30 min)
            if not (60 <= analysis_duration <= 1800):
                analysis_duration = 120

        dest_filename = f"{sha256_hash}.malz"
        dest_filepath = os.path.join(QUARANTINE_DIR, dest_filename)
        if not os.path.exists(dest_filepath):
            with open(dest_filepath, "wb") as f:
                f.write(content)

        # Create a new record in the history database with "Queued" status
        import datetime
        db_session = SessionLocal()
        try:
            new_record = AnalysisHistory(
                sha256_hash=sha256_hash,
                filename=file.filename,
                status="Queued",
                timestamp=datetime.datetime.now()
            )
            db_session.add(new_record)
            db_session.commit()
        except Exception as db_err:
            db_session.rollback()
            print(f"[Backend Warning] Failed to insert initial history record: {db_err}")
        finally:
            db_session.close()

        background_tasks.add_task(
            _publish_trigger,
            sha256_hash=sha256_hash,
            filename=file.filename,
            filepath=dest_filepath,
            workflow_type=analysis_type,
            duration_seconds=analysis_duration,
            mode=analysis_mode,
            phase1_duration=phase1_duration,
            phase2_duration=phase2_duration,
        )

        return JSONResponse(
            status_code=202,
            content={
                "status": "Queued",
                "sha256": sha256_hash,
                "filename": file.filename,
                "analysis_type": analysis_type,
                "analysis_duration": analysis_duration,
                "run_mode": "interactive",
                "analysis_mode": analysis_mode,
                "phase1_duration": phase1_duration,
                "phase2_duration": phase2_duration,
                "message": f"File queued for {analysis_type} analysis (Unified Agent Runtime: {analysis_duration}s, mode: interactive, execution: {analysis_mode}).",
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


@router.get("/download/pcap/{id_or_sha256}")
def download_pcap(id_or_sha256: str):
    sha256 = id_or_sha256.lower()
    if id_or_sha256.isdigit():
        db_session = SessionLocal()
        try:
            record = db_session.query(AnalysisHistory).filter_by(id=int(id_or_sha256)).first()
            if record:
                sha256 = record.sha256_hash.lower()
        finally:
            db_session.close()

    path = os.path.join(PCAPS_DIR, f"{sha256}_traffic.pcap")
    if not os.path.exists(path):
        return JSONResponse(status_code=404, content={"error": "PCAP not found"})
    return FileResponse(path, media_type="application/vnd.tcpdump.pcap", filename=f"{sha256}_traffic.pcap")


@router.get("/download/extracted/{id_or_sha256}/{filename:path}")
def download_extracted(id_or_sha256: str, filename: str):
    sha256 = id_or_sha256.lower()
    if id_or_sha256.isdigit():
        db_session = SessionLocal()
        try:
            record = db_session.query(AnalysisHistory).filter_by(id=int(id_or_sha256)).first()
            if record:
                sha256 = record.sha256_hash.lower()
        finally:
            db_session.close()

    path = os.path.join(EXTRACTED_DIR, sha256, filename)
    if not os.path.exists(path):
        return JSONResponse(status_code=404, content={"error": "File not found"})
    return FileResponse(path, media_type="application/octet-stream", filename=os.path.basename(filename))
