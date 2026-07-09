import os
import sys
import json
import queue
import shutil
import asyncio
import threading
import tempfile
import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
from pubsub import pub

TEMP_WORKSPACE = os.path.join(tempfile.gettempdir(), "mars_workspace")
QUARANTINE_DIR = os.path.join(TEMP_WORKSPACE, "01_quarantine")
EXTRACTED_DIR = os.path.join(TEMP_WORKSPACE, "02_extracted")
DOSSIERS_DIR = os.path.join(TEMP_WORKSPACE, "03_dossiers")
PCAPS_DIR = os.path.join(TEMP_WORKSPACE, "04_pcaps")
PIPELINE_EXTRACTED_DIR = os.path.join(TEMP_WORKSPACE, "extracted")

try:
    import yaml
    import pefile
    import yara
except ImportError as e:
    print(f"[CRITICAL ERROR] Missing dependency: {e}")
    sys.exit(1)

from database.database import init_db, SessionLocal
from database.models import AnalysisHistory
from api.routes import router
from core.pipeline import AnalysisPipeline

# ─────────────────────────────────────────────
# Global per-session state store
# Keyed by sha256 (lowercase)
# ─────────────────────────────────────────────
_sessions: dict[str, dict] = {}
_sessions_lock = threading.Lock()

# SSE queues: sha256 → list of queue.Queue (one per open browser connection)
_sse_queues: dict[str, list] = {}
_sse_lock = threading.Lock()


def _get_or_create_session(sha256: str) -> dict:
    sha256 = sha256.lower()
    with _sessions_lock:
        if sha256 not in _sessions:
            _sessions[sha256] = {
                "sha256": sha256,
                "filename": "",
                "status": "Queued",
                "logs": [],
                "results_store": {},
                "scores": [],
                "scoring_results": {},
            }
        return _sessions[sha256]


def _push_sse(sha256: str, event_type: str, data: dict):
    sha256 = sha256.lower()
    with _sse_lock:
        qs = _sse_queues.get(sha256, [])
    payload = json.dumps({"type": event_type, "data": data})
    for q in qs:
        try:
            q.put_nowait(payload)
        except Exception:
            pass


# ─────────────────────────────────────────────
# Active-session tracking (which sha256 is running)
# ─────────────────────────────────────────────
active_session_sha256: str | None = None
active_session_lock = threading.Lock()
analysis_lock = threading.Lock()
completion_event = threading.Event()

analysis_id_map: dict[str, str] = {}
active_workflow_types: dict[str, str] = {}


# ─────────────────────────────────────────────
# PubSub handlers
# ─────────────────────────────────────────────

def handle_gui_log(msg: str):
    with active_session_lock:
        sha256 = active_session_sha256
    if not sha256:
        return
    sess = _get_or_create_session(sha256)
    sess["logs"].append(msg)
    _push_sse(sha256, "log", {"msg": msg})


def handle_gui_update_table(module: str, data):
    with active_session_lock:
        sha256 = active_session_sha256
    if not sha256:
        return
    sess = _get_or_create_session(sha256)

    # Capture analysis-id ↔ sha256 mapping from Intake module
    if module == "Intake" and isinstance(data, dict):
        intake_sha = data.get("SHA256")
        analysis_id = data.get("Analysis ID")
        if intake_sha and analysis_id:
            analysis_id_map[intake_sha.lower()] = analysis_id
            # Also store filename
            fname = data.get("Original File Name") or data.get("Filename", "")
            if fname:
                sess["filename"] = fname

    # Capture package inventory list
    if module == "Package Unpacker: Inventory" and isinstance(data, dict):
        inv = data.get("inventory", [])
        sess["inventory"] = inv
        _push_sse(sha256, "inventory", {"inventory": inv})

    # Store in results_store
    if isinstance(data, dict):
        sess["results_store"][module] = data
    _push_sse(sha256, "table_update", {"module": module, "data": data if isinstance(data, dict) else {}})


def handle_analysis_trigger(filepath: str, sha256_hash: str, filename: str, workflow_type: str = "full_detonation", duration_seconds: int = 120, headless: bool = False, mode: str = "detonate"):
    global active_session_sha256
    if workflow_type == "bifurcated":
        duration_seconds = 900
    print(f"[Backend] Trigger: {filename} ({sha256_hash[:12]}…) type={workflow_type} mode={mode}")

    with analysis_lock:
        # Re-initialize session dict for this sha256 to clear old logs, status and cancellation flags
        with _sessions_lock:
            _sessions[sha256_hash.lower()] = {
                "sha256": sha256_hash.lower(),
                "filename": filename,
                "status": "Processing",
                "logs": [],
                "results_store": {},
                "scores": [],
                "scoring_results": {},
            }
        sess = _sessions[sha256_hash.lower()]
        if sess.get("cancelled"):
            print(f"[Backend] Session {sha256_hash} was cancelled while in queue. Skipping.")
            sess["status"] = "Terminated"
            pub.sendMessage("analysis.log", sha256_hash=sha256_hash, filename=filename, status="Terminated")
            _push_sse(sha256_hash, "status", {"status": "Terminated"})
            _push_sse(sha256_hash, "complete", {"status": "Terminated", "risk_score": 0})
            return

        with active_session_lock:
            active_session_sha256 = sha256_hash.lower()
        active_workflow_types[sha256_hash.lower()] = workflow_type

        sess["filename"] = filename
        sess["status"] = "Processing"

        pub.sendMessage("analysis.log", sha256_hash=sha256_hash, status="Processing")
        _push_sse(sha256_hash, "status", {"status": "Processing"})

        _, ext = os.path.splitext(filename)
        if not ext:
            ext = ".exe"

        q_dir = os.path.dirname(filepath)
        temp_filepath = os.path.join(q_dir, f"{sha256_hash}{ext}")

        try:
            if os.path.exists(temp_filepath):
                try:
                    os.remove(temp_filepath)
                except Exception:
                    pass
            if not os.path.exists(temp_filepath):
                try:
                    os.link(filepath, temp_filepath)
                except Exception:
                    try:
                        shutil.copy2(filepath, temp_filepath)
                    except Exception as copy_err:
                        print(f"[Backend Warning] Could not link/copy file to temp path (likely AV): {copy_err}")

            completion_event.clear()

            run_static  = workflow_type in ("full_detonation", "static_only", "bifurcated")
            run_dynamic = workflow_type in ("full_detonation", "dynamic_only", "bifurcated")

            target_analysis_path = temp_filepath
            if not os.path.exists(target_analysis_path) and os.path.exists(filepath):
                target_analysis_path = filepath

            pub.sendMessage(
                "analysis.start",
                filepath=os.path.abspath(target_analysis_path),
                run_static=run_static,
                run_dynamic=run_dynamic,
                original_filename=filename,
                duration_seconds=duration_seconds,
                headless=False,
                mode=mode,
                analysis_type=workflow_type,
            )

            completion_event.wait(timeout=duration_seconds + 600)

        except Exception as e:
            print(f"[Backend Error] {e}")
            pub.sendMessage("analysis.log", sha256_hash=sha256_hash, status="Failed")
            with active_session_lock:
                active_session_sha256 = None


def handle_scoring_result(result):
    with active_session_lock:
        sha256 = active_session_sha256
    if not sha256:
        return
    sess = _get_or_create_session(sha256)
    sess["scores"].append(result.total_score)
    sess["scoring_results"][result.target] = result.to_dict()
    _push_sse(sha256, "score", {"target": result.target, "result": result.to_dict()})


def handle_analysis_complete(status: str):
    global active_session_sha256
    with active_session_lock:
        sha256 = active_session_sha256
    if not sha256:
        completion_event.set()
        return

    sess = _get_or_create_session(sha256)
    workflow_type = active_workflow_types.get(sha256, "full_detonation")
    scores = sess.get("scores", [])

    risk_score = int(round(max(scores) * 10)) if scores else 0
    if status == "Success":
        db_status = "Complete"
    elif status == "Terminated":
        db_status = "Terminated"
    else:
        db_status = "Failed"
    sess["status"] = db_status

    if db_status == "Terminated":
        fname = sess.get("filename", "")
        pub.sendMessage("analysis.log", sha256_hash=sha256, filename=fname, status=db_status, risk_score=risk_score)
        _push_sse(sha256, "complete", {"status": db_status, "risk_score": risk_score})
        _, ext = os.path.splitext(fname)
        if not ext:
            ext = ".exe"
        temp_filepath = os.path.join(QUARANTINE_DIR, f"{sha256}{ext}")
        try:
            if os.path.exists(temp_filepath):
                os.remove(temp_filepath)
        except Exception:
            pass
        with active_session_lock:
            active_session_sha256 = None
        completion_event.set()
        return

    analysis_id = analysis_id_map.get(sha256)
    if analysis_id:
        src_json = os.path.join("workspace", "reports", f"{analysis_id}_Report.json")
        dst_json = os.path.join(DOSSIERS_DIR, f"{sha256}_dossier.json")
        os.makedirs(os.path.dirname(dst_json), exist_ok=True)
        if os.path.exists(src_json):
            try:
                shutil.copy2(src_json, dst_json)
            except Exception as e:
                print(f"[Backend Error] Copy JSON: {e}")

        # Locate the actual extracted directory starting with analysis_id
        src_ext = None
        extracted_parent = PIPELINE_EXTRACTED_DIR
        if os.path.exists(extracted_parent):
            for d in os.listdir(extracted_parent):
                if d.startswith(analysis_id) and os.path.isdir(os.path.join(extracted_parent, d)):
                    src_ext = os.path.join(extracted_parent, d)
                    break

        if src_ext and os.path.exists(src_ext):
            dst_ext = os.path.join(EXTRACTED_DIR, sha256)
            os.makedirs(dst_ext, exist_ok=True)
            for item in os.listdir(src_ext):
                s = os.path.join(src_ext, item)
                d = os.path.join(dst_ext, item)
                try:
                    if os.path.isdir(s):
                        shutil.copytree(s, d, dirs_exist_ok=True)
                    else:
                        shutil.copy2(s, d)
                except Exception:
                    pass

        # Copy package inventory log
        inv_src = os.path.join(PIPELINE_EXTRACTED_DIR, f"{analysis_id}_inventory_log.json")
        inv_dst = os.path.join(EXTRACTED_DIR, f"{sha256}_inventory.json")
        if os.path.exists(inv_src):
            try:
                os.makedirs(os.path.dirname(inv_dst), exist_ok=True)
                shutil.copy2(inv_src, inv_dst)
            except Exception:
                pass

    if workflow_type in ("full_detonation", "dynamic_only", "bifurcated"):
        pcap_path = os.path.join(PCAPS_DIR, f"{sha256}_traffic.pcap")
        os.makedirs(os.path.dirname(pcap_path), exist_ok=True)
        if not os.path.exists(pcap_path):
            try:
                with open(pcap_path, "wb") as f:
                    f.write(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00")
            except Exception:
                pass

    fname = sess.get("filename", "")
    pub.sendMessage("analysis.log", sha256_hash=sha256, filename=fname, status=db_status, risk_score=risk_score)
    _push_sse(sha256, "complete", {"status": db_status, "risk_score": risk_score})
    _, ext = os.path.splitext(fname)
    if not ext:
        ext = ".exe"
    temp_filepath = os.path.join(QUARANTINE_DIR, f"{sha256}{ext}")
    try:
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
    except Exception:
        pass

    with active_session_lock:
        active_session_sha256 = None
    completion_event.set()


# Register PubSub listeners
pub.subscribe(handle_gui_log,           "gui.log")
pub.subscribe(handle_gui_update_table,  "gui.update_table")
pub.subscribe(handle_analysis_trigger,  "analysis.trigger")
pub.subscribe(handle_scoring_result,    "scoring.result")
pub.subscribe(handle_analysis_complete, "analysis.complete")


# ─────────────────────────────────────────────
# Report-file scanner (survives restarts)
# ─────────────────────────────────────────────

def _scan_reports_for_sha256(sha256: str) -> tuple:
    """
    Scan workspace/reports/*.json to locate the JSON and PDF for a given
    sha256.  Returns (json_path, pdf_path) — either may be None.
    Also caches the result in analysis_id_map for future calls.
    """
    sha256 = sha256.lower()
    reports_dir = os.path.join("workspace", "reports")
    if not os.path.isdir(reports_dir):
        return None, None

    candidates = []
    for fname in os.listdir(reports_dir):
        if not fname.endswith("_Report.json"):
            continue
        fpath = os.path.join(reports_dir, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            summ = data.get("Analysis_Summary", {})
            file_sha = summ.get("SHA256", "").lower()
            if file_sha == sha256:
                aid = summ.get("Analysis ID", fname.replace("_Report.json", ""))
                candidates.append((aid, fpath))
        except Exception:
            continue

    if not candidates:
        return None, None

    # Most recent analysis first (IDs are timestamp-prefixed: MARS-YYYYMMDD…)
    candidates.sort(key=lambda x: x[0], reverse=True)
    best_aid, best_json = candidates[0]

    # Persist to in-memory map so subsequent calls are instant
    analysis_id_map[sha256] = best_aid

    pdf_path = os.path.join(reports_dir, f"{best_aid}_Report.pdf")
    if not os.path.exists(pdf_path):
        pdf_path = None

    return best_json, pdf_path


def _rebuild_analysis_id_map():
    """Read every report JSON on disk and populate analysis_id_map."""
    reports_dir = os.path.join("workspace", "reports")
    if not os.path.isdir(reports_dir):
        return
    count = 0
    for fname in os.listdir(reports_dir):
        if not fname.endswith("_Report.json"):
            continue
        fpath = os.path.join(reports_dir, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            summ = data.get("Analysis_Summary", {})
            sha = summ.get("SHA256", "").lower()
            aid = summ.get("Analysis ID", "")
            if sha and aid:
                # Only update if not already present (keep most-recent from later scans)
                existing = analysis_id_map.get(sha, "")
                if aid > existing:          # IDs are timestamp-sortable
                    analysis_id_map[sha] = aid
                    count += 1
        except Exception:
            continue
    if count:
        print(f"[Backend] Rebuilt analysis_id_map from {count} report(s) on disk.")


# ─────────────────────────────────────────────
# FastAPI lifespan
# ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    for d in [
        QUARANTINE_DIR,            EXTRACTED_DIR,
        DOSSIERS_DIR,              PCAPS_DIR,
        "workspace/reports",       PIPELINE_EXTRACTED_DIR,
        "web/static/css",          "web/templates",
    ]:
        os.makedirs(d, exist_ok=True)
    init_db()
    _rebuild_analysis_id_map()
    yield


app = FastAPI(title="MARS — Malware Analysis & Reporting System", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="web/static"), name="static")
templates = Jinja2Templates(directory="web/templates")
app.include_router(router)

pipeline = AnalysisPipeline(config_path="config/config.yaml")


# ─────────────────────────────────────────────
# SSE endpoint
# ─────────────────────────────────────────────
@app.get("/stream/{sha256}")
async def stream_events(sha256: str):
    sha256 = sha256.lower()
    q: queue.Queue = queue.Queue()
    with _sse_lock:
        _sse_queues.setdefault(sha256, []).append(q)

    async def event_gen():
        try:
            # Send any buffered history first
            with _sessions_lock:
                sess = _sessions.get(sha256, {})
            if sess:
                for log_line in sess.get("logs", []):
                    payload = json.dumps({"type": "log", "data": {"msg": log_line}})
                    yield f"data: {payload}\n\n"
                for module, data in sess.get("results_store", {}).items():
                    payload = json.dumps({"type": "table_update", "data": {"module": module, "data": data}})
                    yield f"data: {payload}\n\n"
                for target, result in sess.get("scoring_results", {}).items():
                    payload = json.dumps({"type": "score", "data": {"target": target, "result": result}})
                    yield f"data: {payload}\n\n"
                if sess.get("inventory"):
                    payload = json.dumps({"type": "inventory", "data": {"inventory": sess["inventory"]}})
                    yield f"data: {payload}\n\n"
                if sess.get("status") in ("Complete", "Failed"):
                    payload = json.dumps({"type": "complete", "data": {"status": sess["status"]}})
                    yield f"data: {payload}\n\n"
                    return

            while True:
                try:
                    payload = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: q.get(timeout=25)
                    )
                    yield f"data: {payload}\n\n"
                    event = json.loads(payload)
                    if event.get("type") == "complete":
                        break
                except Exception:
                    yield ": keepalive\n\n"
        finally:
            with _sse_lock:
                lst = _sse_queues.get(sha256, [])
                if q in lst:
                    lst.remove(q)

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─────────────────────────────────────────────
# Results & status API
# ─────────────────────────────────────────────
def _reconstruct_results_store_from_dossier(dossier_data: dict) -> tuple[dict, dict]:
    """
    Reconstruct a results_store dict from a saved report JSON so that
    loadAnalysis() can repopulate every dashboard tab after a server restart.
    """
    rs = {}

    # ── Intake summary ───────────────────────────────────────────────
    summary = dossier_data.get("Analysis_Summary", {})
    if summary:
        rs["Intake"] = summary

    # ── Static analysis — map each category to the same module key
    # the live pipeline uses when it calls pub.sendMessage("gui.update_table", …)
    static_map = {
        "PE Headers":        "Static: PE Headers",
        "Mitigations":       "Static: Mitigations",
        "Sections":          "Static: Sections",
        "Suspicious Imports":"Static: Suspicious Imports",
        "Manifest Data":     "Static: Manifest Data",
        "Strings Analytics": "Static: Strings Analytics",
        "Extracted Artifacts":"Static: Extracted Artifacts",
        "YARA Signatures":   "Static: YARA Signatures",
    }
    static_results = dossier_data.get("Static_Analysis_Results", {})
    # Merge all per-file results (usually only one primary file)
    merged_static: dict[str, dict] = {}
    for _fname, file_data in static_results.items():
        if not isinstance(file_data, dict):
            continue
        for cat, cat_data in file_data.items():
            if cat not in merged_static:
                merged_static[cat] = {}
            if isinstance(cat_data, dict):
                merged_static[cat].update(cat_data)
            else:
                merged_static[cat] = cat_data

    for cat, module_key in static_map.items():
        if cat in merged_static:
            rs[module_key] = merged_static[cat]

    # ── Dynamic analysis ─────────────────────────────────────────────
    dyn_results = dossier_data.get("Dynamic_Analysis_Results", {})
    for _tgt, file_data in dyn_results.items():
        if not isinstance(file_data, dict):
            continue
        for cat, events in file_data.items():
            if not isinstance(events, list):
                continue
            module_key = f"Dynamic: {cat}"
            rs[module_key] = {"Events": "\n".join(events)}

    # ── Dynamic Summary ──────────────────────────────────────────────
    dyn_summary = dossier_data.get("Dynamic_Summary", {})
    for _tgt, summary in dyn_summary.items():
        if isinstance(summary, dict):
            rs["Dynamic: Summary"] = summary

    # ── Scoring results ───────────────────────────────────────────────
    scoring = dossier_data.get("Scoring_Results", {})
    # scoring_results is keyed by target filename in the session store

    return rs, scoring


@app.get("/api/results/{sha256}")
async def get_results(sha256: str):
    sha256 = sha256.lower()

    # 1. Try in-memory session (live / recent analysis)
    with _sessions_lock:
        sess = _sessions.get(sha256)

    raw_dossier = None
    dossier_path = os.path.join(DOSSIERS_DIR, f"{sha256}_dossier.json")
    if not os.path.exists(dossier_path):
        json_path, _ = _scan_reports_for_sha256(sha256)
        if json_path:
            dossier_path = json_path
    if os.path.exists(dossier_path):
        try:
            with open(dossier_path, "r", encoding="utf-8") as fh:
                raw_dossier = json.load(fh)
        except Exception:
            pass

    if sess and sess.get("results_store"):
        return JSONResponse({
            "sha256":          sess["sha256"],
            "filename":        sess["filename"],
            "status":          sess["status"],
            "results_store":   sess["results_store"],
            "scoring_results": sess["scoring_results"],
            "logs":            sess["logs"],
            "inventory":       sess.get("inventory", []),
            "raw_dossier":     raw_dossier,
        })

    # 2. Fall back to dossier JSON on disk (survives restarts)
    dossier_path = os.path.join(DOSSIERS_DIR, f"{sha256}_dossier.json")
    if not os.path.exists(dossier_path):
        # Try scanning reports dir as last resort
        json_path, _ = _scan_reports_for_sha256(sha256)
        if json_path:
            dossier_path = json_path

    if os.path.exists(dossier_path):
        try:
            with open(dossier_path, "r", encoding="utf-8") as fh:
                dossier_data = json.load(fh)

            results_store, scoring_results = _reconstruct_results_store_from_dossier(dossier_data)

            # Derive filename and status from DB
            db_session = SessionLocal()
            try:
                record = db_session.query(AnalysisHistory).filter_by(sha256_hash=sha256).first()
                filename = record.filename if record else dossier_data.get("Analysis_Summary", {}).get("Original File Name", "")
                status   = record.status   if record else "Complete"
            finally:
                db_session.close()

            # Load inventory from copied file
            inventory = []
            inv_path = os.path.join(EXTRACTED_DIR, f"{sha256}_inventory.json")
            if os.path.exists(inv_path):
                try:
                    with open(inv_path, "r", encoding="utf-8") as fh:
                        inventory = json.load(fh)
                except Exception:
                    pass
            # Or fall back to checking in report package extraction
            if not inventory:
                inventory = dossier_data.get("Package_Extraction", [])

            return JSONResponse({
                "sha256":          sha256,
                "filename":        filename,
                "status":          status,
                "results_store":   results_store,
                "scoring_results": scoring_results,
                "logs":            [],
                "inventory":       inventory,
                "raw_dossier":     dossier_data,
            })
        except Exception as e:
            return JSONResponse(status_code=500, content={"error": f"Failed to read dossier: {e}"})

    return JSONResponse(status_code=404, content={"error": "No session or dossier found"})


@app.get("/api/artifacts/{sha256}")
async def get_artifacts(sha256: str):
    """Return which downloadable files exist for this analysis."""
    sha256 = sha256.lower()

    # JSON: check dossier copy first, then scan reports dir
    dossier = os.path.join(DOSSIERS_DIR, f"{sha256}_dossier.json")
    if os.path.exists(dossier):
        has_json = True
    else:
        aid = analysis_id_map.get(sha256)
        if aid:
            has_json = os.path.exists(os.path.join("workspace", "reports", f"{aid}_Report.json"))
        else:
            json_p, _ = _scan_reports_for_sha256(sha256)
            has_json = json_p is not None

    # PDF: same map approach
    aid = analysis_id_map.get(sha256)
    if aid:
        has_pdf = os.path.exists(os.path.join("workspace", "reports", f"{aid}_Report.pdf"))
    else:
        _, pdf_p = _scan_reports_for_sha256(sha256)
        has_pdf = pdf_p is not None

    # PCAP: check dedicated pcaps dir
    has_pcap = os.path.exists(os.path.join(PCAPS_DIR, f"{sha256}_traffic.pcap"))

    return {"json": has_json, "pdf": has_pdf, "pcap": has_pcap}


@app.get("/api/status/{sha256}")
async def get_status(sha256: str):
    sha256 = sha256.lower()
    db_session = SessionLocal()
    try:
        record = db_session.query(AnalysisHistory).filter_by(sha256_hash=sha256).first()
        if record:
            return {"status": record.status, "risk_score": record.risk_score}
    finally:
        db_session.close()
    with _sessions_lock:
        sess = _sessions.get(sha256)
    if sess:
        return {"status": sess.get("status", "Unknown"), "risk_score": None}
    return JSONResponse(status_code=404, content={"error": "Not found"})


# ─────────────────────────────────────────────
# Report download endpoints
# ─────────────────────────────────────────────
def _get_download_filename(sha256: str, ext: str) -> str:
    db_session = SessionLocal()
    filename = ""
    timestamp = None
    try:
        record = db_session.query(AnalysisHistory).filter_by(sha256_hash=sha256).first()
        if record:
            filename = record.filename
            timestamp = record.timestamp
    finally:
        db_session.close()

    if not filename:
        with _sessions_lock:
            sess = _sessions.get(sha256)
        if sess:
            filename = sess.get("filename", "")

    if not filename:
        dossier = os.path.join(DOSSIERS_DIR, f"{sha256}_dossier.json")
        if os.path.exists(dossier):
            try:
                with open(dossier, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                filename = data.get("Analysis_Summary", {}).get("Original File Name", "")
            except Exception:
                pass

    if not filename:
        filename = f"{sha256[:12]}.exe"

    if not timestamp:
        timestamp = datetime.datetime.now()

    name_prefix = os.path.splitext(filename)[0]
    time_str = timestamp.strftime("%H%M%S-%d%m%Y")
    return f"{name_prefix}-{time_str}{ext}"


@app.get("/download/report/json/{sha256}")
async def download_json_report(sha256: str):
    from fastapi.responses import FileResponse
    sha256 = sha256.lower()
    dl_filename = _get_download_filename(sha256, ".json")

    # 1. Check dossier copy (created by handle_analysis_complete)
    dossier = os.path.join(DOSSIERS_DIR, f"{sha256}_dossier.json")
    if os.path.exists(dossier):
        return FileResponse(dossier, media_type="application/json",
                            filename=dl_filename)

    # 2. Check in-memory map (set during the current server session)
    aid = analysis_id_map.get(sha256)
    if aid:
        path = os.path.join("workspace", "reports", f"{aid}_Report.json")
        if os.path.exists(path):
            return FileResponse(path, media_type="application/json",
                                filename=dl_filename)

    # 3. Full disk scan (handles previous analyses after a restart)
    json_path, _ = _scan_reports_for_sha256(sha256)
    if json_path and os.path.exists(json_path):
        return FileResponse(json_path, media_type="application/json",
                            filename=dl_filename)

    return JSONResponse(status_code=404, content={"error": "JSON report not found"})


@app.get("/download/report/pdf/{sha256}")
async def download_pdf_report(sha256: str):
    from fastapi.responses import FileResponse
    from core.report import ReportGenerator
    from core.scoring import ScoringResult
    sha256 = sha256.lower()
    dl_filename = _get_download_filename(sha256, ".pdf")

    # Locate the JSON source — try in-memory map first, then disk scan
    json_path = None
    pdf_path  = None

    aid = analysis_id_map.get(sha256)
    if aid:
        candidate = os.path.join("workspace", "reports", f"{aid}_Report.json")
        if os.path.exists(candidate):
            json_path = candidate
            pdf_path  = os.path.join("workspace", "reports", f"{aid}_Report.pdf")

    if not json_path:
        json_path, pdf_path = _scan_reports_for_sha256(sha256)

    if not json_path or not os.path.exists(json_path):
        return JSONResponse(status_code=404, content={"error": "PDF report not found"})

    # Regenerate the PDF from the stored JSON so new styling is applied
    try:
        with open(json_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        # Reconstruct ScoringResult objects from the saved dicts (if present)
        scoring_results: dict = {}
        for target, sr_dict in data.get("Scoring_Results", {}).items():
            try:
                scoring_results[target] = ScoringResult.from_dict(sr_dict)
            except Exception:
                pass

        rg = ReportGenerator({"system": {"reports_dir": "workspace/reports"}})
        rg._build_pdf(data, pdf_path, scoring_results=scoring_results or None)
    except Exception as exc:
        print(f"[PDF regen error] {exc}")
        # Fall back to whatever is on disk if regeneration fails
        if pdf_path and os.path.exists(pdf_path):
            return FileResponse(pdf_path, media_type="application/pdf",
                                filename=dl_filename)
        return JSONResponse(status_code=500, content={"error": f"PDF generation failed: {exc}"})

    return FileResponse(pdf_path, media_type="application/pdf",
                        filename=dl_filename)


@app.post("/api/terminate/{sha256}")
async def terminate_analysis_endpoint(sha256: str):
    sha256 = sha256.lower().strip()
    
    with _sessions_lock:
        sess = _sessions.get(sha256)
        
    if not sess:
        db_session = SessionLocal()
        try:
            record = db_session.query(AnalysisHistory).filter_by(sha256_hash=sha256).first()
            if record and record.status in ("Queued", "Processing"):
                record.status = "Terminated"
                db_session.commit()
                return JSONResponse(content={"status": "Terminated", "message": "Database entry marked as Terminated"})
        except Exception:
            db_session.rollback()
        finally:
            db_session.close()
        return JSONResponse(status_code=404, content={"error": "Analysis session not found"})

    sess["cancelled"] = True
    sess["status"] = "Terminated"

    AnalysisPipeline.cancel_analysis(sha256)

    with active_session_lock:
        active_sha = active_session_sha256

    if active_sha == sha256:
        from core.dynamic import MalwareSandboxAnalyzer
        MalwareSandboxAnalyzer.cancel_active()
        pub.sendMessage("gui.log", msg=f"[!] Termination requested for active analysis: {sha256[:12]}...")
    else:
        pub.sendMessage("analysis.log", sha256_hash=sha256, status="Terminated")
        _push_sse(sha256, "status", {"status": "Terminated"})
        _push_sse(sha256, "complete", {"status": "Terminated", "risk_score": 0})
        pub.sendMessage("gui.log", msg=f"[!] Termination requested for queued analysis: {sha256[:12]}...")

    return JSONResponse(content={"status": "Terminated", "message": "Analysis termination initiated successfully."})


# ─────────────────────────────────────────────
# UI pages
# ─────────────────────────────────────────────
@app.get("/")
async def read_root(request: Request):
    db_session = SessionLocal()
    try:
        history = db_session.query(AnalysisHistory).order_by(AnalysisHistory.timestamp.desc()).all()
    finally:
        db_session.close()
    return templates.TemplateResponse(request=request, name="index.html", context={"history": history})


@app.get("/report/{sha256}")
async def read_report(request: Request, sha256: str):
    sha256 = sha256.lower().strip()
    db_session = SessionLocal()
    try:
        record = db_session.query(AnalysisHistory).filter_by(sha256_hash=sha256).first()
    finally:
        db_session.close()

    if not record:
        return HTMLResponse("<h1>Analysis Record Not Found</h1>", status_code=404)

    report_data = {}
    dossier = os.path.join(DOSSIERS_DIR, f"{sha256}_dossier.json")
    if os.path.exists(dossier):
        try:
            with open(dossier) as fh:
                report_data = json.load(fh)
                # Map keys for Jinja2 template compatibility
                report_data['static_analysis'] = report_data.get('Static_Analysis_Results', {})
                report_data['dynamic_analysis'] = report_data.get('Dynamic_Analysis_Results', {})
                report_data['threat_scoring'] = report_data.get('Scoring_Results', {})
                report_data['metadata'] = report_data.get('Analysis_Summary', {})
        except Exception:
            pass

    with _sessions_lock:
        mem_sess = _sessions.get(sha256, {})

    pcap_exists = os.path.exists(os.path.join(PCAPS_DIR, f"{sha256}_traffic.pcap"))
    ext_dir = os.path.join(EXTRACTED_DIR, sha256)
    extracted_files = []
    if os.path.isdir(ext_dir):
        extracted_files = [f for f in os.listdir(ext_dir) if os.path.isfile(os.path.join(ext_dir, f))]

    return templates.TemplateResponse(
        request=request,
        name="report.html",
        context={
            "record":          record,
            "report_data":     report_data,
            "mem_sess":        mem_sess,
            "pcap_exists":     pcap_exists,
            "extracted_files": extracted_files,
        },
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
