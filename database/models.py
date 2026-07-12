import datetime
from sqlalchemy import Column, Integer, String, DateTime
from database.database import Base, SessionLocal
from pubsub import pub

class AnalysisHistory(Base):
    __tablename__ = "analysis_history"

    id = Column(Integer, primary_key=True, index=True)
    sha256_hash = Column(String, index=True, nullable=False)
    analysis_id = Column(String, nullable=True)
    filename = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.now)
    status = Column(String, default="Queued") # Queued, Processing, Complete, Failed
    risk_score = Column(Integer, nullable=True)

def handle_analysis_log(sha256_hash, filename=None, status=None, risk_score=None):
    """
    Subscribes to 'analysis.log' and updates/inserts records in SQLite DB.
    """
    session = SessionLocal()
    try:
        # Find the LATEST record for this sha256_hash to update the current analysis run
        record = session.query(AnalysisHistory).filter_by(sha256_hash=sha256_hash).order_by(AnalysisHistory.id.desc()).first()
        if record:
            if filename is not None:
                record.filename = filename
            if status is not None:
                record.status = status
                # Reset stale risk score if we re-trigger/re-queue the same file
                if status in ("Queued", "Processing"):
                    record.risk_score = None
            if risk_score is not None:
                record.risk_score = risk_score
            record.timestamp = datetime.datetime.now()
        else:
            # Create new record
            new_record = AnalysisHistory(
                sha256_hash=sha256_hash,
                filename=filename or "Unknown",
                status=status or "Queued",
                risk_score=risk_score,
                timestamp=datetime.datetime.now()
            )
            session.add(new_record)
        session.commit()
        print(f"[DB] Saved analysis log: hash={sha256_hash}, status={status}, risk_score={risk_score}")
    except Exception as e:
        session.rollback()
        print(f"[DB Error] Failed to update/insert analysis history: {e}")
    finally:
        session.close()

# Register the PyPubSub subscriber automatically when models.py is imported
pub.subscribe(handle_analysis_log, "analysis.log")
