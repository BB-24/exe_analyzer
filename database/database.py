import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite:///./mars_history.db"

# connect_args={"check_same_thread": False} is required for SQLite in multithreaded environments
engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def init_db():
    # Run SQLite schema migrations dynamically if needed
    db_path = "./mars_history.db"
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Verify table exists before altering
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='analysis_history';")
        if cursor.fetchone():
            # 1. Check if analysis_id column exists, if not add it
            cursor.execute("PRAGMA table_info(analysis_history);")
            columns = [col[1] for col in cursor.fetchall()]
            if "analysis_id" not in columns:
                cursor.execute("ALTER TABLE analysis_history ADD COLUMN analysis_id TEXT;")
                conn.commit()
                
            # 2. Verify unique index and replace with non-unique index
            cursor.execute("PRAGMA index_list(analysis_history);")
            indexes = cursor.fetchall()
            for idx in indexes:
                # idx format: (seq, name, unique, origin, partial)
                if idx[1] == "ix_analysis_history_sha256_hash" and idx[2] == 1:
                    cursor.execute("DROP INDEX IF EXISTS ix_analysis_history_sha256_hash;")
                    cursor.execute("CREATE INDEX IF NOT EXISTS ix_analysis_history_sha256_hash ON analysis_history(sha256_hash);")
                    conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB Migration Warning] {e}")

    Base.metadata.create_all(bind=engine)
