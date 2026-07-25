import json
import sqlite3
from pathlib import Path
from typing import Optional


DB_PATH = Path(__file__).resolve().parent / "incident_agent.db"


def get_connection():
    conn = sqlite3.connect(
        str(DB_PATH),
        timeout=30,
        check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            run_id TEXT PRIMARY KEY,
            request_hash TEXT NOT NULL,
            state_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS receipts (
            run_id TEXT NOT NULL,
            receipt_id TEXT NOT NULL,
            receipt_hash TEXT NOT NULL,
            receipt_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (run_id, receipt_id)
        )
    """)

    conn.commit()
    conn.close()


def get_incident(run_id: str) -> Optional[dict]:
    conn = get_connection()

    row = conn.execute(
        """
        SELECT state_json
        FROM incidents
        WHERE run_id = ?
        """,
        (run_id,)
    ).fetchone()

    conn.close()

    if row is None:
        return None

    return json.loads(row["state_json"])


def get_request_hash(run_id: str) -> Optional[str]:
    conn = get_connection()

    row = conn.execute(
        """
        SELECT request_hash
        FROM incidents
        WHERE run_id = ?
        """,
        (run_id,)
    ).fetchone()

    conn.close()

    if row is None:
        return None

    return row["request_hash"]


def save_incident(
    run_id: str,
    request_hash: str,
    state: dict,
    timestamp: str
):
    conn = get_connection()

    conn.execute(
        """
        INSERT INTO incidents (
            run_id,
            request_hash,
            state_json,
            created_at,
            updated_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            run_id,
            request_hash,
            json.dumps(
                state,
                sort_keys=True,
                separators=(",", ":")
            ),
            timestamp,
            timestamp
        )
    )

    conn.commit()
    conn.close()


def update_incident(
    run_id: str,
    state: dict,
    timestamp: str
):
    conn = get_connection()

    conn.execute(
        """
        UPDATE incidents
        SET state_json = ?,
            updated_at = ?
        WHERE run_id = ?
        """,
        (
            json.dumps(
                state,
                sort_keys=True,
                separators=(",", ":")
            ),
            timestamp,
            run_id
        )
    )

    conn.commit()
    conn.close()


def save_receipt(
    run_id: str,
    receipt_id: str,
    receipt_hash: str,
    receipt: dict,
    timestamp: str
):
    conn = get_connection()

    conn.execute(
        """
        INSERT INTO receipts (
            run_id,
            receipt_id,
            receipt_hash,
            receipt_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            run_id,
            receipt_id,
            receipt_hash,
            json.dumps(
                receipt,
                sort_keys=True,
                separators=(",", ":")
            ),
            timestamp
        )
    )

    conn.commit()
    conn.close()
