import json
import sqlite3
import threading
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "incident_agent.db"

_lock = threading.RLock()


def get_db():
    conn = sqlite3.connect(
        str(DB_PATH),
        check_same_thread=False,
        timeout=30
    )
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _lock:
        conn = get_db()

        conn.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                request_hash TEXT NOT NULL,
                state_json TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                receipt_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                request_hash TEXT NOT NULL,
                receipt_json TEXT NOT NULL
            )
        """)

        conn.commit()
        conn.close()


def get_run(run_id):
    with _lock:
        conn = get_db()

        row = conn.execute(
            "SELECT * FROM runs WHERE run_id = ?",
            (run_id,)
        ).fetchone()

        conn.close()

        if not row:
            return None

        return {
            "run_id": row["run_id"],
            "request_hash": row["request_hash"],
            "state": json.loads(row["state_json"])
        }


def create_run(run_id, request_hash, state):
    with _lock:
        conn = get_db()

        conn.execute(
            """
            INSERT INTO runs
            (run_id, request_hash, state_json)
            VALUES (?, ?, ?)
            """,
            (
                run_id,
                request_hash,
                json.dumps(
                    state,
                    sort_keys=True,
                    separators=(",", ":")
                )
            )
        )

        conn.commit()
        conn.close()


def update_run(run_id, state):
    with _lock:
        conn = get_db()

        conn.execute(
            """
            UPDATE runs
            SET state_json = ?
            WHERE run_id = ?
            """,
            (
                json.dumps(
                    state,
                    sort_keys=True,
                    separators=(",", ":")
                ),
                run_id
            )
        )

        conn.commit()
        conn.close()


def get_receipt(receipt_id):
    with _lock:
        conn = get_db()

        row = conn.execute(
            """
            SELECT *
            FROM receipts
            WHERE receipt_id = ?
            """,
            (receipt_id,)
        ).fetchone()

        conn.close()

        if not row:
            return None

        return {
            "receipt_id": row["receipt_id"],
            "run_id": row["run_id"],
            "request_hash": row["request_hash"],
            "receipt": json.loads(row["receipt_json"])
        }


def save_receipt(
    receipt_id,
    run_id,
    request_hash,
    receipt
):
    with _lock:
        conn = get_db()

        conn.execute(
            """
            INSERT INTO receipts
            (
                receipt_id,
                run_id,
                request_hash,
                receipt_json
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                receipt_id,
                run_id,
                request_hash,
                json.dumps(
                    receipt,
                    sort_keys=True,
                    separators=(",", ":")
                )
            )
        )

        conn.commit()
        conn.close()
