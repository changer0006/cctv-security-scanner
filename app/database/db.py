
import json
import sqlite3
from pathlib import Path


DEFAULT_DB_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "scan_history.db"
)


def initialize_database(db_path=DEFAULT_DB_PATH):
    """Create the scan-history table if it does not exist."""

    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(path) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                scan_status TEXT,
                device_type TEXT,
                vendor TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                result_json TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_target
            ON scans(target)
        """)


def save_scan(result: dict, db_path=DEFAULT_DB_PATH) -> int:
    """Save one assessment and return its database ID."""

    initialize_database(db_path)

    fingerprint = result.get("fingerprint", {})
    risk = result.get("risk", {})

    with sqlite3.connect(db_path) as connection:
        cursor = connection.execute("""
            INSERT INTO scans (
                target,
                generated_at,
                scan_status,
                device_type,
                vendor,
                risk_score,
                risk_level,
                result_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.get("target", "unknown"),
            result.get("generated_at", ""),
            result.get("scan_status", "unknown"),
            fingerprint.get("device_type", "Unknown"),
            fingerprint.get("vendor", "Unknown"),
            risk.get("risk_score", 0),
            risk.get("risk_level", "INFO"),
            json.dumps(result, ensure_ascii=False),
        ))

        return cursor.lastrowid


def get_scan(scan_id: int, db_path=DEFAULT_DB_PATH):
    """Retrieve one saved assessment, or None if not found."""

    initialize_database(db_path)

    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

    if row is None:
        return None

    saved = dict(row)
    saved["result"] = json.loads(saved.pop("result_json"))
    return saved


def list_scans(limit: int = 50, db_path=DEFAULT_DB_PATH) -> list[dict]:
    """Return the newest saved scans first."""

    if limit < 1:
        raise ValueError("limit must be at least 1")

    initialize_database(db_path)

    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT id, target, generated_at, scan_status,
                   device_type, vendor, risk_score, risk_level
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]
