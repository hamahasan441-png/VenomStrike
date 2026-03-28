"""SQLite database for scan history and results storage."""
# For authorized security testing only.
import sqlite3
import json
import time
import os
from typing import List, Dict, Optional
from config import DB_PATH


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the database schema."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            started_at REAL NOT NULL,
            completed_at REAL,
            status TEXT DEFAULT 'running',
            config TEXT,
            summary TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            vuln_type TEXT NOT NULL,
            url TEXT NOT NULL,
            param TEXT,
            payload TEXT,
            severity TEXT NOT NULL,
            confidence INTEGER,
            cvss REAL,
            cwe TEXT,
            owasp TEXT,
            evidence TEXT,
            debug_info TEXT,
            fix_code TEXT,
            created_at REAL NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)
    # Performance indices for common queries
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_findings_confidence ON findings(confidence)"
    )
    conn.commit()
    conn.close()


def create_scan(scan_id: str, target: str, config: Dict) -> str:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (id, target, started_at, config, status) VALUES (?, ?, ?, ?, ?)",
        (scan_id, target, time.time(), json.dumps(config), "running"),
    )
    conn.commit()
    conn.close()
    return scan_id


def save_finding(scan_id: str, finding: Dict):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO findings 
           (scan_id, vuln_type, url, param, payload, severity, confidence, cvss, cwe, owasp, evidence, debug_info, fix_code, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            scan_id,
            finding.get("vuln_type", ""),
            finding.get("url", ""),
            finding.get("param", ""),
            finding.get("payload", ""),
            finding.get("severity", "Info"),
            finding.get("confidence", 0),
            finding.get("cvss", 0.0),
            finding.get("cwe", ""),
            finding.get("owasp", ""),
            json.dumps(finding.get("evidence", {})),
            json.dumps(finding.get("debug_info", {})),
            json.dumps(finding.get("fix_code", {})),
            time.time(),
        ),
    )
    conn.commit()
    conn.close()


def update_scan_status(scan_id: str, status: str, summary: Dict = None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE scans SET status=?, completed_at=?, summary=? WHERE id=?",
        (status, time.time(), json.dumps(summary or {}), scan_id),
    )
    conn.commit()
    conn.close()


def get_scan(scan_id: str) -> Optional[Dict]:
    conn = get_connection()
    cursor = conn.cursor()
    row = cursor.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    conn.close()
    if row:
        d = dict(row)
        d["config"] = json.loads(d.get("config") or "{}")
        d["summary"] = json.loads(d.get("summary") or "{}")
        return d
    return None


def get_findings(scan_id: str) -> List[Dict]:
    conn = get_connection()
    cursor = conn.cursor()
    rows = cursor.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,)).fetchall()
    conn.close()
    findings = []
    for row in rows:
        d = dict(row)
        d["evidence"] = json.loads(d.get("evidence") or "{}")
        d["debug_info"] = json.loads(d.get("debug_info") or "{}")
        d["fix_code"] = json.loads(d.get("fix_code") or "{}")
        findings.append(d)
    return findings


def get_all_scans() -> List[Dict]:
    conn = get_connection()
    cursor = conn.cursor()
    rows = cursor.execute("SELECT * FROM scans ORDER BY started_at DESC").fetchall()
    conn.close()
    scans = []
    for row in rows:
        d = dict(row)
        d["config"] = json.loads(d.get("config") or "{}")
        d["summary"] = json.loads(d.get("summary") or "{}")
        scans.append(d)
    return scans


def delete_scan(scan_id: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
    cursor.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    conn.commit()
    conn.close()
