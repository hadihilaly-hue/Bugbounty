"""SQLite persistence for batches, runs, validations, and the spend ledger.

Everything a batch does is written here so a run is resumable and so spend can
be tracked across runs against the credit window. Uses stdlib sqlite3 only.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from ..validator.models import ValidationResult

DEFAULT_DB = "runs/bugbounty.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS batches (
    id TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    status TEXT NOT NULL,
    note TEXT
);
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL,
    target_name TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at REAL,
    finished_at REAL,
    reason TEXT
);
CREATE TABLE IF NOT EXISTS validations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL,
    run_id TEXT,
    candidate_id TEXT NOT NULL,
    target_name TEXT NOT NULL,
    vuln_class TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT,
    reproducible INTEGER DEFAULT 0,
    poc TEXT,
    evidence TEXT,
    created_at REAL NOT NULL,
    UNIQUE(batch_id, candidate_id)
);
CREATE TABLE IF NOT EXISTS spend (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT,
    run_id TEXT,
    target_name TEXT,
    job TEXT NOT NULL,
    tokens INTEGER DEFAULT 0,
    requests INTEGER DEFAULT 0,
    usd REAL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL,
    candidate_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    note TEXT,
    created_at REAL NOT NULL,
    UNIQUE(batch_id, candidate_id)
);
CREATE TABLE IF NOT EXISTS benchmarks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    precision REAL, recall REAL, fp_rate REAL,
    tp INTEGER, fp INTEGER, tn INTEGER, fn INTEGER,
    created_at REAL NOT NULL
);
"""


class Store:
    def __init__(self, path: str | Path = DEFAULT_DB) -> None:
        self.path = str(path)
        parent = Path(self.path).parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as con:
            con.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        return con

    # --- batches ---
    def create_batch(self, batch_id: str, note: str | None = None) -> None:
        with self._connect() as con:
            con.execute(
                "INSERT OR IGNORE INTO batches (id, created_at, status, note) VALUES (?,?,?,?)",
                (batch_id, time.time(), "running", note),
            )

    def set_batch_status(self, batch_id: str, status: str) -> None:
        with self._connect() as con:
            con.execute("UPDATE batches SET status=? WHERE id=?", (status, batch_id))

    # --- runs ---
    def start_run(self, run_id: str, batch_id: str, target_name: str) -> None:
        with self._connect() as con:
            con.execute(
                "INSERT OR REPLACE INTO runs (id, batch_id, target_name, status, started_at) "
                "VALUES (?,?,?,?,?)",
                (run_id, batch_id, target_name, "running", time.time()),
            )

    def finish_run(self, run_id: str, status: str, reason: str | None = None) -> None:
        with self._connect() as con:
            con.execute(
                "UPDATE runs SET status=?, finished_at=?, reason=? WHERE id=?",
                (status, time.time(), reason, run_id),
            )

    # --- validations ---
    def record_validation(
        self, batch_id: str, run_id: str | None, target_name: str, result: ValidationResult
    ) -> None:
        with self._connect() as con:
            con.execute(
                "INSERT OR IGNORE INTO validations "
                "(batch_id, run_id, candidate_id, target_name, vuln_class, status, reason, "
                "reproducible, poc, evidence, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    batch_id,
                    run_id,
                    result.candidate_id,
                    target_name,
                    result.vuln_class.value,
                    result.status.value,
                    result.reason,
                    int(result.reproducible),
                    result.poc,
                    json.dumps([e.model_dump() for e in result.evidence]),
                    time.time(),
                ),
            )

    def validated_candidate_ids(self, batch_id: str) -> set[str]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT candidate_id FROM validations WHERE batch_id=?", (batch_id,)
            ).fetchall()
        return {r["candidate_id"] for r in rows}

    def confirmed(self, batch_id: str | None = None) -> list[sqlite3.Row]:
        q = "SELECT * FROM validations WHERE status='confirmed'"
        args: tuple = ()
        if batch_id:
            q += " AND batch_id=?"
            args = (batch_id,)
        with self._connect() as con:
            return con.execute(q + " ORDER BY created_at DESC", args).fetchall()

    # --- spend ---
    def record_spend(
        self,
        job: str,
        usd: float = 0.0,
        tokens: int = 0,
        requests: int = 0,
        batch_id: str | None = None,
        run_id: str | None = None,
        target_name: str | None = None,
    ) -> None:
        with self._connect() as con:
            con.execute(
                "INSERT INTO spend (batch_id, run_id, target_name, job, tokens, requests, usd, "
                "created_at) VALUES (?,?,?,?,?,?,?,?)",
                (batch_id, run_id, target_name, job, tokens, requests, usd, time.time()),
            )

    def total_spend_usd(self) -> float:
        with self._connect() as con:
            row = con.execute("SELECT COALESCE(SUM(usd),0) AS t FROM spend").fetchone()
        return float(row["t"])

    def spend_by_target(self, batch_id: str | None = None) -> dict[str, float]:
        q = "SELECT target_name, COALESCE(SUM(usd),0) AS t FROM spend"
        args: tuple = ()
        if batch_id:
            q += " WHERE batch_id=?"
            args = (batch_id,)
        q += " GROUP BY target_name"
        with self._connect() as con:
            rows = con.execute(q, args).fetchall()
        return {(r["target_name"] or "?"): float(r["t"]) for r in rows}

    def list_validations(
        self, statuses: list[str] | None = None, batch_id: str | None = None
    ) -> list[sqlite3.Row]:
        q = "SELECT * FROM validations"
        clauses: list[str] = []
        args: list = []
        if statuses:
            clauses.append(f"status IN ({','.join('?' for _ in statuses)})")
            args.extend(statuses)
        if batch_id:
            clauses.append("batch_id=?")
            args.append(batch_id)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY (status='confirmed') DESC, created_at DESC"
        with self._connect() as con:
            return con.execute(q, tuple(args)).fetchall()

    def get_validation(self, validation_id: int) -> sqlite3.Row | None:
        with self._connect() as con:
            return con.execute("SELECT * FROM validations WHERE id=?", (validation_id,)).fetchone()

    def record_review(
        self, batch_id: str, candidate_id: str, decision: str, note: str | None = None
    ) -> None:
        with self._connect() as con:
            con.execute(
                "INSERT INTO reviews (batch_id, candidate_id, decision, note, created_at) "
                "VALUES (?,?,?,?,?) ON CONFLICT(batch_id, candidate_id) "
                "DO UPDATE SET decision=excluded.decision, note=excluded.note, "
                "created_at=excluded.created_at",
                (batch_id, candidate_id, decision, note, time.time()),
            )

    def reviews_map(self, batch_id: str | None = None) -> dict[str, str]:
        q = "SELECT candidate_id, decision FROM reviews"
        args: tuple = ()
        if batch_id:
            q += " WHERE batch_id=?"
            args = (batch_id,)
        with self._connect() as con:
            rows = con.execute(q, args).fetchall()
        return {r["candidate_id"]: r["decision"] for r in rows}

    def status_counts(self, batch_id: str | None = None) -> dict[str, int]:
        q = "SELECT status, COUNT(*) AS n FROM validations"
        args: tuple = ()
        if batch_id:
            q += " WHERE batch_id=?"
            args = (batch_id,)
        q += " GROUP BY status"
        with self._connect() as con:
            rows = con.execute(q, args).fetchall()
        return {r["status"]: r["n"] for r in rows}

    def record_benchmark(self, name: str, metrics) -> None:
        with self._connect() as con:
            con.execute(
                "INSERT INTO benchmarks (name, precision, recall, fp_rate, tp, fp, tn, fn, "
                "created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    name,
                    metrics.precision,
                    metrics.recall,
                    metrics.fp_rate,
                    metrics.tp,
                    metrics.fp,
                    metrics.tn,
                    metrics.fn,
                    time.time(),
                ),
            )

    def latest_benchmark(self, name: str | None = None):
        q = "SELECT * FROM benchmarks"
        args: tuple = ()
        if name:
            q += " WHERE name=?"
            args = (name,)
        q += " ORDER BY created_at DESC LIMIT 1"
        with self._connect() as con:
            return con.execute(q, args).fetchone()
