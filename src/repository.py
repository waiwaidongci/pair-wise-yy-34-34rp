from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import STATES


class Gateway:
    """数据库写事务内使用的操作网关。所有方法都不自行提交。"""

    def __init__(self, conn: sqlite3.Connection, replay: bool = False):
        self.conn = conn
        self.replay = replay
        self.result: Any = None

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        item = dict(row)
        return item

    @staticmethod
    def _record(row: sqlite3.Row) -> Dict[str, Any]:
        record = dict(row)
        record["recurrence_risk"] = bool(record.get("recurrence_risk", 0))
        return record

    def get_item(self, item_id: int) -> Dict[str, Any]:
        row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def get_record(self, record_id: int) -> Dict[str, Any]:
        row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        if row is None:
            raise NotFoundError("整改措施不存在")
        return self._record(row)

    def open_record_count(self, item_id: int) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
            (item_id,),
        ).fetchone()
        return int(row["n"])

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            cur = self.conn.execute(
                """INSERT INTO items(title, description, severity, quantity, threshold,
                   status, version, external_ref, created_by, created_at, updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (title, description, severity, quantity, threshold, STATES[0], 1,
                 external_ref, actor, now, now),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(int(cur.lastrowid))

    def transition_item(self, item: Dict[str, Any], target: str,
                        expected_version: int, actor: str) -> Dict[str, Any]:
        now = utc_now()
        if target == "verification":
            sql = """UPDATE items
                SET status=?, version=version+1, updated_at=?,
                    verified_by=?, verified_at=?, closed_by=NULL, closed_at=NULL
                WHERE id=? AND version=?"""
            params = (target, now, actor, now, item["id"], expected_version)
        elif target == "closed":
            sql = """UPDATE items
                SET status=?, version=version+1, updated_at=?,
                    closed_by=?, closed_at=?
                WHERE id=? AND version=?"""
            params = (target, now, actor, now, item["id"], expected_version)
        else:
            sql = """UPDATE items
                SET status=?, version=version+1, updated_at=?
                WHERE id=? AND version=?"""
            params = (target, now, item["id"], expected_version)
        cur = self.conn.execute(sql, params)
        if cur.rowcount == 0:
            raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item["id"])

    def add_record(self, item: Dict[str, Any], kind: str, detail: str, status: str,
                   external_ref: Optional[str], recurrence_risk: bool,
                   expected_version: int, actor: str):
        now = utc_now()
        reopened = bool(item["status"] == "closed" and recurrence_risk)
        reopen_reason = f"出现复发风险措施：{kind}" if reopened else None
        try:
            cur = self.conn.execute(
                """INSERT INTO records(item_id, kind, detail, status, external_ref,
                   recurrence_risk, created_by, created_at, closed_by, closed_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (item["id"], kind, detail, status, external_ref, int(recurrence_risk),
                 actor, now, actor if status == "closed" else None,
                 now if status == "closed" else None),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc

        if reopened:
            sql = """UPDATE items SET
                    status='verification', version=version+1, updated_at=?,
                    verified_by=NULL, verified_at=NULL,
                    closed_by=NULL, closed_at=NULL, reopen_reason=?
                    WHERE id=? AND version=? AND status='closed'"""
        else:
            sql = """UPDATE items SET status=status, version=version+1, updated_at=?
                    WHERE id=? AND version=?"""
        params = ((now, reopen_reason, item["id"], expected_version) if reopened
                  else (now, item["id"], expected_version))
        cur_item = self.conn.execute(sql, params)
        if cur_item.rowcount == 0:
            raise ConflictError("版本冲突，请刷新后重试")
        record = self.get_record(int(cur.lastrowid))
        return record, self.get_item(item["id"]), reopened, reopen_reason

    def close_record(self, item: Dict[str, Any], record_id: int,
                     expected_version: int, actor: str):
        now = utc_now()
        cur_item = self.conn.execute(
            """UPDATE items SET version=version+1, updated_at=?
               WHERE id=? AND version=?""",
            (now, item["id"], expected_version),
        )
        if cur_item.rowcount == 0:
            raise ConflictError("版本冲突，请刷新后重试")
        cur = self.conn.execute(
            """UPDATE records SET status='closed', closed_by=?, closed_at=?
               WHERE id=? AND item_id=? AND status='open'""",
            (actor, now, record_id, item["id"]),
        )
        if cur.rowcount == 0:
            raise ConflictError("整改措施已关闭")
        return self.get_record(record_id), self.get_item(item["id"])

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        row = self.conn.execute(
            "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous = row["entry_hash"] if row else "GENESIS"
        event = make_entry(action, entity_type, entity_id, actor, detail, previous)
        cur = self.conn.execute(
            """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
               previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
            (event["action"], event["entity_type"], event["entity_id"], event["actor"],
             json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
             event["previous_hash"], event["entry_hash"], event["created_at"]),
        )
        event["id"] = int(cur.lastrowid)
        return event


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(
            self.db_path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    verified_by TEXT,
                    verified_at TEXT,
                    closed_by TEXT,
                    closed_at TEXT,
                    reopen_reason TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    recurrence_risk INTEGER NOT NULL DEFAULT 0,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    closed_by TEXT,
                    closed_at TEXT,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS idempotent_requests (
                    request_id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    response TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)
        self._migrate_column("items", "verified_by", "TEXT")
        self._migrate_column("items", "verified_at", "TEXT")
        self._migrate_column("items", "closed_by", "TEXT")
        self._migrate_column("items", "closed_at", "TEXT")
        self._migrate_column("items", "reopen_reason", "TEXT")
        self._migrate_column("records", "recurrence_risk", "INTEGER NOT NULL DEFAULT 0")
        self._migrate_column("records", "closed_by", "TEXT")
        self._migrate_column("records", "closed_at", "TEXT")

    def _migrate_column(self, table: str, column: str, definition: str) -> None:
        columns = {row["name"] for row in self.conn.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            with self.conn:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    @staticmethod
    def _fingerprint(operation: str, payload: Dict[str, Any]) -> str:
        raw = json.dumps(
            {"operation": operation, "payload": payload},
            ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str,
        ).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @contextmanager
    def operation(self, request_id: str, operation: str, payload: Dict[str, Any],
                  actor: str):
        fingerprint = self._fingerprint(operation, payload)
        gateway = Gateway(self.conn)
        with self._lock:
            try:
                self.conn.execute("BEGIN IMMEDIATE")
                row = self.conn.execute(
                    """SELECT operation, fingerprint, response FROM idempotent_requests
                       WHERE request_id=?""",
                    (request_id,),
                ).fetchone()
                if row is not None:
                    if row["operation"] != operation or row["fingerprint"] != fingerprint:
                        raise ConflictError("request_id已用于不同请求")
                    gateway.replay = True
                    gateway.result = json.loads(row["response"])
                    yield gateway
                    self.conn.execute("COMMIT")
                    return

                yield gateway

                response = json.dumps(
                    gateway.result, ensure_ascii=False, default=str, sort_keys=True)
                self.conn.execute(
                    """INSERT INTO idempotent_requests(request_id, operation, fingerprint,
                       response, actor, created_at) VALUES(?,?,?,?,?,?)""",
                    (request_id, operation, fingerprint, response, actor, utc_now()),
                )
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        transaction_started=False
        try:
            with self._lock:
                self.conn.execute("BEGIN IMMEDIATE")
                transaction_started=True
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now),
                )
                item_id = int(cur.lastrowid)
                self.conn.execute("COMMIT")
                transaction_started=False
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        finally:
            if transaction_started:
                self.conn.execute("ROLLBACK")
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        transaction_started=False
        try:
            with self._lock:
                self.conn.execute("BEGIN IMMEDIATE")
                transaction_started=True
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       recurrence_risk, created_by, created_at, closed_by, closed_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, 0, actor, now,
                     actor if status == "closed" else None,
                     now if status == "closed" else None),
                )
                record_id = int(cur.lastrowid)
                self.conn.execute("COMMIT")
                transaction_started=False
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        finally:
            if transaction_started:
                self.conn.execute("ROLLBACK")
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return Gateway._record(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [Gateway._record(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        transaction_started=False
        try:
            with self._lock:
                self.conn.execute("BEGIN IMMEDIATE")
                transaction_started=True
                row = self.conn.execute(
                    "SELECT * FROM audit_events ORDER BY id DESC LIMIT 1"
                ).fetchone()
                previous = row["entry_hash"] if row else "GENESIS"
                event = make_entry(action, entity_type, entity_id, actor, detail, previous)
                cur = self.conn.execute(
                    """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
                       previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                    (event["action"], event["entity_type"], event["entity_id"], event["actor"],
                     json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
                     event["previous_hash"], event["entry_hash"], event["created_at"]),
                )
                event_id = int(cur.lastrowid)
                self.conn.execute("COMMIT")
                transaction_started=False
        finally:
            if transaction_started:
                self.conn.execute("ROLLBACK")
        event["id"] = event_id
        return event

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def verify_audit_chain(self) -> bool:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            payload = {
                "action": row["action"], "entity_type": row["entity_type"],
                "entity_id": row["entity_id"], "actor": row["actor"],
                "detail": json.loads(row["detail"]), "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    def close(self) -> None:
        with self._lock:
            self.conn.close()
