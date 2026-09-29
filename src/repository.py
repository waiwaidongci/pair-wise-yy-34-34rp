from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import ACTION_KIND, STATES


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        # 关闭隐式事务，所有写操作通过 transaction() 显式 BEGIN IMMEDIATE 串行化
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False,
                                    isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()
        self._migrate()

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
                updated_at TEXT NOT NULL
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
                verified INTEGER NOT NULL DEFAULT 0,
                verified_by TEXT,
                verified_at TEXT,
                recurrence INTEGER NOT NULL DEFAULT 0,
                external_ref TEXT,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
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
            CREATE TABLE IF NOT EXISTS idempotency_keys (
                request_id TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                entity_id INTEGER,
                response TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """)

    def _migrate(self) -> None:
        # 兼容旧库：补充措施核验与复发风险字段
        for stmt in (
            "ALTER TABLE records ADD COLUMN verified INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE records ADD COLUMN verified_by TEXT",
            "ALTER TABLE records ADD COLUMN verified_at TEXT",
            "ALTER TABLE records ADD COLUMN recurrence INTEGER NOT NULL DEFAULT 0",
        ):
            try:
                self.conn.execute(stmt)
            except sqlite3.OperationalError:
                pass

    @contextmanager
    def transaction(self):
        """显式事务：BEGIN IMMEDIATE 立即获取写锁，提交/回滚与审计写入同生共死。"""
        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
            else:
                self.conn.execute("COMMIT")

    def _join(self, fn, *args, **kwargs):
        """已在事务中则直接执行，否则开启独立事务。"""
        if self.conn.in_transaction:
            return fn(*args, **kwargs)
        with self.transaction():
            return fn(*args, **kwargs)

    # ---------- 读取（不开启事务） ----------

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

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

    def get_record(self, record_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        if row is None:
            raise NotFoundError("记录不存在")
        return dict(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def unverified_action_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND kind=? AND verified=0",
                (item_id, ACTION_KIND),
            ).fetchone()
        return int(row["n"])

    # ---------- 写入（事务内版本） ----------

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        return self._join(self._create_item_tx, title, description, severity,
                          quantity, threshold, external_ref, actor)

    def _create_item_tx(self, title: str, description: str, severity: str,
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
        row = self.conn.execute("SELECT * FROM items WHERE id=?", (cur.lastrowid,)).fetchone()
        return self._item(row)

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str) -> Dict[str, Any]:
        return self._join(self._transition_item_tx, item_id, target,
                          expected_version, actor)

    def _transition_item_tx(self, item_id: int, target: str, expected_version: int,
                            actor: str) -> Dict[str, Any]:
        now = utc_now()
        cur = self.conn.execute(
            """UPDATE items SET status=?, version=version+1, updated_at=?
               WHERE id=? AND version=?""",
            (target, now, item_id, expected_version),
        )
        if cur.rowcount == 0:
            exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
            if exists is None:
                raise NotFoundError("项目不存在")
            raise ConflictError("版本冲突，请刷新后重试")
        row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        return self._item(row)

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str,
                   recurrence: bool = False) -> Dict[str, Any]:
        return self._join(self._add_record_tx, item_id, kind, detail, status,
                          external_ref, actor, recurrence)

    def _add_record_tx(self, item_id: int, kind: str, detail: str, status: str,
                        external_ref: Optional[str], actor: str,
                        recurrence: bool) -> Dict[str, Any]:
        now = utc_now()
        try:
            cur = self.conn.execute(
                """INSERT INTO records(item_id, kind, detail, status, external_ref,
                   created_by, created_at, recurrence) VALUES(?,?,?,?,?,?,?,?)""",
                (item_id, kind, detail, status, external_ref, actor, now,
                 1 if recurrence else 0),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        row = self.conn.execute("SELECT * FROM records WHERE id=?", (cur.lastrowid,)).fetchone()
        return dict(row)

    def close_record(self, record_id: int, item_id: int, actor: str) -> Dict[str, Any]:
        return self._join(self._close_record_tx, record_id, item_id, actor)

    def _close_record_tx(self, record_id: int, item_id: int, actor: str) -> Dict[str, Any]:
        cur = self.conn.execute(
            "UPDATE records SET status='closed' WHERE id=? AND item_id=? AND status='open'",
            (record_id, item_id),
        )
        if cur.rowcount == 0:
            row = self.conn.execute(
                "SELECT status FROM records WHERE id=? AND item_id=?", (record_id, item_id)
            ).fetchone()
            if row is None:
                raise NotFoundError("记录不存在")
            raise ConflictError("措施已关闭，不能重复关闭")
        row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def verify_record(self, record_id: int, item_id: int, actor: str) -> Dict[str, Any]:
        return self._join(self._verify_record_tx, record_id, item_id, actor)

    def _verify_record_tx(self, record_id: int, item_id: int, actor: str) -> Dict[str, Any]:
        now = utc_now()
        cur = self.conn.execute(
            """UPDATE records SET verified=1, verified_by=?, verified_at=?
               WHERE id=? AND item_id=? AND status='closed' AND verified=0""",
            (actor, now, record_id, item_id),
        )
        if cur.rowcount == 0:
            row = self.conn.execute(
                "SELECT status, verified FROM records WHERE id=? AND item_id=?",
                (record_id, item_id),
            ).fetchone()
            if row is None:
                raise NotFoundError("记录不存在")
            if row["status"] != "closed":
                raise ConflictError("措施尚未关闭，不能核验")
            raise ConflictError("措施已核验，不能重复核验")
        row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def revert_to_verification(self, item_id: int) -> Dict[str, Any]:
        return self._join(self._revert_to_verification_tx, item_id)

    def _revert_to_verification_tx(self, item_id: int) -> Dict[str, Any]:
        now = utc_now()
        cur = self.conn.execute(
            """UPDATE items SET status='verification', version=version+1, updated_at=?
               WHERE id=? AND status='closed'""",
            (now, item_id),
        )
        if cur.rowcount == 0:
            raise ConflictError("事故未关闭，无需退回核验")
        # 原核验失效：所有措施核验标记作废，需重新核验
        self.conn.execute(
            """UPDATE records SET verified=0, verified_by=NULL, verified_at=NULL
               WHERE item_id=? AND verified=1""",
            (item_id,),
        )
        row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        return self._item(row)

    def check_item_version(self, item_id: int, expected_version: int) -> None:
        self._join(self._check_item_version_tx, item_id, expected_version)

    def _check_item_version_tx(self, item_id: int, expected_version: int) -> None:
        now = utc_now()
        cur = self.conn.execute(
            "UPDATE items SET updated_at=? WHERE id=? AND version=?",
            (now, item_id, expected_version),
        )
        if cur.rowcount == 0:
            exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
            if exists is None:
                raise NotFoundError("项目不存在")
            raise ConflictError("版本冲突，请刷新后重试")

    # ---------- 幂等 ----------

    def get_idempotency(self, request_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT response FROM idempotency_keys WHERE request_id=?",
                (request_id,),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["response"])

    def store_idempotency(self, request_id: str, action: str, entity_id: Optional[int],
                          response: Dict[str, Any]) -> None:
        self._join(self._store_idempotency_tx, request_id, action, entity_id, response)

    def _store_idempotency_tx(self, request_id: str, action: str, entity_id: Optional[int],
                              response: Dict[str, Any]) -> None:
        self.conn.execute(
            """INSERT OR IGNORE INTO idempotency_keys(request_id, action, entity_id, response, created_at)
               VALUES(?,?,?,?,?)""",
            (request_id, action, entity_id,
             json.dumps(response, ensure_ascii=False, sort_keys=True), utc_now()),
        )

    # ---------- 审计 ----------

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        return self._join(self._append_audit_tx, action, entity_type, entity_id,
                          actor, detail)

    def _append_audit_tx(self, action: str, entity_type: str, entity_id: int,
                         actor: str, detail: dict) -> Dict[str, Any]:
        row = self.conn.execute(
            "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous = row["entry_hash"] if row else "GENESIS"
        event = make_entry(action, entity_type, entity_id, actor, detail, previous)
        self.conn.execute(
            """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
               previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
            (event["action"], event["entity_type"], event["entity_id"], event["actor"],
             json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
             event["previous_hash"], event["entry_hash"], event["created_at"]),
        )
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
