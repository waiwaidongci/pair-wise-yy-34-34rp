from __future__ import annotations

from typing import Any, Dict, Optional

from .domain import (ConflictError, NotFoundError, PermissionDenied,
                     ValidationError, ensure_role, normalize_severity,
                     require_number, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, ENTITY, RECORD_ROLES, TITLE,
                    VIEW_ROLES, completion_blockers, escalation_required,
                    priority_score, response_deadline_hours, role_for_transition,
                    validate_transition)

VERIFY_ROLES = set(["safety_manager"])


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    # ---------- 幂等与版本 ----------

    @staticmethod
    def _request_id(value: Any) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str) or not value.strip():
            raise ValidationError("request_id必须是非空字符串")
        value = value.strip()
        if len(value) > 100:
            raise ValidationError("request_id不能超过100个字符")
        return value

    @staticmethod
    def _require_version(value: Any) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValidationError("expected_version必须是正整数")
        return value

    @staticmethod
    def _optional_version(value: Any) -> Optional[int]:
        if value is None:
            return None
        return Service._require_version(value)

    def _idempotent(self, request_id: Optional[str]):
        """事务内：命中幂等键则返回已存响应，否则返回 None。"""
        if not request_id:
            return None
        return self.repository.get_idempotency(request_id)

    # ---------- 用例 ----------

    def create_item(self, payload: Dict[str, Any], actor: str, role: str,
                    request_id: Optional[str] = None) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        request_id = self._request_id(request_id)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        with self.repository.transaction():
            cached = self._idempotent(request_id)
            if cached is not None:
                return cached
            item = self.repository._create_item_tx(
                title, description, severity, quantity, threshold, external_ref, actor)
            result = self.enrich(item)
            self.repository.append_audit("create", ENTITY, item["id"], actor, {
                "title": title, "severity": severity, "quantity": quantity,
                "priority": priority_score(severity, quantity, threshold),
            })
            if request_id:
                self.repository.store_idempotency(request_id, "create", item["id"], result)
            return result

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str, request_id: Optional[str] = None) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        request_id = self._request_id(request_id)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        recurrence = payload.get("recurrence", False)
        if not isinstance(recurrence, bool):
            raise ValidationError("recurrence必须是布尔值")
        expected_version = self._optional_version(payload.get("expected_version"))
        with self.repository.transaction():
            cached = self._idempotent(request_id)
            if cached is not None:
                return cached
            item = self.repository.get_item(item_id)
            if item["status"] == "closed" and not recurrence:
                raise ConflictError("事故已关闭，不能新增普通记录；登记复发风险措施将退回核验")
            record = self.repository._add_record_tx(
                item_id, kind, detail, status, external_ref, actor, recurrence)
            if expected_version is not None:
                self.repository.check_item_version(item_id, expected_version)
            self.repository.append_audit("record", ENTITY, item_id, actor, {
                "record_id": record["id"], "kind": kind, "status": status,
                "recurrence": recurrence,
            })
            if recurrence and item["status"] == "closed":
                # 复发风险措施：原核验与关闭失效，事故退回核验，原因留痕
                self.repository.revert_to_verification(item_id)
                self.repository.append_audit("transition", ENTITY, item_id, actor, {
                    "from": "closed", "to": "verification",
                    "reason": "recurrence_measure_added",
                    "record_id": record["id"],
                })
            result = dict(record)
            if request_id:
                self.repository.store_idempotency(request_id, "record", item_id, result)
            return result

    def close_record(self, item_id: int, record_id: int, payload: Dict[str, Any],
                      actor: str, role: str,
                      request_id: Optional[str] = None) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        request_id = self._request_id(request_id)
        expected_version = self._require_version(payload.get("expected_version"))
        with self.repository.transaction():
            cached = self._idempotent(request_id)
            if cached is not None:
                return cached
            item = self.repository.get_item(item_id)
            record = self.repository.get_record(record_id)
            if record["item_id"] != item_id:
                raise NotFoundError("记录不存在")
            self.repository.check_item_version(item_id, expected_version)
            updated = self.repository.close_record(record_id, item_id, actor)
            self.repository.append_audit("record_close", ENTITY, item_id, actor, {
                "record_id": record_id, "kind": record["kind"],
            })
            result = dict(updated)
            if request_id:
                self.repository.store_idempotency(
                    request_id, "record_close", item_id, result)
            return result

    def verify_record(self, item_id: int, record_id: int, payload: Dict[str, Any],
                      actor: str, role: str,
                      request_id: Optional[str] = None) -> Dict[str, Any]:
        ensure_role(role, VERIFY_ROLES)
        actor = require_text(actor, "actor", 100)
        request_id = self._request_id(request_id)
        expected_version = self._require_version(payload.get("expected_version"))
        with self.repository.transaction():
            cached = self._idempotent(request_id)
            if cached is not None:
                return cached
            item = self.repository.get_item(item_id)
            record = self.repository.get_record(record_id)
            if record["item_id"] != item_id:
                raise NotFoundError("记录不存在")
            self.repository.check_item_version(item_id, expected_version)
            updated = self.repository.verify_record(record_id, item_id, actor)
            self.repository.append_audit("record_verify", ENTITY, item_id, actor, {
                "record_id": record_id, "kind": record["kind"],
            })
            result = dict(updated)
            if request_id:
                self.repository.store_idempotency(
                    request_id, "record_verify", item_id, result)
            return result

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str,
                   request_id: Optional[str] = None) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        request_id = self._request_id(request_id)
        expected_version = self._require_version(expected_version)
        with self.repository.transaction():
            cached = self._idempotent(request_id)
            if cached is not None:
                return cached
            item = self.repository.get_item(item_id)
            validate_transition(item["status"], target)
            ensure_role(role, role_for_transition(target))
            open_records = self.repository.open_record_count(item_id)
            unverified_actions = self.repository.unverified_action_count(item_id)
            blockers = completion_blockers(target, open_records, unverified_actions)
            if blockers:
                raise ConflictError("；".join(blockers))
            updated = self.repository.transition_item(item_id, target, expected_version, actor)
            self.repository.append_audit("transition", ENTITY, item_id, actor, {
                "from": item["status"], "to": target,
                "escalation_required": escalation_required(
                    item["severity"], item["quantity"], item["threshold"]),
            })
            result = self.enrich(updated)
            if request_id:
                self.repository.store_idempotency(request_id, "transition", item_id, result)
            return result

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result
