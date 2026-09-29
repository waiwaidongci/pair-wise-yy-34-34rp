from __future__ import annotations

from typing import Any, Dict, Optional

from .domain import (ConflictError, ensure_role, normalize_severity,
                     require_bool, require_expected_version, require_number,
                     require_request_id, require_text)
from .repository import Gateway, Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, ENTITY, RECORD_ROLES,
                    VIEW_ROLES, completion_blockers, escalation_required,
                    priority_score, response_deadline_hours, role_for_transition,
                    validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def _resolve_request_id(self, header_request_id: Optional[str],
                            body_request_id: Optional[str] = None) -> str:
        if body_request_id is not None and header_request_id is not None \
                and body_request_id != header_request_id:
            from .domain import ValidationError
            raise ValidationError("请求头和请求体中的request_id不一致")
        request_id = header_request_id if header_request_id is not None else body_request_id
        return require_request_id(request_id)

    def _request_id(self, payload: Dict[str, Any], header_request_id: Optional[str]) -> str:
        return self._resolve_request_id(header_request_id, payload.pop("request_id", None))

    def _write(self, request_id: str, operation: str, fingerprint: Dict[str, Any],
               actor: str, worker):
        idempotency_payload = dict(fingerprint)
        idempotency_payload["actor"] = actor
        with self.repository.operation(request_id, operation, idempotency_payload, actor) as gw:
            if gw.replay:
                return gw.result
            worker(gw)
            if gw.result is None:
                raise RuntimeError("写操作未生成响应")
        return gw.result

    def create_item(self, payload: Dict[str, Any], actor: str, role: str,
                    header_request_id: Optional[str] = None) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        request_id = self._request_id(payload, header_request_id)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        fingerprint = {
            "title": title, "description": description, "severity": severity,
            "quantity": quantity, "threshold": threshold, "external_ref": external_ref,
        }

        def worker(gw: Gateway) -> None:
            item = gw.create_item(title, description, severity, quantity, threshold,
                                  external_ref, actor)
            gw.append_audit("create", ENTITY, item["id"], actor, {
                "title": title, "severity": severity, "quantity": quantity,
                "priority": priority_score(severity, quantity, threshold),
            })
            gw.result = self.enrich(item)

        return self._write(request_id, "create_item", fingerprint, actor, worker)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str, header_request_id: Optional[str] = None) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        request_id = self._request_id(payload, header_request_id)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            from .domain import ValidationError
            raise ValidationError("status必须是open或closed")
        expected_version = require_expected_version(payload.get("expected_version"))
        recurrence_value = payload.get("recurrence_risk", payload.get("recurrence", False))
        recurrence_risk = require_bool(recurrence_value, "recurrence_risk")
        if kind in ("recurrence", "recurrence_action"):
            kind = "recurrence_action"
            recurrence_risk = True
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        fingerprint = {
            "item_id": item_id, "kind": kind, "detail": detail, "status": status,
            "external_ref": external_ref, "recurrence_risk": recurrence_risk,
            "expected_version": expected_version,
        }

        def worker(gw: Gateway) -> None:
            item = gw.get_item(item_id)
            if item["status"] == "closed" and status == "open" and not recurrence_risk:
                from .domain import ValidationError
                raise ValidationError("事故关闭后新增的未关闭措施必须标记为复发风险措施")
            record, updated, reopened, reopen_reason = gw.add_record(
                item, kind, detail, status, external_ref, recurrence_risk,
                expected_version, actor)
            record_detail = {
                "record_id": record["id"], "kind": kind, "status": status,
                "recurrence_risk": recurrence_risk,
            }
            gw.append_audit("record", ENTITY, item_id, actor, record_detail)
            if reopened:
                gw.append_audit("reopen_to_verification", ENTITY, item_id, actor, {
                    "record_id": record["id"],
                    "reason": reopen_reason,
                    "from": "closed",
                    "to": "verification",
                })
            result = dict(record)
            result["item"] = self.enrich(updated)
            result["reopened_to_verification"] = reopened
            result["reopen_reason"] = reopen_reason
            gw.result = result

        return self._write(request_id, "add_record", fingerprint, actor, worker)

    def close_record(self, item_id: int, record_id: int, payload: Dict[str, Any],
                     actor: str, role: str,
                     header_request_id: Optional[str] = None) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        request_id = self._request_id(payload, header_request_id)
        expected_version = require_expected_version(payload.get("expected_version"))
        fingerprint = {
            "item_id": item_id, "record_id": record_id,
            "expected_version": expected_version,
        }

        def worker(gw: Gateway) -> None:
            item = gw.get_item(item_id)
            record, updated = gw.close_record(item, record_id, expected_version, actor)
            gw.append_audit("close_record", ENTITY, item_id, actor, {
                "record_id": record_id,
            })
            result = dict(record)
            result["item"] = self.enrich(updated)
            gw.result = result

        return self._write(request_id, "close_record", fingerprint, actor, worker)

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str,
                   header_request_id: Optional[str] = None,
                   request_id: Optional[str] = None) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        request_id = self._resolve_request_id(header_request_id, request_id)
        expected_version = require_expected_version(expected_version)
        if not isinstance(target, str) or not target.strip():
            from .domain import ValidationError
            raise ValidationError("target不能为空")
        target = target.strip()
        ensure_role(role, role_for_transition(target))
        fingerprint = {
            "item_id": item_id, "target": target,
            "expected_version": expected_version,
        }

        def worker(gw: Gateway) -> None:
            item = gw.get_item(item_id)
            validate_transition(item["status"], target)
            blockers = completion_blockers(
                target, gw.open_record_count(item_id),
                verified=bool(item.get("verified_at")))
            if blockers:
                raise ConflictError("；".join(blockers))
            updated = gw.transition_item(item, target, expected_version, actor)
            gw.append_audit("transition", ENTITY, item_id, actor, {
                "from": item["status"], "to": target,
                "reverified": item["status"] == "verification" and target == "verification",
                "reopen_reason": item.get("reopen_reason"),
                "escalation_required": escalation_required(
                    item["severity"], item["quantity"], item["threshold"]),
            })
            gw.result = self.enrich(updated)

        return self._write(request_id, "transition", fingerprint, actor, worker)

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
