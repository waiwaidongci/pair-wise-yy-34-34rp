import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

from src.domain import ConflictError, PermissionDenied, ValidationError
from src.http_api import make_handler
from src.repository import Repository
from src.rules import STATES, TRANSITION_ROLES
from src.service import Service


class MeasureWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.item = self.service.create_item(
            {"title": "measure item", "description": "measure linkage",
             "severity": "serious", "quantity": 5, "threshold": 10},
            "creator", "reporter", request_id="create-1")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _to_verification(self):
        current = self.item
        for target in ("investigating", "corrective_action"):
            current = self.service.transition(
                current["id"], target, current["version"],
                "reviewer", TRANSITION_ROLES[target][0])
        return current

    def _add_action(self, ref, status="open"):
        return self.service.add_record(
            self.item["id"],
            {"kind": "action", "detail": "install guard", "status": status,
             "external_ref": ref, "expected_version": None},
            "recorder", "investigator", request_id="add-" + ref)

    def test_close_requires_measures_closed_and_verified(self):
        current = self._to_verification()
        # 措施未关闭 → 不能进入核验后的关闭
        measure = self._add_action("ACT-1")
        with self.assertRaises(ConflictError):
            self.service.transition(
                current["id"], "closed", current["version"],
                "manager", "safety_manager")
        #  investigator 关闭措施
        closed = self.service.close_record(
            self.item["id"], measure["id"],
            {"expected_version": current["version"]},
            "recorder", "investigator", request_id="close-1")
        self.assertEqual(closed["status"], "closed")
        # 措施已关闭但未核验 → 仍不能关闭事故
        with self.assertRaises(ConflictError):
            self.service.transition(
                current["id"], "closed", current["version"],
                "manager", "safety_manager")
        # 核验措施：仅安全管理员
        with self.assertRaises(PermissionDenied):
            self.service.verify_record(
                self.item["id"], measure["id"],
                {"expected_version": current["version"]},
                "recorder", "investigator")
        verified = self.service.verify_record(
            self.item["id"], measure["id"],
            {"expected_version": current["version"]},
            "manager", "safety_manager", request_id="verify-1")
        self.assertEqual(verified["verified"], 1)
        # 核验后进入核验状态，再关闭事故
        in_verification = self.service.transition(
            current["id"], "verification", current["version"],
            "manager", "safety_manager", request_id="verify-item-1")
        done = self.service.transition(
            current["id"], "closed", in_verification["version"],
            "manager", "safety_manager", request_id="close-item-1")
        self.assertEqual(done["status"], "closed")

    def test_verify_requires_closed_measure(self):
        current = self._to_verification()
        measure = self._add_action("ACT-2")
        with self.assertRaises(ConflictError):
            self.service.verify_record(
                self.item["id"], measure["id"],
                {"expected_version": current["version"]},
                "manager", "safety_manager")

    def test_recurrence_measure_after_close_reverts_and_keeps_reason(self):
        current = self._to_verification()
        measure = self._add_action("ACT-3", status="closed")
        self.service.verify_record(
            self.item["id"], measure["id"],
            {"expected_version": current["version"]},
            "manager", "safety_manager")
        in_verification = self.service.transition(
            current["id"], "verification", current["version"],
            "manager", "safety_manager")
        done = self.service.transition(
            current["id"], "closed", in_verification["version"],
            "manager", "safety_manager")
        self.assertEqual(done["status"], "closed")
        # 关闭后出现复发风险措施
        recurrence = self.service.add_record(
            self.item["id"],
            {"kind": "action", "detail": "recurrence risk found",
             "status": "open", "external_ref": "REC-1", "recurrence": True},
            "recorder", "investigator", request_id="rec-1")
        self.assertEqual(recurrence["recurrence"], 1)
        reverted = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(reverted["status"], "verification")
        # 原核验失效：所有措施核验标记作废
        records = self.service.list_records(self.item["id"], "viewer")
        self.assertTrue(all(r["verified"] == 0 for r in records))
        # 原因留痕：审计中保留 closed->verification 及原因
        events = self.service.audit("viewer", self.item["id"])
        revert_events = [e for e in events
                         if e["action"] == "transition"
                         and e["detail"].get("reason") == "recurrence_measure_added"]
        self.assertEqual(len(revert_events), 1)
        self.assertEqual(revert_events[0]["detail"]["from"], "closed")
        self.assertEqual(revert_events[0]["detail"]["reason"], "recurrence_measure_added")
        self.assertTrue(self.repo.verify_audit_chain())

    def test_reclose_after_revert_requires_reverifying_all_measures(self):
        current = self._to_verification()
        measure = self._add_action("ACT-5", status="closed")
        self.service.verify_record(
            self.item["id"], measure["id"],
            {"expected_version": current["version"]},
            "manager", "safety_manager")
        in_verification = self.service.transition(
            current["id"], "verification", current["version"],
            "manager", "safety_manager")
        self.service.transition(
            current["id"], "closed", in_verification["version"],
            "manager", "safety_manager")
        recurrence = self.service.add_record(
            self.item["id"],
            {"kind": "action", "detail": "recurrence", "status": "open",
             "external_ref": "REC-2", "recurrence": True},
            "recorder", "investigator")
        reverted = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(reverted["status"], "verification")
        # 复发措施已关闭，但原措施核验已失效 → 仍不能关闭
        self.service.close_record(
            self.item["id"], recurrence["id"],
            {"expected_version": reverted["version"]},
            "recorder", "investigator")
        with self.assertRaises(ConflictError):
            self.service.transition(
                self.item["id"], "closed", reverted["version"],
                "manager", "safety_manager")
        # 重新核验全部措施后才能关闭
        self.service.verify_record(
            self.item["id"], measure["id"],
            {"expected_version": reverted["version"]},
            "manager", "safety_manager")
        self.service.verify_record(
            self.item["id"], recurrence["id"],
            {"expected_version": reverted["version"]},
            "manager", "safety_manager")
        done = self.service.transition(
            self.item["id"], "closed", reverted["version"],
            "manager", "safety_manager")
        self.assertEqual(done["status"], "closed")
        self.assertTrue(self.repo.verify_audit_chain())

    def test_plain_record_on_closed_item_rejected(self):
        current = self._to_verification()
        measure = self._add_action("ACT-4", status="closed")
        self.service.verify_record(
            self.item["id"], measure["id"],
            {"expected_version": current["version"]},
            "manager", "safety_manager")
        in_verification = self.service.transition(
            current["id"], "verification", current["version"],
            "manager", "safety_manager")
        self.service.transition(
            current["id"], "closed", in_verification["version"],
            "manager", "safety_manager")
        with self.assertRaises(ConflictError):
            self.service.add_record(
                self.item["id"],
                {"kind": "evidence", "detail": "late evidence", "status": "open"},
                "recorder", "investigator")


class ConcurrencyAndIdempotencyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _open_item(self):
        item = self.service.create_item(
            {"title": "concurrency item", "description": "two terminals",
             "severity": "moderate", "quantity": 2, "threshold": 10},
            "creator", "reporter")
        current = item
        for target in ("investigating", "corrective_action"):
            current = self.service.transition(
                current["id"], target, current["version"],
                "reviewer", TRANSITION_ROLES[target][0])
        return current

    def test_stale_version_rolls_back_without_audit(self):
        current = self._open_item()
        before = len(self.service.audit("viewer", current["id"]))
        with self.assertRaises(ConflictError):
            self.service.transition(
                current["id"], "verification", current["version"] + 100,
                "manager", "safety_manager")
        after = len(self.service.audit("viewer", current["id"]))
        self.assertEqual(before, after)
        item = self.service.get_item(current["id"], "viewer")
        self.assertEqual(item["status"], "corrective_action")
        self.assertEqual(item["version"], current["version"])

    def test_audit_failure_rolls_back_data_change(self):
        current = self._open_item()
        original = self.repo._append_audit_tx

        def boom(*args, **kwargs):
            raise RuntimeError("audit write failed")

        self.repo._append_audit_tx = boom
        try:
            with self.assertRaises(RuntimeError):
                self.service.transition(
                    current["id"], "verification", current["version"],
                    "manager", "safety_manager")
        finally:
            self.repo._append_audit_tx = original
        item = self.service.get_item(current["id"], "viewer")
        self.assertEqual(item["status"], "corrective_action")
        self.assertEqual(item["version"], current["version"])
        self.assertTrue(self.repo.verify_audit_chain())

    def test_idempotent_retry_reuses_request_number(self):
        item = self.service.create_item(
            {"title": "idem item", "description": "retry same number",
             "severity": "minor", "quantity": 1, "threshold": 10},
            "creator", "reporter", request_id="fixed-request")
        retry = self.service.create_item(
            {"title": "idem item", "description": "retry same number",
             "severity": "minor", "quantity": 1, "threshold": 10},
            "creator", "reporter", request_id="fixed-request")
        self.assertEqual(item["id"], retry["id"])
        self.assertEqual(item["version"], retry["version"])
        other = self.service.create_item(
            {"title": "idem item", "description": "different request",
             "severity": "minor", "quantity": 1, "threshold": 10},
            "creator", "reporter", request_id="other-request")
        self.assertNotEqual(item["id"], other["id"])
        self.assertTrue(self.repo.verify_audit_chain())

    def test_concurrent_transitions_one_wins(self):
        current = self._open_item()
        results = []
        errors = []

        def worker():
            try:
                results.append(self.service.transition(
                    current["id"], "verification", current["version"],
                    "manager", "safety_manager",
                    request_id="tx-" + threading.current_thread().name))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 5)
        self.assertTrue(all(isinstance(e, ConflictError) for e in errors))
        item = self.service.get_item(current["id"], "viewer")
        self.assertEqual(item["status"], "verification")
        self.assertEqual(item["version"], current["version"] + 1)
        self.assertTrue(self.repo.verify_audit_chain())


class HttpApiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), make_handler(self.service, str(Path(__file__).parent.parent / "static")))
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.repo.close()
        self.tmp.cleanup()

    def _request(self, method, path, body=None, headers=None):
        data = None
        hdrs = {"X-Actor": "tester", "X-Role": "safety_manager"}
        if headers:
            hdrs.update(headers)
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        req = Request(self.base + path, data=data, headers=hdrs, method=method)
        try:
            with urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_http_measure_flow_and_request_id(self):
        status, payload = self._request("POST", "/api/items", {
            "title": "http item", "description": "via http",
            "severity": "minor", "quantity": 1, "threshold": 10},
            headers={"X-Role": "reporter", "X-Request-Id": "http-create"})
        self.assertEqual(status, 201)
        item = payload
        # 直接尝试关闭（无措施）→ 冲突
        status, payload = self._request(
            "POST", "/api/items/%d/transition" % item["id"],
            {"target": "closed", "expected_version": item["version"]},
            headers={"X-Request-Id": "http-close-bad"})
        self.assertEqual(status, 409)
        # 重试同一请求编号得到相同结果
        status2, payload2 = self._request(
            "POST", "/api/items/%d/transition" % item["id"],
            {"target": "closed", "expected_version": item["version"]},
            headers={"X-Request-Id": "http-close-bad"})
        self.assertEqual(status2, status)
        self.assertEqual(payload2, payload)


if __name__ == "__main__":
    unittest.main()
