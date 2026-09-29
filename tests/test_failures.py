import tempfile, threading, unittest
from pathlib import Path
from src.domain import ConflictError, PermissionDenied, ValidationError
from src.repository import Gateway, Repository
from src.service import Service
from src.rules import STATES, TRANSITION_ROLES


class FailureTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.repo=Repository(str(Path(self.tmp.name)/"test.db"))
        self.service=Service(self.repo)
        self.item=self.service.create_item(
            {"title":"failure item","description":"failure scenarios",
             "severity":'serious',"quantity":5,"threshold":10,"external_ref":"FAIL-1"},
            "creator",'reporter',"req-create-fail")

    def tearDown(self): self.repo.close(); self.tmp.cleanup()

    def move_to_verification(self, item, status="closed"):
        current=item
        if status == "open":
            targets=STATES[1:3]
        else:
            targets=STATES[1:-1]
        for target in targets:
            current=self.service.transition(
                current["id"],target,current["version"],"reviewer",
                TRANSITION_ROLES[target][0],f"req-move-{target}-{current['version']}")
        if status == "open":
            return current
        closed=self.service.transition(
            current["id"],STATES[-1],current["version"],"reviewer",
            TRANSITION_ROLES[STATES[-1]][0],"req-close-setup")
        return closed

    def test_permission_version_duplicate_and_invariant(self):
        with self.assertRaises(PermissionDenied):
            self.service.transition(
                self.item["id"],STATES[1],1,"attacker","viewer","req-denied")
        with self.assertRaises(ConflictError):
            self.service.transition(
                self.item["id"],STATES[1],99,"reviewer",
                TRANSITION_ROLES[STATES[1]][0],"req-stale-transition")

        payload={"kind":"action","detail":"same reference","status":"open",
                 "external_ref":"DUP-1","expected_version":self.item["version"]}
        self.service.add_record(self.item["id"],payload,"recorder",'investigator',"req-dup-1")
        with self.assertRaises(ConflictError):
            self.service.add_record(self.item["id"],payload,"recorder",'investigator',"req-dup-2")

        current=self.service.get_item(self.item["id"],"viewer")
        current=self.move_to_verification(current,status="open")
        with self.assertRaises(ConflictError):
            self.service.transition(
                current["id"],STATES[3],current["version"],"reviewer",
                TRANSITION_ROLES[STATES[3]][0],"req-verification-with-open")

    def test_records_require_read_version_and_become_invalid_after_recurrence(self):
        current=self.move_to_verification(self.item,status="closed")
        stale_version=current["version"]
        self.service.add_record(
            current["id"],
            {"kind":"evidence","detail":"ordinary update","status":"closed",
             "external_ref":"E-1","expected_version":stale_version},
            "recorder",'investigator',"req-evidence-bump")
        current=self.service.get_item(current["id"],"viewer")
        with self.assertRaises(ConflictError):
            self.service.add_record(
                current["id"],
                {"kind":"action","detail":"stale recurrence","status":"open",
                 "external_ref":"REC-STALE","recurrence_risk":True,
                 "expected_version":stale_version},
                "recorder",'safety_manager',"req-recurrence-stale")
        self.assertEqual(self.service.get_item(current["id"],"viewer")["status"],"closed")

    def test_audit_write_failure_rolls_back_everything(self):
        version_before=self.item["version"]
        original=Gateway.append_audit
        def failing_audit(gw,*args,**kwargs):
            raise RuntimeError("audit unavailable")
        Gateway.append_audit=failing_audit
        try:
            with self.assertRaises(RuntimeError):
                self.service.transition(
                    self.item["id"],STATES[1],version_before,"reviewer",
                    "investigator","req-failing-audit")
        finally:
            Gateway.append_audit=original

        stored=self.service.get_item(self.item["id"],"viewer")
        self.assertEqual(stored["status"],STATES[0])
        self.assertEqual(stored["version"],version_before)
        self.assertEqual(len(self.service.audit("viewer",self.item["id"])),1)
        self.assertTrue(self.repo.verify_audit_chain())

        retried=self.service.transition(
            self.item["id"],STATES[1],version_before,"reviewer",
            "investigator","req-failing-audit")
        self.assertEqual(retried["status"],STATES[1])
        self.assertEqual(retried["version"],version_before+1)

    def test_same_request_id_replays_same_response(self):
        payload={"kind":"evidence","detail":"idempotent","status":"closed",
                 "external_ref":"IDEM-1","expected_version":self.item["version"]}
        first=self.service.add_record(
            self.item["id"],payload,"recorder",'investigator',"req-idem-record")
        second=self.service.add_record(
            self.item["id"],payload,"recorder",'investigator',"req-idem-record")
        self.assertEqual(first["id"],second["id"])
        self.assertEqual(len(self.service.list_records(self.item["id"],"viewer")),1)

        changed=dict(payload)
        changed["detail"]="different request"
        with self.assertRaises(ConflictError):
            self.service.add_record(
                self.item["id"],changed,"recorder",'investigator',"req-idem-record")

    def test_closed_incident_open_measure_must_be_recurrence(self):
        current=self.move_to_verification(self.item,status="closed")
        with self.assertRaises(ValidationError):
            self.service.add_record(
                current["id"],
                {"kind":"action","detail":"ordinary open action","status":"open",
                 "external_ref":"OPEN-NORMAL","recurrence_risk":False,
                 "expected_version":current["version"]},
                "recorder",'safety_manager',"req-normal-open-after-close")
        stored=self.service.get_item(current["id"],"viewer")
        self.assertEqual(stored["status"],"closed")
        self.assertEqual(stored["version"],current["version"])

    def test_concurrent_same_version_transition_leaves_single_update(self):
        version=self.item["version"]
        start=threading.Barrier(2)
        results=[]

        def submit(label, request_id):
            start.wait()
            try:
                results.append(("ok", self.service.transition(
                    self.item["id"],STATES[1],version,"reviewer",
                    "investigator",request_id)))
            except Exception as exc:
                results.append(("conflict", exc))

        first=threading.Thread(target=submit,args=("a","req-concurrent-a"))
        second=threading.Thread(target=submit,args=("b","req-concurrent-b"))
        first.start(); second.start(); first.join(); second.join()

        statuses=sorted(status for status,_ in results)
        self.assertEqual(statuses,["conflict","ok"])
        stored=self.service.get_item(self.item["id"],"viewer")
        self.assertEqual(stored["status"],STATES[1])
        self.assertEqual(stored["version"],version+1)

    def test_closed_recurrence_measure_also_invalidates_verification(self):
        current=self.move_to_verification(self.item,status="closed")
        result=self.service.add_record(
            current["id"],
            {"kind":"recurrence_action","detail":"risk identified and immediately fixed",
             "status":"closed","external_ref":"REC-CLOSED","recurrence_risk":True,
             "expected_version":current["version"]},
            "recorder",'safety_manager',"req-closed-recurrence")
        updated=result["item"]
        self.assertTrue(result["reopened_to_verification"])
        self.assertEqual(updated["status"],STATES[3])
        self.assertIsNone(updated["verified_at"])
        self.assertIsNone(updated["closed_at"])
        self.assertEqual(self.repo.open_record_count(current["id"]),0)

    def test_only_safety_manager_can_verify_after_recurrence(self):
        with self.assertRaises(ValidationError):
            self.service.add_record(
                self.item["id"],
                {"kind":"action","detail":"missing version","status":"open"},
                "recorder",'investigator',"req-missing-version")
        with self.assertRaises(ValidationError):
            self.service.transition(
                self.item["id"],STATES[1],True,"reviewer",
                "investigator","req-bad-version")


if __name__=="__main__": unittest.main()
