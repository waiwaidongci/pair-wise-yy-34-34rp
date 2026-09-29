import tempfile, unittest
from pathlib import Path
from src.repository import Gateway, Repository
from src.service import Service
from src.rules import STATES, TRANSITION_ROLES


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.repo=Repository(str(Path(self.tmp.name)/"test.db"))
        self.service=Service(self.repo)

    def tearDown(self):
        self.repo.close(); self.tmp.cleanup()

    def manager(self, item_id, target, version):
        return self.service.transition(
            item_id, target, version, "safety", "safety_manager",
            f"req-transition-{item_id}-{target}-{version}")

    def investigator(self, item_id, target, version):
        return self.service.transition(
            item_id, target, version, "investigator", "investigator",
            f"req-transition-{item_id}-{target}-{version}")

    def test_complete_workflow_recurrence_reverification_and_audit(self):
        item=self.service.create_item(
            {"title":"workflow item","description":"complete business flow",
             "severity":'serious',"quantity":12,"threshold":6,"external_ref":"WF-1"},
            "creator",'reporter',"req-create-wf")
        self.assertEqual(item["status"],STATES[0])

        added=self.service.add_record(
            item["id"],
            {"kind":"action","detail":"protective equipment provided",
             "status":"closed","external_ref":"EV-1","expected_version":item["version"]},
            "recorder",'investigator',"req-record-closed-wf")
        current=added["item"]
        self.assertEqual(current["version"],2)

        current=self.investigator(current["id"],STATES[1],current["version"])
        current=self.investigator(current["id"],STATES[2],current["version"])
        current=self.manager(current["id"],STATES[3],current["version"])
        self.assertIsNotNone(current["verified_at"])
        current=self.manager(current["id"],STATES[4],current["version"])
        self.assertEqual(current["status"],STATES[-1])
        self.assertIsNotNone(current["closed_at"])
        closed_version=current["version"]

        reopened=self.service.add_record(
            current["id"],
            {"kind":"recurrence_action","detail":"same hazard appears again",
             "status":"open","external_ref":"REC-1","recurrence_risk":True,
             "expected_version":closed_version},
            "recorder",'safety_manager',"req-record-recurrence-wf")
        current=reopened["item"]
        self.assertTrue(reopened["reopened_to_verification"])
        self.assertEqual(current["status"],STATES[3])
        self.assertIsNone(current["verified_by"])
        self.assertIsNone(current["verified_at"])
        self.assertIsNone(current["closed_by"])
        self.assertIsNone(current["closed_at"])
        self.assertIn("复发风险",current["reopen_reason"])

        with self.assertRaises(Exception):
            self.manager(current["id"],STATES[4],current["version"])

        record_id=reopened["id"]
        closed_record=self.service.close_record(
            current["id"],record_id,
            {"expected_version":current["version"]},
            "safety",'safety_manager',"req-close-recurrence-wf")
        current=closed_record["item"]

        with self.assertRaises(Exception):
            self.manager(current["id"],STATES[4],current["version"])

        current=self.manager(current["id"],STATES[3],current["version"])
        self.assertIsNotNone(current["verified_at"])
        current=self.manager(current["id"],STATES[4],current["version"])
        self.assertEqual(current["status"],STATES[-1])

        records=self.service.list_records(current["id"],"viewer")
        self.assertEqual(len(records),2)
        self.assertTrue(all(record["status"]=="closed" for record in records))
        events=self.service.audit("viewer",current["id"])
        self.assertTrue(self.repo.verify_audit_chain())
        self.assertTrue(any(event["action"]=="reopen_to_verification" for event in events))
        self.assertGreaterEqual(len(events),9)


if __name__=="__main__": unittest.main()
