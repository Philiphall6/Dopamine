import unittest

from test_triage_agx_iouat_object_probe import event
from test_triage_agx_shared_alias_probe import complete_run as shared_run
from triage_agx_owned_queue_probe import OWN_REQUIRED, REQUIRED, REVISION, triage


def complete_run():
    run = shared_run()
    run[0]["detail"] = run[0]["detail"].replace(
        "agx-shared-alias-v1", "agx-own-queue-v2"
    )
    table = next(item for item in run if item["stage"] == "titan.shared-alias.table")
    table["detail"] = "value=0xffffffe012210000 exact=0x8"
    details = {
        ("titan.own-queue.device", "PASS"):
            "value=0xffffffe010000000 exact=0x8",
        ("titan.own-queue.array-count", "PASS"):
            "source=0xffffffe012220000 offset=0x28 size=0x4 value=0x400",
        ("titan.own-queue.input-size", "PASS"):
            "source=0xffffffe010000000 offset=0x278 size=0x4 value=0x410",
        ("titan.own-queue.create", "PASS"):
            "kr=0x0 output-size=0x10 id=2 token=0x55 count=1024",
        ("titan.own-queue.object", "PASS"):
            "value=0xffffffe012400000 exact=0x8",
        ("titan.own-queue.object-repeat", "PASS"):
            "value=0xffffffe012400000 exact=0x8",
        ("titan.own-queue.table", "PASS"):
            "value=0xffffffe012210000 exact=0x8",
        ("titan.own-queue.device-backref", "PASS"):
            "value=0xffffffe010000000 exact=0x8",
        ("titan.own-queue.token", "PASS"):
            "source=0xffffffe012400000 offset=0x558 size=0x8 value=0x55",
        ("titan.own-queue.ready", "PASS"):
            "source=0xffffffe012400000 offset=0x5e8 size=0x1 value=0x1",
        ("titan.own-queue.buffer-repeat", "PASS"):
            "value=0xffffffe012300000 exact=0x8",
        ("titan.own-queue.identity", "PASS"):
            "queue=0xffffffe012400000 table=same device=same token=same ready=1 resource=0xffffffe012500000 buffer-id=3 buffer-stable=yes",
    }
    own = [event(stage, status, details.get((stage, status), ""))
           for stage, status in OWN_REQUIRED]
    anchor = next(index for index, item in enumerate(run)
                  if (item["stage"], item["status"]) ==
                  ("titan.shared-alias", "PASS"))
    run[anchor:anchor] = own
    assert [(item["stage"], item["status"]) for item in run] == list(REQUIRED)
    return run


class OwnedQueueTriageTests(unittest.TestCase):
    def test_complete_run(self):
        result = triage(complete_run() + [event("titan.run", "FAIL")], "run-a")
        self.assertEqual(result["verdict"], "owned_queue_and_buffer_observed")
        self.assertTrue(result["alias_ok"])
        self.assertTrue(result["queue_identity_ok"])
        self.assertIn("parser consumption", result["limits"])

    def test_wrong_revision(self):
        run = complete_run()
        run[0]["detail"] = run[0]["detail"].replace(REVISION, "old-revision")
        self.assertEqual(triage(run, "run-a")["verdict"], "wrong_target_or_revision")

    def test_returned_id_alone_is_not_proof(self):
        run = complete_run()
        run = [item for item in run if item["stage"] not in
               {"titan.own-queue.object", "titan.own-queue.object-repeat",
                "titan.own-queue.object-vtable-identity", "titan.own-queue.identity"}]
        self.assertEqual(triage(run, "run-a")["verdict"], "incomplete_or_blocked")

    def test_buffer_changed_after_creation(self):
        run = complete_run()
        item = next(item for item in run if item["stage"] ==
                    "titan.own-queue.buffer-repeat")
        item["detail"] = "value=0xffffffe012600000 exact=0x8"
        self.assertFalse(triage(run, "run-a")["queue_identity_ok"])

    def test_wrong_device_input_size(self):
        run = complete_run()
        item = next(item for item in run if item["stage"] ==
                    "titan.own-queue.input-size")
        item["detail"] = item["detail"].replace("0x410", "0x408")
        self.assertEqual(triage(run, "run-a")["verdict"], "incomplete_or_blocked")

    def test_missing_close_or_restoration(self):
        for stage in ("titan.own-queue.connection-close", "titan.shared-alias.restore"):
            with self.subTest(stage=stage):
                run = [item for item in complete_run() if item["stage"] != stage]
                self.assertEqual(triage(run, "run-a")["verdict"],
                                 "incomplete_or_blocked")

    def test_crash_after_selector_is_incomplete(self):
        run = complete_run()
        index = next(i for i, item in enumerate(run) if
                     (item["stage"], item["status"]) ==
                     ("titan.own-queue.create", "PASS"))
        self.assertEqual(triage(run[:index], "run-a")["verdict"],
                         "incomplete_or_blocked")

    def test_forbidden_stage(self):
        run = complete_run() + [event("titan.command-buffers", "START")]
        self.assertEqual(triage(run, "run-a")["verdict"],
                         "unexpected_active_stage")


if __name__ == "__main__":
    unittest.main()
