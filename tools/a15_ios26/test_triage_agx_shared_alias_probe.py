import unittest

from test_triage_agx_iouat_object_probe import complete_run as object_run, event
from triage_agx_shared_alias_probe import REQUIRED, REVISION, SHARED_REQUIRED, triage


def complete_run():
    prefix = object_run()
    prefix[0]["detail"] = prefix[0]["detail"].replace(
        "agx-iouat-object-v1", "agx-shared-alias-v1")
    details = {
        ("titan.shared-alias.create", "PASS"):
            "kr=0x0 out-size=0x10 address=0x100000000 size=0x4000 id=3",
        ("titan.shared-alias.buffer", "PASS"):
            "value=0xffffffe012300000 exact=0x8",
        ("titan.shared-alias.buffer-repeat", "PASS"):
            "value=0xffffffe012300000 exact=0x8",
        ("titan.shared-alias.descriptor", "PASS"):
            "value=0xffffffe012310000 exact=0x8",
        ("titan.shared-alias.backing", "PASS"):
            "value=0xffffffe012310000 exact=0x8",
        ("titan.shared-alias.user-map-object", "PASS"):
            "value=0xffffffe012320000 exact=0x8",
        ("titan.shared-alias.map-address", "PASS"):
            "source=0xffffffe012320000 offset=0x28 size=0x8 value=0x100000000",
        ("titan.shared-alias.map-length", "PASS"):
            "source=0xffffffe012320000 offset=0x30 size=0x8 value=0x4000",
        ("titan.shared-alias.registry", "PASS"):
            "client=0xffffffe012200000 id=3 buffer=0xffffffe012300000 descriptor=0xffffffe012310000 map=0xffffffe012320000",
        ("titan.shared-alias.alias-read", "PASS"):
            "physical=0x855b84100 kernel-alias=0xfffffff089e68100 bytes=0x20",
        ("titan.shared-alias.user-write", "PASS"):
            "kernel-read=0 offset=0x0 dual-alias-match=yes",
    }
    shared = [event(stage, status, details.get((stage, status), ""))
              for stage, status in SHARED_REQUIRED]
    anchor = next(index for index, item in enumerate(prefix)
                  if (item["stage"], item["status"]) ==
                  ("titan.agx-iouat-object", "STOP")) + 1
    run = prefix[:anchor] + shared + prefix[anchor:]
    assert [(item["stage"], item["status"]) for item in run] == list(REQUIRED)
    return run


class SharedAliasTriageTests(unittest.TestCase):
    def test_complete_run(self):
        result = triage(complete_run() + [event("titan.run", "FAIL")], "run-a")
        self.assertEqual(result["verdict"], "registered_user_dram_alias_observed")
        self.assertTrue(result["buffer_identity_ok"])
        self.assertTrue(result["byte_alias_ok"])
        self.assertIn("Parser acceptance", result["limits"])

    def test_wrong_revision(self):
        run = complete_run()
        run[0]["detail"] = run[0]["detail"].replace(REVISION, "old-revision")
        self.assertEqual(triage(run, "run-a")["verdict"],
                         "wrong_target_or_revision")

    def test_client_open_failure_is_attributed(self):
        run = complete_run()
        index = next(i for i, item in enumerate(run) if
                     (item["stage"], item["status"]) ==
                     ("titan.shared-alias.open", "PASS"))
        run = run[:index] + [event("titan.shared-alias.open", "BLOCKED", "kr=0xe00002c1")]
        result = triage(run, "run-a")
        self.assertEqual(result["verdict"], "incomplete_or_blocked")
        self.assertEqual(result["first_blocker"]["stage"], "titan.shared-alias.open")

    def test_registry_mismatch_is_not_alias_proof(self):
        run = complete_run()
        registry = next(item for item in run if item["stage"] ==
                        "titan.shared-alias.registry")
        registry["detail"] = registry["detail"].replace("id=3", "id=4")
        self.assertFalse(triage(run, "run-a")["buffer_identity_ok"])

    def test_write_readback_mismatch_is_not_success(self):
        run = complete_run()
        write = next(item for item in run if (item["stage"], item["status"]) ==
                     ("titan.shared-alias.user-write", "PASS"))
        write["detail"] = "kernel-read=0 offset=0x0 dual-alias-match=no"
        self.assertFalse(triage(run, "run-a")["byte_alias_ok"])

    def test_restoration_and_redirect_required(self):
        for stage in ("titan.shared-alias.restore", "titan.shared-alias.redirect"):
            with self.subTest(stage=stage):
                run = [item for item in complete_run() if item["stage"] != stage]
                self.assertEqual(triage(run, "run-a")["verdict"],
                                 "incomplete_or_blocked")

    def test_no_protected_stage(self):
        for stage in ("titan.iorvbar.read", "titan.physwrite.publish"):
            with self.subTest(stage=stage):
                run = complete_run() + [event(stage, "START")]
                self.assertEqual(triage(run, "run-a")["verdict"],
                                 "unexpected_active_stage")

    def test_run_separation(self):
        run = complete_run()
        split = next(i for i, item in enumerate(run) if item["stage"] ==
                     "titan.shared-alias")
        run[split:] = [dict(item, run_id="run-b") for item in run[split:]]
        self.assertEqual(triage(run, "run-a")["verdict"],
                         "incomplete_or_blocked")


if __name__ == "__main__":
    unittest.main()
