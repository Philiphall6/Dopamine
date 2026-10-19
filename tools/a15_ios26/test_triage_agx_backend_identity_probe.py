import unittest

from test_triage_agx_firmware_probe import complete_run as firmware_run
from test_triage_agx_iouat_object_probe import event
from triage_agx_backend_identity_probe import META_VTABLE, REQUIRED, REVISION, SLOTS, triage
from triage_agx_firmware_probe import REVISION as FIRMWARE_REVISION


def complete_run():
    run = firmware_run(base_match=False)
    run[0]["detail"] = run[0]["detail"].replace(FIRMWARE_REVISION, REVISION)
    metaclass = 0xffffffe018700000
    details = {
        ("titan.backend-identity.metaclass", "PASS"): f"value=0x{metaclass:x} exact=0x8",
        ("titan.backend-identity.metaclass-repeat", "PASS"): f"value=0x{metaclass:x} exact=0x8",
        ("titan.backend-identity.metaclass-vtable-identity", "PASS"):
            f"object=0x{metaclass:x} unslid=0x{META_VTABLE:x} expected=0x{META_VTABLE:x}",
    }
    for index, (name, target) in enumerate(SLOTS.items()):
        prefix = f"titan.backend-identity.{name}"
        slot = 0xfffffff040000000 + index * 8
        raw = 0x1234000000000000 + index
        for suffix in ("-read", "-repeat"):
            details[(prefix + suffix, "PASS")] = (
                f"source=0x{slot:x} offset=0x0 size=0x8 value=0x{raw:x}")
        details[(prefix, "PASS")] = (
            f"slot=0x{slot:x} raw=0x{raw:x}/0x{raw:x} "
            f"unslid=0x{target:x} expected=0x{target:x}")
    backend = [event(stage, status, details.get((stage, status), ""))
               for stage, status in REQUIRED]
    anchor = next(index for index, item in enumerate(run) if
                  (item["stage"], item["status"]) == ("titan.own-queue", "PASS"))
    run[anchor:anchor] = backend
    return run


class BackendIdentityTriageTests(unittest.TestCase):
    def test_complete_bounded_run(self):
        report = triage(complete_run(), "run-a")
        self.assertEqual(report["verdict"], "agx_backend_identity_observed")
        self.assertTrue(report["backend_identity_ok"])
        self.assertIn("No backend method", report["limits"])

    def test_changed_or_missing_read_is_incomplete(self):
        for stage in ("titan.backend-identity.metaclass-repeat",
                      "titan.backend-identity.prepare-repeat"):
            with self.subTest(stage=stage):
                run = [item for item in complete_run() if item["stage"] != stage]
                self.assertEqual(triage(run, "run-a")["verdict"], "incomplete_or_blocked")

    def test_wrong_code_target_is_incomplete(self):
        run = complete_run()
        item = next(item for item in run if item["stage"] ==
                    "titan.backend-identity.factory" and item["status"] == "PASS")
        item["detail"] = item["detail"].replace("0xfffffff0087e4280", "0xfffffff0087e4284")
        self.assertEqual(triage(run, "run-a")["verdict"], "incomplete_or_blocked")

    def test_forbidden_packet_stage_is_rejected(self):
        run = complete_run() + [event("titan.command-buffers", "START")]
        self.assertEqual(triage(run, "run-a")["verdict"], "unexpected_active_stage")


if __name__ == "__main__":
    unittest.main()
