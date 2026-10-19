import unittest

from test_triage_agx_iouat_object_probe import event
from test_triage_agx_owned_queue_probe import complete_run as queue_run
from triage_agx_firmware_probe import FIRMWARE_REQUIRED, REVISION, triage
from triage_agx_owned_queue_probe import REVISION as QUEUE_REVISION


def complete_run(*, base_match=True):
    run = queue_run()
    run[0]["detail"] = run[0]["detail"].replace(QUEUE_REVISION, REVISION)
    unslid = 0xfffffff007b18e58 if base_match else 0xfffffff007b18f00
    details = {
        ("titan.own-queue.firmware-object", "PASS"):
            "value=0xffffffe018000000 exact=0x8",
        ("titan.own-queue.firmware-object-repeat", "PASS"):
            "value=0xffffffe018000000 exact=0x8",
        ("titan.own-queue.firmware-vtable-read", "PASS"):
            "source=0xffffffe018000000 offset=0x0 size=0x8 value=0xaabbccdd",
        ("titan.own-queue.firmware-vtable-repeat", "PASS"):
            "source=0xffffffe018000000 offset=0x0 size=0x8 value=0xaabbccdd",
        ("titan.own-queue.firmware-vtable", "INFO"):
            f"object=0xffffffe018000000 unslid=0x{unslid:x} "
            f"static-ASC-base-match={'yes' if base_match else 'no'}",
    }
    firmware = [event(stage, status, details.get((stage, status), ""))
                for stage, status in FIRMWARE_REQUIRED]
    position = next(index for index, item in enumerate(run) if
                    (item["stage"], item["status"]) == ("titan.own-queue", "PASS"))
    run[position:position] = firmware
    return run


class FirmwareIdentityTriageTests(unittest.TestCase):
    def test_static_base_identity_is_observation_only(self):
        result = triage(complete_run(), "run-a")
        self.assertEqual(result["verdict"], "firmware_identity_observed")
        self.assertTrue(result["static_asc_base_match"])
        self.assertIn("No packet submission", result["limits"])

    def test_different_stable_identity_is_still_observed(self):
        result = triage(complete_run(base_match=False), "run-a")
        self.assertEqual(result["verdict"], "firmware_identity_observed")
        self.assertFalse(result["static_asc_base_match"])

    def test_changed_pointer_or_vtable_is_incomplete(self):
        for stage, replacement in (
            ("titan.own-queue.firmware-object-repeat", "value=0xffffffe018001000 exact=0x8"),
            ("titan.own-queue.firmware-vtable-repeat", "value=0xaabbccde"),
        ):
            with self.subTest(stage=stage):
                run = complete_run()
                next(item for item in run if item["stage"] == stage)["detail"] = replacement
                self.assertEqual(triage(run, "run-a")["verdict"], "incomplete_or_blocked")

    def test_missing_or_early_checkpoint_is_incomplete(self):
        run = [item for item in complete_run() if item["stage"] !=
               "titan.own-queue.firmware-vtable-repeat"]
        self.assertEqual(triage(run, "run-a")["verdict"], "incomplete_or_blocked")
        run = complete_run()
        firmware = next(item for item in run if item["stage"] ==
                        "titan.own-queue.firmware-vtable")
        run.remove(firmware)
        run.insert(0, firmware)
        self.assertEqual(triage(run, "run-a")["verdict"], "incomplete_or_blocked")

    def test_forbidden_submission_stage_is_rejected(self):
        run = complete_run() + [event("titan.command-buffers", "START")]
        self.assertEqual(triage(run, "run-a")["verdict"], "unexpected_active_stage")


if __name__ == "__main__":
    unittest.main()
