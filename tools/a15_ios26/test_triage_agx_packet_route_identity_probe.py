import unittest

from test_triage_agx_backend_identity_probe import complete_run as backend_run
from test_triage_agx_iouat_object_probe import event
from triage_agx_backend_identity_probe import REVISION as BACKEND_REVISION
from triage_agx_packet_route_identity_probe import (
    COMMAND_CALLBACK, COMMAND_VTABLE, FIRMWARE_CALLBACK, FIRMWARE_VTABLE,
    REQUIRED, REVISION, triage,
)


def complete_run():
    run = backend_run()
    run[0]["detail"] = run[0]["detail"].replace(BACKEND_REVISION, REVISION)
    firmware_info = next(item for item in run if item["stage"] ==
                         "titan.own-queue.firmware-vtable")
    firmware_info["detail"] = firmware_info["detail"].replace(
        "0xfffffff007b18f00", f"0x{FIRMWARE_VTABLE:x}")
    slide = 0x3ab78000
    command = 0xffffffe018004000
    device = 0xffffffe010000000
    firmware = 0xffffffe018000000
    command_raw = 0xbbeeff01
    firmware_raw = 0xaabbccdd
    details = {
        "command-buffer": f"value=0x{command:x} exact=0x8",
        "command-buffer-repeat": f"value=0x{command:x} exact=0x8",
        "command-vtable": f"source=0x{command:x} offset=0x0 size=0x8 value=0x{command_raw:x}",
        "command-vtable-repeat": f"source=0x{command:x} offset=0x0 size=0x8 value=0x{command_raw:x}",
        "command-type": f"object=0x{command:x} unslid=0x{COMMAND_VTABLE:x} expected=0x{COMMAND_VTABLE:x}",
        "command-device": f"value=0x{device:x} exact=0x8",
        "command-device-repeat": f"value=0x{device:x} exact=0x8",
        "device-link": f"command-device=0x{device:x} expected=0x{device:x}",
        "firmware-type": f"object=0x{firmware:x} unslid=0x{FIRMWARE_VTABLE:x} expected=0x{FIRMWARE_VTABLE:x}",
        "firmware-vtable-repeat": f"source=0x{firmware:x} offset=0x0 size=0x8 value=0x{firmware_raw:x}",
        "command-buffer-final": f"value=0x{command:x} exact=0x8",
        "firmware-final": f"value=0x{firmware:x} exact=0x8",
        "stability": "command=same firmware=same",
    }
    for name, vtable, target in (
        ("command-callback", COMMAND_VTABLE, COMMAND_CALLBACK),
        ("firmware-callback", FIRMWARE_VTABLE, FIRMWARE_CALLBACK),
    ):
        slot = vtable + slide + (0x98 if name == "command-callback" else 0x210)
        raw = 0x1234567800000000 + slot % 0x1000
        for suffix in ("-read", "-repeat"):
            details[name + suffix] = (
                f"source=0x{slot:x} offset=0x0 size=0x8 value=0x{raw:x}")
        details[name] = (
            f"slot=0x{slot:x} raw=0x{raw:x}/0x{raw:x} "
            f"unslid=0x{target:x} expected=0x{target:x}")
    packet = [event(stage, status, details.get(stage.removeprefix(
        "titan.packet-route-identity."), "")) for stage, status in REQUIRED]
    anchor = next(index for index, item in enumerate(run) if
                  (item["stage"], item["status"]) == ("titan.own-queue", "PASS"))
    run[anchor:anchor] = packet
    return run


class PacketRouteIdentityTriageTests(unittest.TestCase):
    def test_complete_read_only_run(self):
        report = triage(complete_run(), "run-a")
        self.assertEqual(report["verdict"], "agx_packet_route_identity_observed")
        self.assertTrue(report["packet_route_identity_ok"])
        self.assertIn("No method call", report["limits"])

    def test_mismatched_or_missing_identity_is_incomplete(self):
        for stage in ("titan.packet-route-identity.command-buffer-repeat",
                      "titan.packet-route-identity.command-device-repeat",
                      "titan.packet-route-identity.firmware-vtable-repeat"):
            with self.subTest(stage=stage):
                run = [item for item in complete_run() if item["stage"] != stage]
                self.assertEqual(triage(run, "run-a")["verdict"], "incomplete_or_blocked")

    def test_wrong_callback_target_is_incomplete(self):
        run = complete_run()
        slot = next(item for item in run if item["stage"] ==
                    "titan.packet-route-identity.command-callback" and item["status"] == "PASS")
        slot["detail"] = slot["detail"].replace(
            f"unslid=0x{COMMAND_CALLBACK:x}", f"unslid=0x{COMMAND_CALLBACK + 4:x}")
        self.assertEqual(triage(run, "run-a")["verdict"], "incomplete_or_blocked")

    def test_wrong_prior_firmware_type_is_incomplete(self):
        run = complete_run()
        prior = next(item for item in run if item["stage"] == "titan.own-queue.firmware-vtable")
        prior["detail"] = prior["detail"].replace(
            f"unslid=0x{FIRMWARE_VTABLE:x}", "unslid=0xfffffff007b18e58")
        self.assertEqual(triage(run, "run-a")["verdict"], "incomplete_or_blocked")

    def test_forbidden_submission_stage_is_rejected(self):
        run = complete_run() + [event("titan.command-buffers", "START")]
        self.assertEqual(triage(run, "run-a")["verdict"], "unexpected_active_stage")


if __name__ == "__main__":
    unittest.main()
