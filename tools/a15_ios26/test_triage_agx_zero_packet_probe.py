import unittest

from test_triage_agx_iouat_object_probe import event
from test_triage_agx_packet_route_identity_probe import complete_run as route_run
from triage_agx_owned_queue_probe import detail
from triage_agx_packet_route_identity_probe import REVISION as ROUTE_REVISION
from triage_agx_zero_packet_probe import REQUIRED, REVISION, triage


def complete_run():
    run = route_run()
    run[0]["detail"] = run[0]["detail"].replace(ROUTE_REVISION, REVISION)
    command = detail(run, "titan.packet-route-identity.command-buffer")
    firmware = detail(run, "titan.own-queue.firmware-object")
    buffer = detail(run, "titan.shared-alias.buffer")
    values = {
        "command-buffer": command,
        "firmware": firmware,
        "buffer": buffer,
        "identities": "command=0xffffffe018004000 firmware=same buffer=same",
        "buffer-preflight": "address=0x104000000 size=0x4000 all-zero=yes first-nonzero=0x0",
        "pool-before": "read=0 offset=0x0 digest=0x11223344 bytes=0x208",
        "queue-before": "backend=0x0 status=0x0 flags=0x0/0x0 count=0 dispatch=0 ready=1 precheck=0x0 state800=0x0 state802=0x0 command-index=0",
        "pool-before-repeat": "read=0 offset=0x0 digest=0x11223344 bytes=0x208",
        "preflight-stability": "pool=same backend=0x0",
        "call": "kr=0x0 output-count=1 output=0x0 attempt=1/1",
        "pool-after": "read=0 offset=0x0 digest=0x11223344 bytes=0x208",
        "queue-after": "backend=0x0 status=0x0 flags=0x0/0x0 count=0 dispatch=1 ready=1 precheck=0x0 state800=0x1 state802=0x0 command-index=1",
        "pool-after-repeat": "read=0 offset=0x0 digest=0x11223344 bytes=0x208",
        "queue-after-repeat": "backend=0x0 status=0x0 flags=0x0/0x0 count=0 dispatch=1 ready=1 precheck=0x0 state800=0x1 state802=0x0 command-index=1",
        "cleanup-state": "pool-post=stable pool-restored=yes queue-post=stable backend=0x0/0x0",
        "command-buffer-final": command,
        "firmware-final": firmware,
        "buffer-final": buffer,
        "postflight": "command=same firmware=same buffer=same all-zero=yes first-nonzero=0x0",
    }
    packet = []
    for stage, status in REQUIRED:
        name = stage.removeprefix("titan.zero-packet.")
        if stage == "titan.zero-packet.call" and status == "START":
            value = "selector=25 queue-id=1 buffer-id=1 scalars=4 structure=0x38 output=1 attempt=1/1"
        elif stage == "titan.zero-packet":
            value = "attempts=1; connection cleanup follows" if status == "STOP" else ""
        else:
            value = values.get(name, "")
        packet.append(event(stage, status, value))
    anchor = next(index for index, item in enumerate(run) if
                  (item["stage"], item["status"]) == ("titan.own-queue", "PASS"))
    run[anchor:anchor] = packet
    return run


class ZeroPacketTriageTests(unittest.TestCase):
    def test_complete_single_attempt(self):
        report = triage(complete_run(), "run-a")
        self.assertEqual(report["verdict"], "agx_zero_packet_cleanup_observed")
        self.assertTrue(report["zero_packet_observation_ok"])
        self.assertEqual(report["selector25_attempts"], 1)

    def test_missing_post_snapshot_is_incomplete(self):
        run = [item for item in complete_run() if item["stage"] !=
               "titan.zero-packet.pool-after-repeat"]
        self.assertEqual(triage(run, "run-a")["verdict"], "incomplete_or_blocked")

    def test_pool_digest_change_is_incomplete(self):
        run = complete_run()
        changed = next(item for item in run if item["stage"] ==
                       "titan.zero-packet.pool-after" and item["status"] == "PASS")
        changed["detail"] = changed["detail"].replace("0x11223344", "0x11223345")
        self.assertEqual(triage(run, "run-a")["verdict"], "incomplete_or_blocked")

    def test_live_backend_after_call_is_incomplete(self):
        run = complete_run()
        changed = next(item for item in run if item["stage"] ==
                       "titan.zero-packet.queue-after" and item["status"] == "PASS")
        changed["detail"] = changed["detail"].replace("backend=0x0", "backend=0x8")
        self.assertEqual(triage(run, "run-a")["verdict"], "incomplete_or_blocked")

    def test_second_call_is_incomplete(self):
        run = complete_run()
        call = next(item for item in run if item["stage"] ==
                    "titan.zero-packet.call" and item["status"] == "PASS")
        index = run.index(call)
        run[index:index] = [dict(call, status="START"), dict(call)]
        self.assertEqual(triage(run, "run-a")["verdict"], "incomplete_or_blocked")


if __name__ == "__main__":
    unittest.main()
