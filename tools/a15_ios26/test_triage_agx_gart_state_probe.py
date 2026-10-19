import unittest

from triage_agx_gart_state_probe import GART_VTABLE, REQUIRED, REVISION, triage


def event(stage, status, detail="", run_id="run-a"):
    return {"run_id": run_id, "stage": stage, "status": status, "detail": detail}


def complete_run():
    details = {
        ("probe.entry", "START"):
            f"target=iPhone14,2 build=23A355 revision={REVISION}",
        ("titan.agx-gart-state.identity", "PASS"):
            f"gart=0xffffffe012340000 vtable=0x{GART_VTABLE:x}/0x{GART_VTABLE:x} expected=0x{GART_VTABLE:x}",
        ("titan.agx-gart-state", "PASS"):
            "service=0xffffffe010000000 gart=0xffffffe012340000 "
            "state=0xffffffe015670000 state-vtable-unslid=0xfffffff007b10000; state type unconfirmed",
    }
    return [event(stage, status, details.get((stage, status), ""))
            for stage, status in REQUIRED]


class GartStateTriageTests(unittest.TestCase):
    def test_complete_read_only_chain(self):
        run = complete_run() + [event("titan.run", "FAIL", "bounded stop")]
        result = triage(run, "run-a")
        self.assertEqual(result["verdict"], "gart_state_pointer_chain_observed")
        self.assertEqual(result["observed_pointers"]["gart"], 0xffffffe012340000)
        self.assertIn("physical write", result["limits"])

    def test_wrong_build_or_revision(self):
        run = complete_run()
        run[0]["detail"] = run[0]["detail"].replace("23A355", "23A999")
        self.assertEqual(triage(run, "run-a")["verdict"], "wrong_target_or_revision")
        run[0]["detail"] = run[0]["detail"].replace("23A999", "23A355").replace(
            REVISION, "old-revision")
        self.assertEqual(triage(run, "run-a")["verdict"], "wrong_target_or_revision")

    def test_identity_mismatch_blocks_state_claim(self):
        run = complete_run()
        identity = next(item for item in run if item["stage"] ==
                        "titan.agx-gart-state.identity")
        identity["detail"] = identity["detail"].replace(
            f"vtable=0x{GART_VTABLE:x}", "vtable=0xfffffff007000000", 1)
        self.assertEqual(triage(run, "run-a")["verdict"], "incomplete_or_blocked")

    def test_first_blocker_retained(self):
        run = complete_run()
        index = next(i for i, item in enumerate(run) if item["stage"] ==
                     "titan.agx-gart-state.identity")
        run[index] = event("titan.agx-gart-state.identity", "BLOCKED", "wrong vtable")
        result = triage(run, "run-a")
        self.assertEqual(result["first_blocker"]["stage"],
                         "titan.agx-gart-state.identity")
        self.assertEqual(result["verdict"], "incomplete_or_blocked")

    def test_interrupted_chain_not_promoted(self):
        run = complete_run()[:10]
        self.assertEqual(triage(run, "run-a")["verdict"], "incomplete_or_blocked")
        self.assertTrue(triage(run, "run-a")["missing_or_out_of_order"])

    def test_order_and_forbidden_stage(self):
        run = complete_run()
        run[13], run[14] = run[14], run[13]
        self.assertEqual(triage(run, "run-a")["verdict"], "incomplete_or_blocked")
        run = complete_run() + [event("titan.iorvbar.resolve", "START")]
        self.assertEqual(triage(run, "run-a")["verdict"], "unexpected_active_stage")

    def test_other_run_cannot_complete_it(self):
        run = complete_run()[:9]
        run += [dict(item, run_id="run-b") for item in complete_run()[9:]]
        self.assertEqual(triage(run, "run-a")["verdict"], "incomplete_or_blocked")


if __name__ == "__main__":
    unittest.main()
