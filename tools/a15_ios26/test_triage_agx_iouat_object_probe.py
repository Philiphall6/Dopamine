import unittest

from triage_agx_iouat_object_probe import (
    FACTORY_VTABLE, GART_VTABLE, MUX_VTABLE, REQUIRED, REVISION, triage,
)


def event(stage, status, detail="", run_id="run-a"):
    return {"run_id": run_id, "stage": stage, "status": status, "detail": detail}


def complete_run():
    details = {
        ("probe.entry", "START"):
            f"target=iPhone14,2 build=23A355 revision={REVISION}",
        ("titan.agx-gart-state.identity", "PASS"):
            f"gart=0xffffffe012340000 vtable=0x{GART_VTABLE:x}/0x{GART_VTABLE:x} expected=0x{GART_VTABLE:x}",
        ("titan.agx-gart-state.gart", "PASS"):
            "value=0xffffffe012340000 exact=0x8",
        ("titan.agx-gart-state.gart-repeat", "PASS"):
            "value=0xffffffe012340000 exact=0x8",
        ("titan.agx-gart-state.state", "PASS"):
            "value=0xffffffe015670000 exact=0x8",
        ("titan.agx-gart-state.state-repeat", "PASS"):
            "value=0xffffffe015670000 exact=0x8",
        ("titan.agx-gart-state.mux-identity", "PASS"):
            f"state=0xffffffe015670000 vtable=0x{MUX_VTABLE:x}/0x{MUX_VTABLE:x} expected=0x{MUX_VTABLE:x}",
        ("titan.agx-gart-state", "PASS"):
            f"service=0xffffffe010000000 gart=0xffffffe012340000 state=0xffffffe015670000 state-vtable-unslid=0x{MUX_VTABLE:x}; AGXUATMux vtable validated",
        ("titan.agx-iouat-object.identity", "PASS"):
            f"object=0xffffffe018900000 vtable=0x{FACTORY_VTABLE:x}/0x{FACTORY_VTABLE:x} expected=0x{FACTORY_VTABLE:x}",
        ("titan.agx-iouat-object.mode", "PASS"):
            "source=0xfffffff00ab61150 offset=0x0 size=0x1 value=0x1",
        ("titan.agx-iouat-object.mode-repeat", "PASS"):
            "source=0xfffffff00ab61150 offset=0x0 size=0x1 value=0x1",
        ("titan.agx-iouat-object.initialized", "PASS"):
            "source=0xfffffff00ab61150 offset=0x10 size=0x1 value=0x1",
        ("titan.agx-iouat-object.initialized-repeat", "PASS"):
            "source=0xfffffff00ab61150 offset=0x10 size=0x1 value=0x1",
        ("titan.agx-iouat-object.mode-gate", "PASS"):
            "mode=1/1 initialized=1/1 expected=1/1",
        ("titan.agx-iouat-object.pointer", "PASS"):
            "value=0xffffffe018900000 exact=0x8",
        ("titan.agx-iouat-object.pointer-repeat", "PASS"):
            "value=0xffffffe018900000 exact=0x8",
        ("titan.agx-iouat-object", "PASS"):
            f"mux=0xffffffe015670000 object=0xffffffe018900000 factory-vtable-unslid=0x{FACTORY_VTABLE:x}",
    }
    return [event(stage, status, details.get((stage, status), ""))
            for stage, status in REQUIRED]


class IOUATObjectTriageTests(unittest.TestCase):
    def test_complete_bounded_chain(self):
        run = complete_run() + [event("titan.run", "FAIL", "bounded stop")]
        result = triage(run, "run-a")
        self.assertEqual(result["verdict"], "iouat_factory_object_observed")
        self.assertEqual(result["observed_pointers"]["factory_object"],
                         0xffffffe018900000)
        self.assertIn("protected-memory change", result["limits"])

    def test_wrong_target_or_revision(self):
        run = complete_run()
        run[0]["detail"] = run[0]["detail"].replace("23A355", "23A999")
        self.assertEqual(triage(run, "run-a")["verdict"],
                         "wrong_target_or_revision")

    def test_mismatched_factory_vtable(self):
        run = complete_run()
        identity = next(item for item in run if item["stage"] ==
                        "titan.agx-iouat-object.identity")
        identity["detail"] = identity["detail"].replace(
            f"vtable=0x{FACTORY_VTABLE:x}", "vtable=0xfffffff007000000", 1)
        self.assertEqual(triage(run, "run-a")["verdict"],
                         "incomplete_or_blocked")

    def test_null_field_stops_before_vtable(self):
        run = complete_run()
        index = next(i for i, item in enumerate(run) if item["stage"] ==
                     "titan.agx-iouat-object.pointer")
        run = run[:index] + [event("titan.agx-iouat-object.pointer", "FAIL",
                                   "value=0x0")]
        result = triage(run, "run-a")
        self.assertEqual(result["verdict"], "incomplete_or_blocked")
        self.assertEqual(result["first_blocker"]["stage"],
                         "titan.agx-iouat-object.pointer")

    def test_inactive_mode_stops_before_field(self):
        run = complete_run()
        index = next(i for i, item in enumerate(run) if item["stage"] ==
                     "titan.agx-iouat-object.mode-gate")
        run = run[:index] + [event("titan.agx-iouat-object.mode-gate", "BLOCKED",
                                   "mode=0/0 initialized=1/1 expected=1/1")]
        result = triage(run, "run-a")
        self.assertEqual(result["verdict"], "incomplete_or_blocked")
        self.assertEqual(result["first_blocker"]["stage"],
                         "titan.agx-iouat-object.mode-gate")

    def test_missing_cleanup_is_incomplete(self):
        self.assertEqual(triage(complete_run()[:-1], "run-a")["verdict"],
                         "incomplete_or_blocked")

    def test_forbidden_active_stage(self):
        run = complete_run() + [event("titan.iorvbar.resolve", "START")]
        self.assertEqual(triage(run, "run-a")["verdict"],
                         "unexpected_active_stage")

    def test_repeated_pointer_mismatch(self):
        run = complete_run()
        repeated = next(item for item in run if item["stage"] ==
                        "titan.agx-iouat-object.pointer-repeat")
        repeated["detail"] = "value=0xffffffe018901000 exact=0x8"
        self.assertEqual(triage(run, "run-a")["verdict"],
                         "incomplete_or_blocked")

    def test_summary_pointer_mismatch(self):
        run = complete_run()
        summary = next(item for item in run if (item["stage"], item["status"]) ==
                       ("titan.agx-iouat-object", "PASS"))
        summary["detail"] = summary["detail"].replace(
            "mux=0xffffffe015670000", "mux=0xffffffe015671000")
        self.assertEqual(triage(run, "run-a")["verdict"],
                         "incomplete_or_blocked")

    def test_order_and_run_separation(self):
        run = complete_run()
        run[14], run[15] = run[15], run[14]
        self.assertEqual(triage(run, "run-a")["verdict"],
                         "incomplete_or_blocked")
        run = complete_run()[:15]
        run += [dict(item, run_id="run-b") for item in complete_run()[15:]]
        self.assertEqual(triage(run, "run-a")["verdict"],
                         "incomplete_or_blocked")


if __name__ == "__main__":
    unittest.main()
