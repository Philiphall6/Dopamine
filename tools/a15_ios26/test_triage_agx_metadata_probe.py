import json
import unittest

from triage_agx_metadata_probe import FIELD_STAGES, MODE_REVISION, REVISION, SCHEMA, load_events, triage


def event(stage, status, detail="", run_id="run-a"):
    return {
        "schema": SCHEMA,
        "run_id": run_id,
        "timestamp": 1.0,
        "stage": stage,
        "status": status,
        "detail": detail,
    }


def complete_run(gpu_map="0xffffffe000001000", provider="sgx"):
    items = [event("probe.entry", "START",
                   f"target=iPhone14,2 build=23A355 mode=active-titan-bounded revision={REVISION}"),
             event("agx.registry-match", "INFO",
                   f"id=0x45 name=sgx class=AGXAcceleratorG14P parent-name={provider}"),
             event("agx.registry", "SUMMARY",
                   "scanned=1700 matches=1 base=1 class-failures=0 complete=yes iterator-valid=yes"),
             event("agx.registry", "STOP"),
             event("xpf.gather", "PASS"),
             event("kernel.primitive", "PASS"),
             event("titan.target-gate", "PASS"),
             event("titan.kernel-patchfinder", "PASS"),
             event("titan.agx-map-metadata", "START"),
             event("titan.agx-map-metadata.identity", "PASS"),
             event("titan.agx-map-metadata.wrapper-vtable", "PASS",
                   "unslid=0xfffffff007abcb18 expected=0xfffffff007abcb18"),
             event("titan.agx-map-metadata.instance-vtable", "PASS",
                   "unslid=0xfffffff007b1e0d0 expected=0xfffffff007b1e0d0")]
    items += [event(f"titan.agx-map-metadata.{suffix}", "PASS") for suffix in FIELD_STAGES]
    items += [event(f"titan.agx-map-metadata.{suffix}-repeat", "PASS") for suffix in FIELD_STAGES]
    items += [event("titan.agx-map-metadata.stability", "PASS"),
              event("titan.agx-map-metadata", "PASS",
                    "registry-id=0x45 service+0x310=0xffffffe000002000 "
                    "mode=2 gpu-index=0 fender-index=1 flags=0x1 "
                    "gpu-physical=0x204000000 fender-physical=0x204d00000 "
                    f"gpu-map={gpu_map} fender-map=0x0"),
              event("titan.agx-map-metadata", "STOP"),
              event("titan.run", "FAIL", "return=-1; intentionally stopped")]
    return items


def mode_run(mode=1, source=None, initialized=1):
    source = mode if source is None else source
    items = complete_run()
    items[0]["detail"] = items[0]["detail"].replace(REVISION, MODE_REVISION)
    items.insert(6, event("kernel-write.self-page", "PASS", "app-owned page only"))
    mode_events = [event("titan.agx-uat-mode", "START"),
                   event("titan.agx-uat-mode.source", "PASS", f"value={source:#x}"),
                   event("titan.agx-uat-mode.global", "PASS", f"value={mode:#x}"),
                   event("titan.agx-uat-mode.initialized", "PASS", f"value={initialized:#x}"),
                   event("titan.agx-uat-mode.source-repeat", "PASS", f"value={source:#x}"),
                   event("titan.agx-uat-mode.global-repeat", "PASS", f"value={mode:#x}"),
                   event("titan.agx-uat-mode.initialized-repeat", "PASS", f"value={initialized:#x}"),
                   event("titan.agx-uat-mode.stability", "PASS"),
                   event("titan.agx-uat-mode", "PASS",
                         f"route={'IOUAT' if mode else 'AGXUAT'} global={mode} "
                         f"initialized={initialized} source-bit={source & 1}"),
                   event("titan.agx-uat-mode", "STOP")]
    items[-2:-2] = mode_events
    return items


class AGXMetadataTriageTests(unittest.TestCase):
    def test_complete_candidate_ignores_expected_titan_fail(self):
        result = triage(complete_run(), "run-a")
        self.assertEqual(result["verdict"], "metadata_matches_static_candidate")
        self.assertIsNone(result["first_blocker"])
        self.assertTrue(result["provider_confirmed"])
        self.assertIn("cannot prove MMIO access", result["limits"])

    def test_combined_self_page_revision_accepts_metadata_without_inferred_iouat(self):
        items = complete_run()
        items[0]["detail"] = items[0]["detail"].replace(
            REVISION, "self-page-write-v1+agx-map-metadata-v1+rtkit-mmio-disabled-v1")
        items.insert(6, event("kernel-write.self-page", "PASS", "app-owned page only"))
        result = triage(items, "run-a")
        self.assertEqual(result["verdict"], "metadata_matches_static_candidate")
        self.assertIn("ProbeConfig mode is not the AGX dispatch bit", result["limits"])

    def test_iouat_mode_requires_source_and_global_agreement(self):
        result = triage(mode_run(mode=1, source=3), "run-a")
        self.assertEqual(result["verdict"], "iouat_dispatch_bit_selected")
        self.assertEqual(result["uat_dispatch"], {"route": "IOUAT", "global": 1,
                                                  "source_byte": 3})
        self.assertIn("not proof of an IOUAT request", result["limits"])

    def test_agxuat_mode_is_distinct_from_probeconfig_mode(self):
        result = triage(mode_run(mode=0, source=2), "run-a")
        self.assertEqual(result["verdict"], "agxuat_dispatch_bit_selected")
        self.assertEqual(result["map_metadata"]["mode"], 2)

    def test_mode_source_mismatch_blocks_route_claim(self):
        result = triage(mode_run(mode=1, source=0), "run-a")
        self.assertEqual(result["verdict"], "incomplete_or_blocked")
        self.assertFalse(result["mode_link_ok"])
        self.assertIsNone(result["uat_dispatch"])
        self.assertEqual(result["observed_dispatch_bit"], {
            "global": 1, "conditional_route": "IOUAT", "initialized": 1,
            "source_byte": 0, "instance_link_proven": False,
        })

    def test_default_zero_without_initializer_blocks_route_claim(self):
        result = triage(mode_run(mode=0, source=0, initialized=0), "run-a")
        self.assertEqual(result["verdict"], "incomplete_or_blocked")
        self.assertFalse(result["mode_link_ok"])
        self.assertIsNone(result["observed_dispatch_bit"])

    def test_missing_mode_repeat_blocks_route_claim(self):
        items = [item for item in mode_run() if item["stage"] != "titan.agx-uat-mode.global-repeat"]
        result = triage(items, "run-a")
        self.assertEqual(result["verdict"], "incomplete_or_blocked")
        self.assertIn("titan.agx-uat-mode.global-repeat:PASS", result["missing_or_out_of_order"])

    def test_falsified_mode_summary_blocks_route_claim(self):
        items = mode_run(mode=1)
        summary = next(item for item in items if item["stage"] == "titan.agx-uat-mode" and
                       item["status"] == "PASS")
        summary["detail"] = summary["detail"].replace("route=IOUAT", "route=AGXUAT")
        self.assertEqual(triage(items, "run-a")["verdict"], "incomplete_or_blocked")

    def test_null_map_is_not_a_candidate(self):
        result = triage(complete_run(gpu_map="0x0"), "run-a")
        self.assertEqual(result["verdict"], "metadata_complete_unconfirmed_map_or_provider")

    def test_provider_mismatch_is_not_confirmed(self):
        result = triage(complete_run(provider="other"), "run-a")
        self.assertFalse(result["provider_confirmed"])
        self.assertEqual(result["verdict"], "metadata_complete_unconfirmed_map_or_provider")

    def test_missing_stability_is_incomplete(self):
        items = [item for item in complete_run() if item["stage"] != "titan.agx-map-metadata.stability"]
        result = triage(items, "run-a")
        self.assertEqual(result["verdict"], "incomplete_or_blocked")
        self.assertIn("titan.agx-map-metadata.stability:PASS", result["missing_or_out_of_order"])

    def test_specific_failure_precedes_generic_titan_failure(self):
        items = complete_run()
        items.insert(-3, event("titan.agx-map-metadata.config-gpu-map", "FAIL", "exact-kreadbuf=14"))
        result = triage(items, "run-a")
        self.assertEqual(result["first_blocker"]["stage"], "titan.agx-map-metadata.config-gpu-map")

    def test_legacy_gpu_selector_is_forbidden(self):
        items = complete_run()
        items.insert(-1, event("titan.self-gpu.queue-selector", "START"))
        result = triage(items, "run-a")
        self.assertEqual(result["verdict"], "unexpected_active_stage")

    def test_old_revision_does_not_relabel_its_stages(self):
        items = complete_run()
        items[0]["detail"] = items[0]["detail"].replace(REVISION, "old-revision")
        items.insert(-1, event("titan.command-buffers", "FAIL"))
        result = triage(items, "run-a")
        self.assertEqual(result["verdict"], "wrong_target_or_revision")
        self.assertEqual(result["forbidden_stages"], [])

    def test_generic_titan_failure_used_only_without_stop(self):
        items = complete_run()
        items = [item for item in items if not (item["stage"] == "titan.agx-map-metadata" and
                                                  item["status"] == "STOP")]
        result = triage(items, "run-a")
        self.assertEqual(result["first_blocker"]["stage"], "titan.run")

    def test_stop_before_pass_is_out_of_order(self):
        items = complete_run()
        stop = items.pop(-2)
        items.insert(-2, stop)
        result = triage(items, "run-a")
        self.assertIn("checkpoint order invalid", result["missing_or_out_of_order"])

    def test_other_run_cannot_satisfy_missing_checkpoints(self):
        items = complete_run()[:-4]
        items += [dict(item, run_id="run-b") for item in complete_run()]
        result = triage(items, "run-a")
        self.assertEqual(result["verdict"], "incomplete_or_blocked")

    def test_revision_mismatch_rejected(self):
        items = complete_run()
        items[0]["detail"] = items[0]["detail"].replace(REVISION, "old-revision")
        self.assertEqual(triage(items, "run-a")["verdict"], "wrong_target_or_revision")

    def test_jsonl_schema_and_truncation_rejected(self):
        raw = json.dumps(event("probe.entry", "START")).encode() + b"\n{"
        with self.assertRaisesRegex(ValueError, "line 2"):
            load_events(raw)


if __name__ == "__main__":
    unittest.main()
