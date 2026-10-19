import hashlib
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from audit_agx_submit_boundary import (
    BACKEND_COMMON_RELEASE,
    BACKEND_FAILURE_RELEASE,
    BACKEND_OBJECT_READY,
    BASE_HELPER_END,
    BASE_HELPER_GOT,
    BASE_HELPER_GOT_ENCODING,
    BASE_HELPER_KERNEL_TARGET,
    BASE_HELPER_RETURN,
    BASE_HELPER_SLOT,
    BASE_HELPER_SLOT_ENCODING,
    BASE_HELPER_START,
    BASE_HELPER_VIRTUAL_CALL,
    BASE_INIT_END,
    BASE_INIT_HELPER_CALL,
    BASE_INIT_RETURN,
    COMMAND_BUFFER_CALLBACK,
    COMMAND_BUFFER_CALLBACK_ENCODING,
    COMMAND_BUFFER_CALLBACK_SLOT,
    COMMAND_BUFFER_INIT_ENCODING,
    COMMAND_BUFFER_INIT_SLOT,
    BLOCK_FENCE_FIRST_CLEAR,
    BLOCK_FENCE_FIRST_RELEASE_PATH,
    BLOCK_FENCE_FREE,
    BLOCK_FENCE_FREE_ENCODING,
    BLOCK_FENCE_FREE_GRAPH_END,
    BLOCK_FENCE_FREE_SLOT,
    BLOCK_FENCE_FINAL_STAGE,
    BLOCK_FENCE_RELEASE_CORE_ENCODING,
    BLOCK_FENCE_RELEASE_CORE_SLOT,
    BLOCK_FENCE_RELEASE_ENCODING,
    BLOCK_FENCE_RELEASE_SLOT,
    BLOCK_FENCE_SECOND_CLEAR,
    BLOCK_FENCE_SECOND_RELEASE_PATH,
    BLOCK_FENCE_SECOND_STAGE,
    BLOCK_FENCE_TAGGED_RELEASE_ENCODING,
    BLOCK_FENCE_TAGGED_RELEASE_SLOT,
    EXPECTED_BASE_INIT,
    EXPECTED_BASE_HELPER,
    EXPECTED_COMMAND_BUFFER,
    EXPECTED_BLOCK_FENCE_FREE,
    EXPECTED_FIRMWARE_FACTORY,
    EXPECTED_KERNEL_TARGET,
    EXPECTED_METACLASS_CHAIN,
    EXPECTED_EMPTY_PACKET_PATH,
    EXPECTED_SUBMIT_RECORD_CONTRACT,
    EXPECTED_OLD_SELECTOR_0,
    EXPECTED_PACKET_OVERRIDE,
    EXPECTED_PURE_VIRTUAL,
    EXPECTED_RELEASE_CHAIN,
    FIRMWARE_ALLOC_ENCODING,
    FIRMWARE_ALLOC_SLOT,
    FIRMWARE_BASE_CALLBACK_ENCODING,
    FIRMWARE_BASE_CALLBACK_SLOT,
    FIRMWARE_FACTORY_ENCODING,
    FIRMWARE_FACTORY_SLOT,
    FIRMWARE_CLASS_NAME,
    FIRMWARE_PARENT_ALLOC_ENCODING,
    FIRMWARE_PARENT_ALLOC_SLOT,
    FIRMWARE_PARENT_CLASS_NAME,
    FIRMWARE_POST_STORE_DEVICE_ENCODING,
    FIRMWARE_POST_STORE_DEVICE_SLOT,
    JOURNAL_RUN_ID,
    LIVE_DEVICE_VTABLE,
    LIVE_QUEUE_VTABLE,
    PROCESS_RETURN,
    QUEUE_PACKET_BASE,
    QUEUE_PACKET_BASE_ENCODING,
    QUEUE_PACKET_BASE_GOT,
    QUEUE_PACKET_BASE_GOT_ENCODING,
    QUEUE_PACKET_BASE_SLOT,
    QUEUE_PACKET_ENCODING,
    QUEUE_PACKET_SLOT,
    QUEUE_EMPTY_FINALIZER,
    QUEUE_EMPTY_FINALIZER_ENCODING,
    QUEUE_EMPTY_FINALIZER_SLOT,
    QUEUE_PRECHECK_ENCODING,
    QUEUE_PRECHECK_SLOT,
    EXPECTED_AGX,
    PREPARE_BASE_GOT,
    PREPARE_BASE_GOT_ENCODING,
    PREPARE_BASE_INITIALIZER,
    PREPARE_BASE_SLOT,
    PREPARE_BASE_SLOT_ENCODING,
    PREPARE_INDIRECT_CALL,
    PREPARE_POOL_WRITES,
    PREPARE_RETENTION_PATH,
    PREPARE_ROLLBACK_WRITES,
    branch_target,
    build_graph,
    dominates,
    path_through,
    reachable,
    reachable_avoiding,
    verify_prepare_base_slot,
    verify_instructions,
    verify_base_init_helper,
    verify_block_fence_metaclass,
    verify_block_fence_cleanup,
    verify_command_buffer_callback,
    verify_firmware_callback_candidate,
    verify_live_queue_link,
    verify_queue_packet_route,
)
from audit_agx_uat_dispatch import IOGPU_SELECTOR_0_ENTRIES


def instruction(address, mnemonic, operands=""):
    return SimpleNamespace(address=address, mnemonic=mnemonic, op_str=operands)


class SubmitBoundaryTests(unittest.TestCase):
    def test_required_call_dominates_parser(self):
        graph = build_graph([
            instruction(0, "cbz", "w0, #0x10"),
            instruction(4, "blraa", "x8, x17"),
            instruction(8, "tbz", "w0, #0, #0x10"),
            instruction(12, "blraa", "x9, x17"),
            instruction(16, "ret"),
        ])
        self.assertTrue(dominates(graph, 0, 4, 12))
        self.assertTrue(dominates(graph, 0, 8, 12))
        self.assertNotIn(12, reachable(graph, 16))

    def test_bypass_invalidates_dominance(self):
        graph = build_graph([
            instruction(0, "cbz", "w0, #0x8"),
            instruction(4, "blraa", "x8, x17"),
            instruction(8, "blraa", "x9, x17"),
            instruction(12, "ret"),
        ])
        self.assertFalse(dominates(graph, 0, 4, 8))

    def test_path_through_required_site_avoids_rollback(self):
        graph = {0: (4, 8), 4: (12,), 8: (12,), 12: ()}
        self.assertEqual(path_through(graph, 0, 12, (4,), (8,)), [0, 4, 12])
        self.assertIsNone(path_through(graph, 0, 12, (8,), (8,)))

    def test_reachable_avoiding_multiple_release_sites(self):
        graph = {0: (4, 8), 4: (12,), 8: (16,), 12: (20,), 16: (20,), 20: ()}
        self.assertNotIn(20, reachable_avoiding(graph, 0, {12, 16}))
        self.assertIn(20, reachable_avoiding(graph, 0, {12}))

    def test_retention_and_rollback_sites_are_distinct(self):
        self.assertFalse(set(PREPARE_RETENTION_PATH) & set(PREPARE_ROLLBACK_WRITES))

    def test_computed_branch_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "computed branch"):
            build_graph([instruction(0, "braa", "x8, x17")])

    def test_undecoded_instruction_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported instruction"):
            build_graph([instruction(0, ".byte", "0x00")])

    def test_malformed_target_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unresolved branch target"):
            branch_target("w0, x1")

    def test_candidate_backend_contract_has_distinct_writes(self):
        self.assertEqual(len(PREPARE_POOL_WRITES), 4)
        self.assertEqual(len(set(PREPARE_POOL_WRITES)), 4)
        self.assertEqual(EXPECTED_AGX[PREPARE_INDIRECT_CALL], ("blraa", "x8, x17"))

    def test_instruction_mutation_is_rejected(self):
        expected = {4: ("blraa", "x8, x17")}
        image = SimpleNamespace(instruction_at=lambda _: instruction(4, "b", "#0x8"))
        with self.assertRaisesRegex(ValueError, "instruction mismatch"):
            verify_instructions(image, expected)

    def test_prepare_base_slot_resolves_exact_image_target(self):
        agx = SimpleNamespace(read_u64=lambda address: PREPARE_BASE_GOT_ENCODING
                              if address == PREPARE_BASE_GOT else None)
        iogpu = SimpleNamespace(
            read_u64=lambda address: PREPARE_BASE_SLOT_ENCODING
            if address == PREPARE_BASE_SLOT else None,
            mapped_bytes=lambda _address, size: bytes(size),
            instruction_at=lambda address: instruction(address, *EXPECTED_BASE_INIT[address]),
        )
        graph = {
            PREPARE_BASE_INITIALIZER: (BASE_INIT_HELPER_CALL,),
            BASE_INIT_HELPER_CALL: (BASE_INIT_RETURN,),
            BASE_INIT_RETURN: (),
        }
        with patch("audit_agx_submit_boundary.function_graph", return_value=graph) as mocked:
            result = verify_prepare_base_slot(agx, iogpu)
        mocked.assert_called_once_with(iogpu, PREPARE_BASE_INITIALIZER, BASE_INIT_END)
        self.assertEqual(result["static_target"], f"{PREPARE_BASE_INITIALIZER:#x}")
        self.assertTrue(result["helper_call_dominates_return"])

    def test_prepare_base_slot_mutation_is_rejected(self):
        agx = SimpleNamespace(read_u64=lambda _address: PREPARE_BASE_GOT_ENCODING ^ 1)
        iogpu = SimpleNamespace(read_u64=lambda _address: PREPARE_BASE_SLOT_ENCODING)
        with self.assertRaisesRegex(ValueError, "pointer chain changed"):
            verify_prepare_base_slot(agx, iogpu)

    def test_prepare_base_target_mutation_is_rejected(self):
        agx = SimpleNamespace(read_u64=lambda _address: PREPARE_BASE_GOT_ENCODING)
        iogpu = SimpleNamespace(read_u64=lambda _address: PREPARE_BASE_SLOT_ENCODING ^ 1)
        with self.assertRaisesRegex(ValueError, "pointer chain changed"):
            verify_prepare_base_slot(agx, iogpu)

    def test_base_helper_resolves_kernel_return_one(self):
        iogpu = SimpleNamespace(
            read_u64=lambda address: BASE_HELPER_GOT_ENCODING
            if address == BASE_HELPER_GOT else None,
            instruction_at=lambda address: instruction(address, *EXPECTED_BASE_HELPER[address]),
        )
        kernel = SimpleNamespace(
            read_u64=lambda address: BASE_HELPER_SLOT_ENCODING
            if address == BASE_HELPER_SLOT else None,
            mapped_bytes=lambda _address, size: bytes(size),
            instruction_at=lambda address: instruction(address, *EXPECTED_KERNEL_TARGET[address]),
        )
        graph = {
            BASE_HELPER_START: (BASE_HELPER_VIRTUAL_CALL,),
            BASE_HELPER_VIRTUAL_CALL: (BASE_HELPER_RETURN,),
            BASE_HELPER_RETURN: (),
        }
        with patch("audit_agx_submit_boundary.function_graph", return_value=graph):
            result = verify_base_init_helper(iogpu, kernel)
        self.assertEqual(result["static_kernel_target"], f"{BASE_HELPER_KERNEL_TARGET:#x}")
        self.assertTrue(result["kernel_target_returns_one"])

    def test_base_helper_slot_mutation_is_rejected(self):
        iogpu = SimpleNamespace(read_u64=lambda _address: BASE_HELPER_GOT_ENCODING)
        kernel = SimpleNamespace(read_u64=lambda _address: BASE_HELPER_SLOT_ENCODING ^ 1)
        with self.assertRaisesRegex(ValueError, "pointer chain changed"):
            verify_base_init_helper(iogpu, kernel)

    def test_observed_queue_override_reaches_base_packet_method(self):
        agx_slots = {
            QUEUE_PACKET_SLOT: QUEUE_PACKET_ENCODING,
            QUEUE_PRECHECK_SLOT: QUEUE_PRECHECK_ENCODING,
            QUEUE_EMPTY_FINALIZER_SLOT: QUEUE_EMPTY_FINALIZER_ENCODING,
            QUEUE_PACKET_BASE_GOT: QUEUE_PACKET_BASE_GOT_ENCODING,
        }
        iogpu_slots = {QUEUE_PACKET_BASE_SLOT: QUEUE_PACKET_BASE_ENCODING}
        iogpu_slots.update({address: encoding for _, address, encoding, _
                            in IOGPU_SELECTOR_0_ENTRIES})
        agx = SimpleNamespace(
            read_u64=agx_slots.get,
            instruction_at=lambda address: instruction(address, *EXPECTED_PACKET_OVERRIDE[address]),
        )
        iogpu = SimpleNamespace(
            read_u64=iogpu_slots.get,
            instruction_at=lambda address: instruction(
                address, *(EXPECTED_EMPTY_PACKET_PATH | EXPECTED_SUBMIT_RECORD_CONTRACT |
                           EXPECTED_OLD_SELECTOR_0)[address]),
        )
        result = verify_queue_packet_route(agx, iogpu)
        self.assertEqual(result["base_packet_target"], f"{QUEUE_PACKET_BASE:#x}")
        self.assertFalse(result["parser_only_alternate_route_established"])
        self.assertTrue(result["all_zero_header_command_dispatch_skipped"])
        self.assertEqual(result["all_zero_header_finalizer_target"],
                         f"{QUEUE_EMPTY_FINALIZER:#x}")
        self.assertEqual(result["submit_record_size"], "0x30")

    def test_submit_record_size_mutation_is_rejected(self):
        agx_slots = {
            QUEUE_PACKET_SLOT: QUEUE_PACKET_ENCODING,
            QUEUE_PRECHECK_SLOT: QUEUE_PRECHECK_ENCODING,
            QUEUE_EMPTY_FINALIZER_SLOT: QUEUE_EMPTY_FINALIZER_ENCODING,
            QUEUE_PACKET_BASE_GOT: QUEUE_PACKET_BASE_GOT_ENCODING,
        }
        iogpu_slots = {QUEUE_PACKET_BASE_SLOT: QUEUE_PACKET_BASE_ENCODING}
        iogpu_slots.update({address: encoding for _, address, encoding, _
                            in IOGPU_SELECTOR_0_ENTRIES})
        agx = SimpleNamespace(
            read_u64=agx_slots.get,
            instruction_at=lambda address: instruction(address, *EXPECTED_PACKET_OVERRIDE[address]),
        )
        expected = (EXPECTED_EMPTY_PACKET_PATH | EXPECTED_SUBMIT_RECORD_CONTRACT |
                    EXPECTED_OLD_SELECTOR_0)
        iogpu = SimpleNamespace(
            read_u64=iogpu_slots.get,
            instruction_at=lambda address: instruction(
                address, "mov", "w8, #0x38") if address == 0xfffffff009f43aa4
                else instruction(address, *expected[address]),
        )
        with self.assertRaisesRegex(ValueError, "instruction mismatch"):
            verify_queue_packet_route(agx, iogpu)

    def test_observed_queue_packet_slot_mutation_is_rejected(self):
        agx = SimpleNamespace(read_u64=lambda address: QUEUE_PACKET_ENCODING ^ 1
                              if address == QUEUE_PACKET_SLOT else None)
        with self.assertRaisesRegex(ValueError, "observed-queue-packet-override"):
            verify_queue_packet_route(agx, SimpleNamespace())

    def test_queue_base_method_mutation_is_rejected(self):
        agx_slots = {
            QUEUE_PACKET_SLOT: QUEUE_PACKET_ENCODING,
            QUEUE_PRECHECK_SLOT: QUEUE_PRECHECK_ENCODING,
            QUEUE_EMPTY_FINALIZER_SLOT: QUEUE_EMPTY_FINALIZER_ENCODING,
            QUEUE_PACKET_BASE_GOT: QUEUE_PACKET_BASE_GOT_ENCODING,
        }
        agx = SimpleNamespace(read_u64=agx_slots.get)
        iogpu = SimpleNamespace(read_u64=lambda _address: QUEUE_PACKET_BASE_ENCODING ^ 1)
        with self.assertRaisesRegex(ValueError, "pointer chain changed"):
            verify_queue_packet_route(agx, iogpu)

    def test_queue_command_buffer_callback_is_stateful(self):
        slots = {
            COMMAND_BUFFER_INIT_SLOT: COMMAND_BUFFER_INIT_ENCODING,
            COMMAND_BUFFER_CALLBACK_SLOT: COMMAND_BUFFER_CALLBACK_ENCODING,
        }
        agx = SimpleNamespace(
            read_cstring=lambda _address: "AGXCommandBuffer",
            read_u64=slots.get,
            instruction_at=lambda address: instruction(address, *EXPECTED_COMMAND_BUFFER[address]),
        )
        result = verify_command_buffer_callback(agx)
        self.assertEqual(result["vtable_entries"][1]["decoded_static_target"],
                         f"{COMMAND_BUFFER_CALLBACK:#x}")
        self.assertEqual(len(result["callback_state_write_sites"]), 6)
        self.assertFalse(result["runtime_object_identity_observed"])

    def test_queue_command_buffer_class_mutation_is_rejected(self):
        agx = SimpleNamespace(read_cstring=lambda _address: "OtherClass")
        with self.assertRaisesRegex(ValueError, "class name changed"):
            verify_command_buffer_callback(agx)

    def test_queue_command_buffer_slot_mutation_is_rejected(self):
        slots = {
            COMMAND_BUFFER_INIT_SLOT: COMMAND_BUFFER_INIT_ENCODING,
            COMMAND_BUFFER_CALLBACK_SLOT: COMMAND_BUFFER_CALLBACK_ENCODING ^ 1,
        }
        agx = SimpleNamespace(
            read_cstring=lambda _address: "AGXCommandBuffer",
            read_u64=slots.get,
        )
        with self.assertRaisesRegex(ValueError, "queue-command-buffer-callback"):
            verify_command_buffer_callback(agx)

    def test_firmware_base_slot_is_not_assumed_effective(self):
        slots = {
            FIRMWARE_FACTORY_SLOT: FIRMWARE_FACTORY_ENCODING,
            FIRMWARE_POST_STORE_DEVICE_SLOT: FIRMWARE_POST_STORE_DEVICE_ENCODING,
            FIRMWARE_PARENT_ALLOC_SLOT: FIRMWARE_PARENT_ALLOC_ENCODING,
            FIRMWARE_ALLOC_SLOT: FIRMWARE_ALLOC_ENCODING,
            FIRMWARE_BASE_CALLBACK_SLOT: FIRMWARE_BASE_CALLBACK_ENCODING,
        }
        agx = SimpleNamespace(
            read_cstring=lambda address: {
                FIRMWARE_CLASS_NAME: "AGXArmFirmwareASC",
                FIRMWARE_PARENT_CLASS_NAME: "AGXArmFirmware",
            }.get(address),
            read_u64=slots.get,
            instruction_at=lambda address: instruction(address, *EXPECTED_FIRMWARE_FACTORY[address]),
        )
        kernel = SimpleNamespace(
            read_cstring=lambda _address: "__cxa_pure_virtual",
            instruction_at=lambda address: instruction(address, *EXPECTED_PURE_VIRTUAL[address]),
        )
        result = verify_firmware_callback_candidate(agx, kernel)
        self.assertEqual(result["base_callback_symbol"], "__cxa_pure_virtual")
        self.assertTrue(result["abstract_parent_allocator_returns_null"])
        self.assertTrue(result["immediate_post_store_call_receives_device"])
        self.assertFalse(result["effective_callback_target_resolved"])

    def test_firmware_class_mutation_is_rejected(self):
        agx = SimpleNamespace(read_cstring=lambda _address: "OtherClass")
        kernel = SimpleNamespace(read_cstring=lambda _address: "__cxa_pure_virtual")
        with self.assertRaisesRegex(ValueError, "marker changed"):
            verify_firmware_callback_candidate(agx, kernel)

    def test_firmware_slot_mutation_is_rejected(self):
        slots = {
            FIRMWARE_FACTORY_SLOT: FIRMWARE_FACTORY_ENCODING,
            FIRMWARE_POST_STORE_DEVICE_SLOT: FIRMWARE_POST_STORE_DEVICE_ENCODING,
            FIRMWARE_PARENT_ALLOC_SLOT: FIRMWARE_PARENT_ALLOC_ENCODING,
            FIRMWARE_ALLOC_SLOT: FIRMWARE_ALLOC_ENCODING,
            FIRMWARE_BASE_CALLBACK_SLOT: FIRMWARE_BASE_CALLBACK_ENCODING ^ 1,
        }
        agx = SimpleNamespace(read_cstring=lambda address: "AGXArmFirmwareASC"
                              if address == FIRMWARE_CLASS_NAME else "AGXArmFirmware",
                              read_u64=slots.get)
        kernel = SimpleNamespace(read_cstring=lambda _address: "__cxa_pure_virtual")
        with self.assertRaisesRegex(ValueError, "firmware-base-callback"):
            verify_firmware_callback_candidate(agx, kernel)

    def test_post_store_device_slot_mutation_is_rejected(self):
        slots = {
            FIRMWARE_FACTORY_SLOT: FIRMWARE_FACTORY_ENCODING,
            FIRMWARE_POST_STORE_DEVICE_SLOT: FIRMWARE_POST_STORE_DEVICE_ENCODING ^ 1,
        }
        agx = SimpleNamespace(read_cstring=lambda address: "AGXArmFirmwareASC"
                              if address == FIRMWARE_CLASS_NAME else "AGXArmFirmware",
                              read_u64=slots.get)
        kernel = SimpleNamespace(read_cstring=lambda _address: "__cxa_pure_virtual")
        with self.assertRaisesRegex(ValueError, "post-store-device-method"):
            verify_firmware_callback_candidate(agx, kernel)

    def test_live_queue_links_to_static_device_slot(self):
        raw = self.queue_journal()
        with patch("audit_agx_submit_boundary.JOURNAL_SHA256", hashlib.sha256(raw).hexdigest()), \
             patch("audit_agx_submit_boundary.triage", return_value={
                 "verdict": "owned_queue_and_buffer_observed"
             }):
            result = verify_live_queue_link(raw)
        self.assertEqual(result["queue_vtable_unslid"], f"{LIVE_QUEUE_VTABLE:#x}")
        self.assertEqual(result["device_vtable_unslid"], f"{LIVE_DEVICE_VTABLE:#x}")
        self.assertFalse(result["submit_lookup_checkpoint_observed"])

    def test_wrong_live_queue_vtable_is_rejected(self):
        raw = self.queue_journal(queue_vtable=LIVE_QUEUE_VTABLE ^ 1)
        with patch("audit_agx_submit_boundary.JOURNAL_SHA256", hashlib.sha256(raw).hexdigest()), \
             patch("audit_agx_submit_boundary.triage", return_value={
                 "verdict": "owned_queue_and_buffer_observed"
             }):
            with self.assertRaisesRegex(ValueError, "vtable identity changed"):
                verify_live_queue_link(raw)

    def test_block_fence_metaclass_chain_is_pinned(self):
        agx = SimpleNamespace(
            instruction_at=lambda address: instruction(address, *EXPECTED_METACLASS_CHAIN[address]),
            read_cstring=lambda _address: "AGXBlockFence",
        )
        result = verify_block_fence_metaclass(agx)
        self.assertEqual(result["class_name"], "AGXBlockFence")
        self.assertEqual(result["prepare_slot"], "0xfffffff007b16db0")
        self.assertFalse(result["runtime_object_identity_observed"])

    def test_block_fence_metaclass_name_mutation_is_rejected(self):
        agx = SimpleNamespace(
            instruction_at=lambda address: instruction(address, *EXPECTED_METACLASS_CHAIN[address]),
            read_cstring=lambda _address: "OtherClass",
        )
        with self.assertRaisesRegex(ValueError, "metaclass name changed"):
            verify_block_fence_metaclass(agx)

    def test_block_fence_cleanup_covers_normal_returns_and_pool_fields(self):
        slots = {
            BLOCK_FENCE_RELEASE_SLOT: BLOCK_FENCE_RELEASE_ENCODING,
            BLOCK_FENCE_TAGGED_RELEASE_SLOT: BLOCK_FENCE_TAGGED_RELEASE_ENCODING,
            BLOCK_FENCE_RELEASE_CORE_SLOT: BLOCK_FENCE_RELEASE_CORE_ENCODING,
            BLOCK_FENCE_FREE_SLOT: BLOCK_FENCE_FREE_ENCODING,
        }
        agx = SimpleNamespace(
            read_u64=slots.get,
            instruction_at=lambda address: instruction(
                address, *EXPECTED_BLOCK_FENCE_FREE[address]
            ),
        )
        kernel = SimpleNamespace(
            instruction_at=lambda address: instruction(address, *EXPECTED_RELEASE_CHAIN[address]),
        )
        process = {
            BACKEND_OBJECT_READY: (BACKEND_FAILURE_RELEASE, BACKEND_COMMON_RELEASE),
            BACKEND_FAILURE_RELEASE: (PROCESS_RETURN,),
            BACKEND_COMMON_RELEASE: (PROCESS_RETURN,),
            PROCESS_RETURN: (),
        }
        free_graph = {
            BLOCK_FENCE_FIRST_RELEASE_PATH: (BLOCK_FENCE_FIRST_CLEAR,),
            BLOCK_FENCE_FIRST_CLEAR: (BLOCK_FENCE_SECOND_STAGE,),
            BLOCK_FENCE_SECOND_STAGE: (),
            BLOCK_FENCE_SECOND_RELEASE_PATH: (BLOCK_FENCE_SECOND_CLEAR,),
            BLOCK_FENCE_SECOND_CLEAR: (BLOCK_FENCE_FINAL_STAGE,),
            BLOCK_FENCE_FINAL_STAGE: (),
        }
        with patch("audit_agx_submit_boundary.function_graph", return_value=free_graph) as mocked:
            result = verify_block_fence_cleanup(agx, kernel, process)
        mocked.assert_called_once_with(agx, BLOCK_FENCE_FREE, BLOCK_FENCE_FREE_GRAPH_END)
        self.assertTrue(result["normal_return_local_release_covered"])
        self.assertTrue(result["release_core_dispatches_virtual_free"])
        self.assertFalse(result["final_release_before_selector_return_proven"])

    def test_block_fence_cleanup_rejects_unreleased_normal_return(self):
        slots = {
            BLOCK_FENCE_RELEASE_SLOT: BLOCK_FENCE_RELEASE_ENCODING,
            BLOCK_FENCE_TAGGED_RELEASE_SLOT: BLOCK_FENCE_TAGGED_RELEASE_ENCODING,
            BLOCK_FENCE_RELEASE_CORE_SLOT: BLOCK_FENCE_RELEASE_CORE_ENCODING,
            BLOCK_FENCE_FREE_SLOT: BLOCK_FENCE_FREE_ENCODING,
        }
        agx = SimpleNamespace(
            read_u64=slots.get,
            instruction_at=lambda address: instruction(
                address, *EXPECTED_BLOCK_FENCE_FREE[address]
            ),
        )
        kernel = SimpleNamespace(
            instruction_at=lambda address: instruction(address, *EXPECTED_RELEASE_CHAIN[address]),
        )
        process = {
            BACKEND_OBJECT_READY: (PROCESS_RETURN, BACKEND_FAILURE_RELEASE),
            BACKEND_FAILURE_RELEASE: (PROCESS_RETURN,),
            BACKEND_COMMON_RELEASE: (PROCESS_RETURN,),
            PROCESS_RETURN: (),
        }
        with self.assertRaisesRegex(ValueError, "release coverage changed"):
            verify_block_fence_cleanup(agx, kernel, process)

    @staticmethod
    def queue_journal(queue_vtable=LIVE_QUEUE_VTABLE):
        details = {
            "titan.own-queue.object-vtable-identity": f"unslid={queue_vtable:#x}",
            "titan.own-queue.device-vtable-identity": f"unslid={LIVE_DEVICE_VTABLE:#x}",
            "titan.own-queue.object": "value=0xffffffe86e6aa000",
            "titan.own-queue.device-backref": "value=0xffffffe1c17bc000",
            "titan.own-queue.device": "value=0xffffffe1c17bc000",
        }
        return b"\n".join(json.dumps({
            "schema": "dopamine.a15-ios26.active-probe.v1",
            "run_id": JOURNAL_RUN_ID,
            "stage": stage,
            "status": "PASS",
            "detail": detail,
        }).encode() for stage, detail in details.items()) + b"\n"


if __name__ == "__main__":
    unittest.main()
