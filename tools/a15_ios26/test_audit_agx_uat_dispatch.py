import unittest
from types import SimpleNamespace

from audit_agx_uat_dispatch import (
    ANCHORS,
    AGX_MODE_INIT_VTABLE_ENTRY,
    AGX_GART_VTABLE,
    AGX_GART_SETUP_ENTRY,
    AGX_GART_FACTORY_ENTRIES,
    AGX_GART_SERVICE_FIELD,
    AGX_GART_CLASS_TAG_SLOT,
    AGX_GART_CLASS_TAG_ENCODING,
    AGX_GART_CLASS_TAG,
    AGX_UAT_MUX_VTABLE,
    AGX_UAT_MUX_CLASS_TAG_SLOT,
    AGX_UAT_MUX_CLASS_TAG_ENCODING,
    AGX_UAT_MUX_CLASS_TAG,
    IOUAT_FACTORY_VTABLE,
    CALLBACK_ENTRIES,
    CONSTRUCTOR_ENTRY,
    INDIRECT_ENTRIES,
    IOGPU_INDIRECT_ENTRIES,
    IOGPU_COMMAND_BASE,
    IOGPU_COMMAND_TABLE,
    IOGPU_COMMAND_16,
    IOGPU_ARRAY_PROVIDER_ENTRY,
    IOGPU_SELECTOR_0_ENTRIES,
    IOGPU_EXTERNAL_METHOD_TABLES,
    IOGPU_EXTERNAL_METHOD_ENTRIES,
    TITAN_SELECTOR_CONTRACT,
    IOGPU_BUFFER_ADDRESS_ENTRIES,
    IOGPU_BASE_BUFFER_VTABLE,
    IOGPU_PACKET_GETTER_OFFSET,
    AGX_PREPARSER_CLASSES,
    AGX_PREPARSER_FACTORY_ENTRIES,
    AGX_QUEUE_CREATION_ENTRIES,
    IOGPU_REGISTRY_ARRAY_VTABLE,
    IOGPU_REGISTRY_INSERT_ENTRY,
    BACKING_FACTORY_METACLASS_POINTER,
    BACKING_FACTORY_CLASS_NAME,
    BACKING_FACTORY_CLASS_NAME_ADDRESS,
    BACKING_FACTORY_VIRTUAL_ENTRIES,
    IOBUFFER_KERNEL_MAP_ENTRY,
    IOBUFFER_BACKING_OPTIONS,
    IOBUFFER_TASK_MAP_OPTIONS,
    IOGPU_TABLE_FACTORY_ENTRIES,
    AGX_TABLE_FACTORY_ENTRIES,
    IOGPU_SHARED_BUFFER_FACTORY_ENTRY,
    AGX_SHARED_BUFFER_FACTORY_ENTRY,
    AGX_BASE_TABLE_FALLBACK,
    KERNEL_BUFFER_ADDRESS_ENTRY,
    summarize_devicetree,
    validate_anchors,
    validate_mode_references,
    validate_agx_gart_class_tag,
    validate_agx_uat_mux_class_tag,
    validate_iogpu_command_16,
    validate_callback_entries,
    validate_constructor_entry,
    validate_indirect_entries,
    validate_agx_base_table_fallback,
    validate_iogpu_base_buffer_getter,
    validate_agx_preparser_classes,
    validate_backing_factory_runtime_pointer,
    validate_backing_factory_class_name,
    validate_external_methods,
    validate_titan_selector_contract,
)


class AGXUATDispatchAuditTests(unittest.TestCase):
    def setUp(self):
        self.observed = {
            address: (mnemonic, operands)
            for _, _, address, mnemonic, operands in ANCHORS
        }

    def test_exact_anchors_pass(self):
        self.assertEqual(len(validate_anchors(self.observed)), len(ANCHORS))

    def test_branch_polarity_change_fails(self):
        address = next(address for _, label, address, _, _ in ANCHORS
                       if label == "map.mode-branch")
        self.observed[address] = ("tbnz", "w8, #0, #0xfffffff00887ae54")
        with self.assertRaisesRegex(ValueError, "map.mode-branch"):
            validate_anchors(self.observed)

    def test_mode_source_instance_offset_change_fails(self):
        address = next(address for _, label, address, _, _ in ANCHORS
                       if label == "mode.source-base-offset")
        self.observed[address] = ("mov", "w8, #0xdab4")
        with self.assertRaisesRegex(ValueError, "mode.source-base-offset"):
            validate_anchors(self.observed)

    def test_mode_initializer_belongs_to_agx_instance_vtable(self):
        entry = AGX_MODE_INIT_VTABLE_ENTRY[0]
        self.assertEqual(entry[1] - 0xfffffff007b1e0d0, 0x618)
        self.assertEqual(validate_indirect_entries({entry[1]: entry[2]}.get,
                                                   AGX_MODE_INIT_VTABLE_ENTRY)[0]["decoded_static_target"],
                         "0xfffffff008857ee4")

    def test_mode_initializer_vtable_change_fails(self):
        entry = AGX_MODE_INIT_VTABLE_ENTRY[0]
        with self.assertRaisesRegex(ValueError, "agx-g14p-mode-init"):
            validate_indirect_entries({entry[1]: entry[2] ^ 1}.get,
                                      AGX_MODE_INIT_VTABLE_ENTRY)

    def test_gart_setup_vtable_is_distinct_from_service(self):
        entry = AGX_GART_SETUP_ENTRY[0]
        self.assertEqual(entry[1] - AGX_GART_VTABLE, 0xb0)
        self.assertNotEqual(AGX_GART_VTABLE, 0xfffffff007b1e0d0)
        self.assertEqual(validate_indirect_entries({entry[1]: entry[2]}.get,
                                                   AGX_GART_SETUP_ENTRY)[0]["decoded_static_target"],
                         "0xfffffff00887c57c")

    def test_gart_class_tag_and_setup_argument_pinned(self):
        result = validate_agx_gart_class_tag(
            {AGX_GART_CLASS_TAG_SLOT: AGX_GART_CLASS_TAG_ENCODING}.get,
            lambda _: AGX_GART_CLASS_TAG,
        )
        self.assertEqual(result["tag"], AGX_GART_CLASS_TAG)
        self.assertEqual(self.observed[0xfffffff00887c5cc], ("mov", "x19, x0"))
        with self.assertRaisesRegex(ValueError, "GART class tag changed"):
            validate_agx_gart_class_tag(
                {AGX_GART_CLASS_TAG_SLOT: AGX_GART_CLASS_TAG_ENCODING ^ 1}.get,
                lambda _: AGX_GART_CLASS_TAG,
            )

    def test_service_to_gart_field_is_derived_not_guessed(self):
        self.assertEqual(AGX_GART_SERVICE_FIELD, 0xee80)
        entries = {address: encoded for _, address, encoded, _ in AGX_GART_FACTORY_ENTRIES}
        self.assertEqual(len(validate_indirect_entries(entries.get,
                                                       AGX_GART_FACTORY_ENTRIES)), 2)
        self.assertEqual(self.observed[0xfffffff0087e5c24], ("add", "x25, x0, x8"))
        self.assertEqual(self.observed[0xfffffff0087e7340],
                         ("str", "x0, [x25, #0x360]"))

    def test_live_state_vtable_matches_uat_mux_constructor(self):
        result = validate_agx_uat_mux_class_tag(
            {AGX_UAT_MUX_CLASS_TAG_SLOT: AGX_UAT_MUX_CLASS_TAG_ENCODING}.get,
            lambda _: AGX_UAT_MUX_CLASS_TAG,
        )
        self.assertEqual(result["vtable"], f"{AGX_UAT_MUX_VTABLE:#x}")
        self.assertEqual(self.observed[0xfffffff00888c7d4], ("str", "x16, [x0]"))
        with self.assertRaisesRegex(ValueError, "UAT mux class tag changed"):
            validate_agx_uat_mux_class_tag(
                {AGX_UAT_MUX_CLASS_TAG_SLOT: AGX_UAT_MUX_CLASS_TAG_ENCODING ^ 1}.get,
                lambda _: AGX_UAT_MUX_CLASS_TAG,
            )

    def test_iouat_factory_field_and_vtable_are_pinned(self):
        self.assertEqual(IOUAT_FACTORY_VTABLE, 0xfffffff007aed3a0)
        self.assertEqual(self.observed[0xfffffff00887c960],
                         ("str", "x0, [x22, #0x10]"))
        self.assertEqual(self.observed[0xfffffff00875f374],
                         ("str", "x16, [x0]"))

    def test_mode_initialized_store_change_fails(self):
        address = next(address for _, label, address, _, _ in ANCHORS
                       if label == "mode.initialized-store")
        self.observed[address] = ("strb", "w22, [x8, #0x150]")
        with self.assertRaisesRegex(ValueError, "mode.initialized-store"):
            validate_anchors(self.observed)

    def test_mode_global_single_writer_and_consumers(self):
        mode = [SimpleNamespace(address=0xfffffff008857f28, kind="strb"),
                SimpleNamespace(address=0xfffffff00887acbc, kind="ldrb"),
                SimpleNamespace(address=0xfffffff00887c94c, kind="ldrb")]
        initialized = [SimpleNamespace(address=0xfffffff008857f48, kind="strb"),
                       SimpleNamespace(address=0xfffffff00887b818, kind="ldrb")]
        self.assertEqual(validate_mode_references(mode, initialized)["mode_reference_count"], 3)
        mode.append(SimpleNamespace(address=0xfffffff00887ab00, kind="strb"))
        with self.assertRaisesRegex(ValueError, "write sites changed"):
            validate_mode_references(mode, initialized)

    def test_missing_segment_producer_fails(self):
        address = next(address for _, label, address, _, _ in ANCHORS
                       if label == "iouat.segment-stride")
        del self.observed[address]
        with self.assertRaisesRegex(ValueError, "iouat.segment-stride"):
            validate_anchors(self.observed)

    def test_default_provider_branch_change_fails(self):
        address = next(address for _, label, address, _, _ in ANCHORS
                       if label == "iouat.default-branch")
        self.observed[address] = ("cbnz", "x20, #0xfffffff00875ee58")
        with self.assertRaisesRegex(ValueError, "iouat.default-branch"):
            validate_anchors(self.observed)

    def test_agx_factory_provider_change_fails(self):
        address = next(address for _, label, address, _, _ in ANCHORS
                       if label == "factory.null-provider")
        self.observed[address] = ("mov", "x3, x19")
        with self.assertRaisesRegex(ValueError, "factory.null-provider"):
            validate_anchors(self.observed)

    def test_map2_descriptor_forward_change_fails(self):
        address = next(address for _, label, address, _, _ in ANCHORS
                       if label == "map2.descriptor-forward")
        self.observed[address] = ("mov", "x1, x20")
        with self.assertRaisesRegex(ValueError, "map2.descriptor-forward"):
            validate_anchors(self.observed)

    def test_indirect_entries_use_kernel_static_base(self):
        entries = {
            address: encoded
            for _, address, encoded, _ in INDIRECT_ENTRIES
        }
        self.assertEqual(len(validate_indirect_entries(entries.get)), 3)

    def test_indirect_target_change_fails(self):
        entries = {address: 0 for _, address, _, _ in INDIRECT_ENTRIES}
        with self.assertRaisesRegex(ValueError, "upstream-map-dispatch"):
            validate_indirect_entries(entries.get)

    def test_indirect_pac_metadata_change_fails(self):
        entries = {address: encoded for _, address, encoded, _ in INDIRECT_ENTRIES}
        entries[INDIRECT_ENTRIES[0][1]] ^= 1 << 48
        with self.assertRaisesRegex(ValueError, "upstream-map-dispatch"):
            validate_indirect_entries(entries.get)

    def test_wrapper_descriptor_forward_change_fails(self):
        address = next(address for _, label, address, _, _ in ANCHORS
                       if label == "wrapper.descriptor-forward")
        self.observed[address] = ("mov", "x3, x21")
        with self.assertRaisesRegex(ValueError, "wrapper.descriptor-forward"):
            validate_anchors(self.observed)

    def test_command_16_jump_table_target(self):
        slot = IOGPU_COMMAND_TABLE + (16 - 2) * 4
        displacement = IOGPU_COMMAND_16 - IOGPU_COMMAND_BASE
        self.assertEqual(
            validate_iogpu_command_16({slot: displacement}.get)["handler"],
            f"{IOGPU_COMMAND_16:#x}",
        )
        with self.assertRaisesRegex(ValueError, "IOGPU command 16"):
            validate_iogpu_command_16({slot: displacement + 4}.get)

    def test_record_array_object_change_fails(self):
        address = next(address for _, label, address, _, _ in ANCHORS
                       if label == "record.array-object")
        self.observed[address] = ("ldr", "x2, [x8]")
        with self.assertRaisesRegex(ValueError, "record.array-object"):
            validate_anchors(self.observed)

    def test_array_provider_parent_object_change_fails(self):
        address = next(address for _, label, address, _, _ in ANCHORS
                       if label == "provider.parent-object")
        self.observed[address] = ("ldr", "x0, [x19, #0x90]")
        with self.assertRaisesRegex(ValueError, "provider.parent-object"):
            validate_anchors(self.observed)

    def test_frame_length_guard_change_fails(self):
        address = next(address for _, label, address, _, _ in ANCHORS
                       if label == "frame.end-overflow")
        self.observed[address] = ("b.lo", "#0xfffffff009f4be44")
        with self.assertRaisesRegex(ValueError, "frame.end-overflow"):
            validate_anchors(self.observed)

    def test_array_provider_candidate_entry(self):
        address, encoded = IOGPU_ARRAY_PROVIDER_ENTRY[0][1:3]
        self.assertEqual(
            len(validate_indirect_entries(
                {address: encoded}.get, IOGPU_ARRAY_PROVIDER_ENTRY
            )), 1
        )
        with self.assertRaisesRegex(ValueError, "granule-array-provider-candidate"):
            validate_indirect_entries(
                {address: encoded ^ (1 << 48)}.get,
                IOGPU_ARRAY_PROVIDER_ENTRY,
            )

    def test_iogpu_indirect_entries(self):
        entries = {address: encoded for _, address, encoded, _ in IOGPU_INDIRECT_ENTRIES}
        self.assertEqual(
            len(validate_indirect_entries(entries.get, IOGPU_INDIRECT_ENTRIES)), 6
        )
        entries[IOGPU_INDIRECT_ENTRIES[0][1]] ^= 1 << 48
        with self.assertRaisesRegex(ValueError, "resource-map-dispatch"):
            validate_indirect_entries(entries.get, IOGPU_INDIRECT_ENTRIES)

    def test_packet_process_dispatch_change_fails(self):
        entries = {address: encoded for _, address, encoded, _ in IOGPU_INDIRECT_ENTRIES}
        packet = next(item for item in IOGPU_INDIRECT_ENTRIES
                      if item[0] == "packet-process-dispatch")
        entries[packet[1]] ^= 1 << 48
        with self.assertRaisesRegex(ValueError, "packet-process-dispatch"):
            validate_indirect_entries(entries.get, IOGPU_INDIRECT_ENTRIES)

    def test_packet_object_init_dispatch_change_fails(self):
        entries = {address: encoded for _, address, encoded, _ in IOGPU_INDIRECT_ENTRIES}
        init = next(item for item in IOGPU_INDIRECT_ENTRIES
                    if item[0] == "packet-object-init-dispatch")
        entries[init[1]] ^= 1 << 48
        with self.assertRaisesRegex(ValueError, "packet-object-init-dispatch"):
            validate_indirect_entries(entries.get, IOGPU_INDIRECT_ENTRIES)

    def test_object_table_bounds_change_fails(self):
        address = next(address for _, label, address, _, _ in ANCHORS
                       if label == "table.check-limit")
        self.observed[address] = ("cmp", "w8, w2")
        with self.assertRaisesRegex(ValueError, "table.check-limit"):
            validate_anchors(self.observed)

    def test_selector_0_entries_and_copy_semantics(self):
        entries = {address: encoded for _, address, encoded, _ in IOGPU_SELECTOR_0_ENTRIES}
        self.assertEqual(
            len(validate_indirect_entries(entries.get, IOGPU_SELECTOR_0_ENTRIES)), 2
        )
        entries[IOGPU_SELECTOR_0_ENTRIES[1][1]] ^= 1 << 48
        with self.assertRaisesRegex(ValueError, "selector-0-mode-set"):
            validate_indirect_entries(entries.get, IOGPU_SELECTOR_0_ENTRIES)
        address = next(address for _, label, address, _, _ in ANCHORS
                       if label == "usercopy.pan-off")
        self.observed[address] = ("msr", "pan, #1")
        with self.assertRaisesRegex(ValueError, "usercopy.pan-off"):
            validate_anchors(self.observed)

    def test_external_methods_pin_both_modes_and_contracts(self):
        values = {}
        for _, base in IOGPU_EXTERNAL_METHOD_TABLES:
            for index, _, encoding, input_contract, output_contract, _ in IOGPU_EXTERNAL_METHOD_ENTRIES:
                slot = base + 0x18 * index
                values.update({slot: encoding, slot + 8: input_contract, slot + 16: output_contract})
        self.assertEqual(len(validate_external_methods(values.get)), 18)
        mode, base = IOGPU_EXTERNAL_METHOD_TABLES[1]
        slot = base + 0x18 * 25
        values[slot + 8] ^= 1
        with self.assertRaisesRegex(ValueError, f"external {mode} index 25"):
            validate_external_methods(values.get)

    def test_external_submit_target_change_fails(self):
        values = {}
        for _, base in IOGPU_EXTERNAL_METHOD_TABLES:
            for index, _, encoding, input_contract, output_contract, _ in IOGPU_EXTERNAL_METHOD_ENTRIES:
                slot = base + 0x18 * index
                values.update({slot: encoding, slot + 8: input_contract, slot + 16: output_contract})
        values[IOGPU_EXTERNAL_METHOD_TABLES[0][1] + 0x18 * 25] ^= 4
        with self.assertRaisesRegex(ValueError, "external mode-clear index 25"):
            validate_external_methods(values.get)

    def test_submit_boundary_requires_queue_before_stateful_parser(self):
        labels = {label: address for _, label, address, _, _ in ANCHORS}
        self.assertLess(labels["submit.queue-lookup"], labels["submit.batch-entry"])
        self.assertLess(labels["batch.state-active"], labels["batch.parser-dispatch"])
        self.assertLess(labels["batch.backend-setup"], labels["batch.parser-dispatch"])
        self.assertLess(labels["packet.buffer-lookup"], labels["packet.buffer-map-call"])
        for label in (
            "submit.four-scalars", "submit.queue-lookup", "submit.queue-missing",
            "submit.queue-field-compare", "submit.queue-mismatch",
            "submit.batch-entry", "batch.state-active", "batch.queue-lock",
            "batch.process-entry", "batch.backend-setup", "batch.parser-dispatch",
        ):
            with self.subTest(label=label):
                observed = self.observed.copy()
                observed[labels[label]] = ("nop", "")
                with self.assertRaisesRegex(ValueError, label.replace(".", r"\.")):
                    validate_anchors(observed)

    def test_agx_queue_and_fence_preparser_identity(self):
        names = {address: name for name, address in AGX_PREPARSER_CLASSES}
        self.assertEqual(validate_agx_preparser_classes(names.get), {
            name: f"{address:#x}" for name, address in AGX_PREPARSER_CLASSES
        })
        names[AGX_PREPARSER_CLASSES[1][1]] = "OtherFence"
        with self.assertRaisesRegex(ValueError, "AGXBlockFence"):
            validate_agx_preparser_classes(names.get)

        entries = {address: encoded for _, address, encoded, _ in
                   AGX_PREPARSER_FACTORY_ENTRIES}
        self.assertEqual(len(validate_indirect_entries(
            entries.get, AGX_PREPARSER_FACTORY_ENTRIES
        )), 5)
        entries[AGX_PREPARSER_FACTORY_ENTRIES[-1][1]] ^= 1 << 48
        with self.assertRaisesRegex(ValueError, "agx-block-fence-prepare"):
            validate_indirect_entries(entries.get, AGX_PREPARSER_FACTORY_ENTRIES)

        labels = {label: address for _, label, address, _, _ in ANCHORS}
        self.assertLess(labels["fence.pool-lock"], labels["fence.pool-bitmap-write"])
        for label in ("queue.factory-class", "queue.class-name",
                      "queue.vtable-base", "queue.vtable-adjust",
                      "queue.vtable-store", "fence.factory-class",
                      "fence.class-name", "fence.vtable-base",
                      "fence.vtable-adjust", "fence.vtable-store", "fence.pool-lock",
                      "fence.pool-bitmap-write"):
            with self.subTest(label=label):
                observed = self.observed.copy()
                observed[labels[label]] = ("nop", "")
                with self.assertRaisesRegex(ValueError, label.replace(".", r"\.")):
                    validate_anchors(observed)

    def test_queue_creation_has_stateful_pre_return_path(self):
        entries = {address: encoded for _, address, encoded, _ in
                   AGX_QUEUE_CREATION_ENTRIES}
        self.assertEqual(len(validate_indirect_entries(
            entries.get, AGX_QUEUE_CREATION_ENTRIES
        )), 3)
        entries[AGX_QUEUE_CREATION_ENTRIES[2][1]] ^= 1 << 48
        with self.assertRaisesRegex(ValueError, "agx-command-queue-resource-setup"):
            validate_indirect_entries(entries.get, AGX_QUEUE_CREATION_ENTRIES)

        labels = {label: address for _, label, address, _, _ in ANCHORS}
        self.assertLess(labels["external.queue-init"], labels["external.queue-register"])
        self.assertLess(labels["external.queue-register"], labels["external.queue-return"])
        self.assertLess(labels["queue.resource-allocate"], labels["queue.resource-ready"])
        self.assertLess(labels["queue.resource-finalize"], labels["queue.resource-ready"])
        for label in (
            "external.queue-register", "external.queue-return",
            "queue.init-device-call", "queue.init-base-call",
            "queue.init-resource-array", "queue.init-resource-call-zero",
            "queue.init-resource-call", "queue.resource-allocate",
            "queue.resource-setup", "queue.resource-store",
            "queue.resource-finalize", "queue.resource-ready",
        ):
            with self.subTest(label=label):
                observed = self.observed.copy()
                observed[labels[label]] = ("nop", "")
                with self.assertRaisesRegex(ValueError, label.replace(".", r"\.")):
                    validate_anchors(observed)

    def test_g14p_queue_requires_extended_input_before_factory(self):
        labels = {label: address for _, label, address, _, _ in ANCHORS}
        self.assertLess(labels["external.queue-size-accepted"],
                        labels["external.queue-init"])
        self.assertLess(labels["external.queue-size-reject"],
                        labels["external.queue-init"])
        self.assertLess(labels["queue.agx-options-low"],
                        labels["queue.agx-options-all"])
        for label in (
            "queue.base-input-size", "queue.agx-input-size",
            "queue.agx-input-size-store", "external.queue-input-size",
            "external.queue-device-size", "external.queue-minimum-size",
            "external.queue-exact-size", "external.queue-size-accepted",
            "external.queue-size-reject", "queue.agx-options-low",
            "queue.agx-options-all",
        ):
            with self.subTest(label=label):
                observed = self.observed.copy()
                observed[labels[label]] = ("nop", "")
                with self.assertRaisesRegex(ValueError, label.replace(".", r"\.")):
                    validate_anchors(observed)

    def test_historical_selector_values_are_one_above_compatible_indices(self):
        header = "\n".join(
            f"#define {name} ({historical})"
            for name, historical, _ in TITAN_SELECTOR_CONTRACT
        )
        self.assertEqual(len(validate_titan_selector_contract(header)), 5)
        changed = header.replace(
            "#define IOGPU_SELECTOR_SUBMIT_COMMAND_BUFFERS (26)",
            "#define IOGPU_SELECTOR_SUBMIT_COMMAND_BUFFERS (25)",
        )
        with self.assertRaisesRegex(ValueError, "IOGPU_SELECTOR_SUBMIT_COMMAND_BUFFERS"):
            validate_titan_selector_contract(changed)

    def test_shared_object_registration_path_is_pinned(self):
        for label, changed in (
            ("shared.client-table", ("ldr", "x0, [x0, #0x118]")),
            ("shared.registration-array", ("ldr", "x0, [x23, #0x88]")),
            ("shared.register-object", ("bl", "#0xfffffff009f17f10")),
        ):
            with self.subTest(label=label):
                observed = self.observed.copy()
                address = next(address for _, name, address, _, _ in ANCHORS
                               if name == label)
                observed[address] = changed
                with self.assertRaisesRegex(ValueError, label):
                    validate_anchors(observed)

    def test_common_backing_object_and_mapping_path_are_pinned(self):
        for label, changed in (
            ("shared.backing-reload", ("ldr", "x23, [x19, #0x48]")),
            ("shared.backing-alias-store", ("str", "x0, [x19, #0x28]")),
            ("shared.user-map-create", ("bl", "#0xfffffff0086dfc88")),
        ):
            with self.subTest(label=label):
                observed = self.observed.copy()
                address = next(address for _, name, address, _, _ in ANCHORS
                               if name == label)
                observed[address] = changed
                with self.assertRaisesRegex(ValueError, label):
                    validate_anchors(observed)

    def test_table_factory_provenance_and_pac_entries(self):
        for expected in (IOGPU_TABLE_FACTORY_ENTRIES, AGX_TABLE_FACTORY_ENTRIES):
            with self.subTest(factory=expected[0][0]):
                values = {address: encoded for _, address, encoded, _ in expected}
                self.assertEqual(len(validate_indirect_entries(values.get, expected)), len(expected))
                values[expected[0][1]] ^= 1 << 48
                with self.assertRaisesRegex(ValueError, expected[0][0]):
                    validate_indirect_entries(values.get, expected)

    def test_shared_factory_mode_and_mapping_options(self):
        for expected in (IOGPU_SHARED_BUFFER_FACTORY_ENTRY,
                         AGX_SHARED_BUFFER_FACTORY_ENTRY):
            address, encoded = expected[0][1:3]
            self.assertEqual(len(validate_indirect_entries(
                {address: encoded}.get, expected)), 1)
        for label, changed in (
            ("shared.base-map-options", ("mov", "w3, #0x1001")),
            ("shared.agx-mode-compare", ("cmp", "w3, #1")),
            ("shared.agx-read-only-options", ("mov", "w4, #1")),
            ("shared.user-map-options", ("mov", "x3, x21")),
        ):
            with self.subTest(label=label):
                observed = self.observed.copy()
                address = next(address for _, name, address, _, _ in ANCHORS
                               if name == label)
                observed[address] = changed
                with self.assertRaisesRegex(ValueError, label):
                    validate_anchors(observed)

    def test_agx_base_table_fallback_targets_fixed_option_factory(self):
        address, encoded, _, _, slot = AGX_BASE_TABLE_FALLBACK
        method = IOGPU_SHARED_BUFFER_FACTORY_ENTRY[0][2]
        self.assertEqual(
            validate_agx_base_table_fallback(
                {address: encoded}.get, {slot: method}.get
            )["slot"], f"{slot:#x}",
        )
        with self.assertRaisesRegex(ValueError, "base-table fallback"):
            validate_agx_base_table_fallback(
                {address: encoded ^ 1}.get, {slot: method}.get
            )
        with self.assertRaisesRegex(ValueError, "base-table method"):
            validate_agx_base_table_fallback(
                {address: encoded}.get, {slot: method ^ 1}.get
            )

    def test_base_buffer_packet_getter_matches_installed_vtable(self):
        slot = IOGPU_BASE_BUFFER_VTABLE + IOGPU_PACKET_GETTER_OFFSET
        expected = IOGPU_BUFFER_ADDRESS_ENTRIES[1]
        self.assertEqual(slot, expected[1])
        self.assertEqual(validate_iogpu_base_buffer_getter(
            {slot: expected[2]}.get
        )["decoded_static_target"], f"{expected[3]:#x}")
        with self.assertRaisesRegex(ValueError, "packet getter"):
            validate_iogpu_base_buffer_getter({slot: expected[2] ^ 1}.get)

    def test_mapping_context_reaches_task_map_field(self):
        address = next(address for _, label, address, _, _ in ANCHORS
                       if label == "shared.mapping-task-map")
        self.observed[address] = ("ldr", "x16, [x19, #0x30]")
        with self.assertRaisesRegex(ValueError, "shared.mapping-task-map"):
            validate_anchors(self.observed)

    def test_backing_task_choice_and_options_are_pinned(self):
        for label, changed in (
            ("shared.backing-task-choice", ("csel", "x0, xzr, x2, eq")),
            ("shared.backing-options-high", ("movk", "w1, #0, lsl #16")),
            ("shared.backing-capacity", ("mov", "x2, x1")),
            ("shared.backing-user-tag", ("mov", "w5, #0")),
            ("shared.backing-init-call", ("blraa", "x9, x17")),
        ):
            with self.subTest(label=label):
                observed = self.observed.copy()
                address = next(address for _, name, address, _, _ in ANCHORS
                               if name == label)
                observed[address] = changed
                with self.assertRaisesRegex(ValueError, label):
                    validate_anchors(observed)

    def test_runtime_metaclass_pointer_is_zero_fill(self):
        section = SimpleNamespace(
            name="__common", virtual_address=BACKING_FACTORY_METACLASS_POINTER,
            size=8, content=b"",
        )
        self.assertTrue(validate_backing_factory_runtime_pointer(
            [section])["runtime_value_unobserved"])
        section.content = b"\0" * 8
        with self.assertRaisesRegex(ValueError, "zero-fill __common"):
            validate_backing_factory_runtime_pointer([section])

    def test_backing_factory_class_registration(self):
        read_name = {BACKING_FACTORY_CLASS_NAME_ADDRESS: BACKING_FACTORY_CLASS_NAME}.get
        result = validate_backing_factory_class_name(read_name)
        self.assertEqual(result["metaclass_global"], f"{BACKING_FACTORY_METACLASS_POINTER:#x}")
        self.assertTrue(result["runtime_allocation_unobserved"])
        with self.assertRaisesRegex(ValueError, "class name mismatch"):
            validate_backing_factory_class_name(lambda address: "IOSKMemoryBuffer")
        for label in ("shared.metaclass-global-address", "shared.metaclass-name-address",
                      "shared.metaclass-register", "shared.metaclass-vtable-store",
                      "shared.object-vtable-store", "shared.factory-metaclass-load",
                      "shared.factory-allocate-slot", "shared.factory-init-slot",
                      "shared.init-task-selection", "shared.init-range-count",
                      "shared.init-descriptor-call"):
            with self.subTest(label=label):
                observed = self.observed.copy()
                address = next(address for _, name, address, _, _ in ANCHORS
                               if name == label)
                observed[address] = ("nop", "")
                with self.assertRaisesRegex(ValueError, label):
                    validate_anchors(observed)

    def test_backing_factory_virtual_dispatch(self):
        entries = {address: encoded for _, address, encoded, _ in BACKING_FACTORY_VIRTUAL_ENTRIES}
        self.assertEqual(len(validate_indirect_entries(
            entries.get, BACKING_FACTORY_VIRTUAL_ENTRIES)), 2)
        for label, address, encoded, _ in BACKING_FACTORY_VIRTUAL_ENTRIES:
            with self.subTest(label=label):
                changed = entries.copy()
                changed[address] = encoded ^ (1 << 48)
                with self.assertRaisesRegex(ValueError, label):
                    validate_indirect_entries(changed.get, BACKING_FACTORY_VIRTUAL_ENTRIES)

    def test_dual_mapping_uses_same_descriptor_and_kernel_map_method(self):
        label, address, encoded, target = IOBUFFER_KERNEL_MAP_ENTRY[0]
        self.assertEqual(target, 0xfffffff0086e0abc)
        self.assertEqual(validate_indirect_entries(
            {address: encoded}.get, IOBUFFER_KERNEL_MAP_ENTRY
        )[0]["decoded_static_target"], f"{target:#x}")
        with self.assertRaisesRegex(ValueError, label):
            validate_indirect_entries(
                {address: encoded ^ (1 << 48)}.get, IOBUFFER_KERNEL_MAP_ENTRY
            )
        for anchor in (
            "shared.backing-alias-store", "shared.user-map-backing",
            "shared.user-map-create", "shared.kernel-map-source",
            "shared.kernel-map-dispatch-slot", "shared.kernel-map-call",
            "shared.kernel-map-store", "shared.kernel-map-lazy-call",
            "shared.kernel-map-option-anywhere", "shared.kernel-map-create",
            "buffer.base-object", "buffer.base-call",
        ):
            with self.subTest(anchor=anchor):
                observed = self.observed.copy()
                instruction_address = next(
                    address for _, name, address, _, _ in ANCHORS if name == anchor
                )
                observed[instruction_address] = ("nop", "")
                with self.assertRaisesRegex(ValueError, anchor):
                    validate_anchors(observed)

    def test_registry_store_and_packet_lookup_round_trip_is_pinned(self):
        label, address, encoded, target = IOGPU_REGISTRY_INSERT_ENTRY[0]
        self.assertEqual(address, IOGPU_REGISTRY_ARRAY_VTABLE + 0x78)
        self.assertEqual(validate_indirect_entries(
            {address: encoded}.get, IOGPU_REGISTRY_INSERT_ENTRY
        )[0]["decoded_static_target"], f"{target:#x}")
        with self.assertRaisesRegex(ValueError, label):
            validate_indirect_entries(
                {address: encoded ^ (1 << 48)}.get, IOGPU_REGISTRY_INSERT_ENTRY
            )
        for anchor in (
            "table.init-array-create", "table.init-array-store",
            "table.array-vtable-store", "shared.registration-array",
            "shared.registration-object", "table.insert-argument",
            "table.insert-dispatch", "table.insert-slot-store",
            "shared.output-id", "packet.buffer-table", "packet.buffer-id",
            "packet.buffer-lookup", "table.lookup-id-guard",
            "table.check-limit", "table.lookup-slot-load",
        ):
            with self.subTest(anchor=anchor):
                observed = self.observed.copy()
                instruction_address = next(
                    address for _, name, address, _, _ in ANCHORS if name == anchor
                )
                observed[instruction_address] = ("nop", "")
                with self.assertRaisesRegex(ValueError, anchor):
                    validate_anchors(observed)

    def test_backing_task_mapping_options_and_address_flow(self):
        self.assertEqual(IOBUFFER_BACKING_OPTIONS, 0x10060)
        self.assertEqual(IOBUFFER_TASK_MAP_OPTIONS, 1)
        self.assertEqual(IOBUFFER_TASK_MAP_OPTIONS & 0x1000, 0)
        self.assertEqual(IOBUFFER_TASK_MAP_OPTIONS & 0x10000, 0)
        for label in ("shared.task-map-mask-a", "shared.task-map-mask-b",
                      "shared.task-map-options", "shared.task-map-task",
                      "shared.task-map-create", "shared.task-map-store",
                      "shared.task-map-null", "shared.task-map-get-address",
                      "shared.task-map-buffer-address", "shared.mapping-task-map",
                      "shared.map-object-dispatch"):
            with self.subTest(label=label):
                observed = self.observed.copy()
                address = next(address for _, name, address, _, _ in ANCHORS
                               if name == label)
                observed[address] = ("nop", "")
                with self.assertRaisesRegex(ValueError, label):
                    validate_anchors(observed)

    def test_buffer_address_candidate_entries(self):
        entries = {address: encoded for _, address, encoded, _ in IOGPU_BUFFER_ADDRESS_ENTRIES}
        self.assertEqual(
            len(validate_indirect_entries(entries.get, IOGPU_BUFFER_ADDRESS_ENTRIES)), 2
        )
        entries[IOGPU_BUFFER_ADDRESS_ENTRIES[0][1]] ^= 1 << 48
        with self.assertRaisesRegex(ValueError, "buffer-address-base-candidate"):
            validate_indirect_entries(entries.get, IOGPU_BUFFER_ADDRESS_ENTRIES)
        address = next(address for _, label, address, _, _ in ANCHORS
                       if label == "buffer.slice-offset")
        self.observed[address] = ("ldr", "x8, [x19, #0x58]")
        with self.assertRaisesRegex(ValueError, "buffer.slice-offset"):
            validate_anchors(self.observed)

    def test_kernel_buffer_address_candidate(self):
        address, encoded = KERNEL_BUFFER_ADDRESS_ENTRY[0][1:3]
        self.assertEqual(
            len(validate_indirect_entries(
                {address: encoded}.get, KERNEL_BUFFER_ADDRESS_ENTRY
            )), 1
        )
        with self.assertRaisesRegex(ValueError, "buffer-base-virtual-candidate"):
            validate_indirect_entries(
                {address: encoded ^ (1 << 48)}.get,
                KERNEL_BUFFER_ADDRESS_ENTRY,
            )

    def test_constructor_indirect_entry(self):
        address, encoded, target = CONSTRUCTOR_ENTRY
        self.assertEqual(
            validate_constructor_entry({address: encoded}.get)["decoded_static_target"],
            f"{target:#x}",
        )
        with self.assertRaisesRegex(ValueError, "IOUAT constructor"):
            validate_constructor_entry({address: encoded ^ (1 << 48)}.get)

    def test_wrong_devicetree_is_rejected(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as directory:
            path = Path(directory) / "tree.raw"
            path.write_bytes(b"not the pinned tree")
            with self.assertRaisesRegex(ValueError, "DeviceTree SHA-256 mismatch"):
                summarize_devicetree(path)

    def test_callback_candidates_match_names_and_targets(self):
        values = {}
        names = {}
        for name, header, header_value, slot, encoded, _ in CALLBACK_ENTRIES:
            values[header] = header_value
            values[slot] = encoded
            names[0xfffffff007004000 + (header_value & 0xffffffff)] = name
        self.assertEqual(
            len(validate_callback_entries(values.get, names.get)), 4
        )

    def test_callback_name_mismatch_fails(self):
        values = {}
        names = {}
        for name, header, header_value, slot, encoded, _ in CALLBACK_ENTRIES:
            values[header] = header_value
            values[slot] = encoded
            names[0xfffffff007004000 + (header_value & 0xffffffff)] = name
        names[0xfffffff007004000 + (CALLBACK_ENTRIES[0][2] & 0xffffffff)] = "other"
        with self.assertRaisesRegex(ValueError, "uat callback table"):
            validate_callback_entries(values.get, names.get)


if __name__ == "__main__":
    unittest.main()
