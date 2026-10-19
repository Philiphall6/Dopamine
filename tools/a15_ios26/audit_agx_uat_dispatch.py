#!/usr/bin/env python3
"""Pin the AGX/IOUAT map dispatch observed in the 23A355 kernelcache.

This is a static disassembly check. It never runs device code or changes the
kernelcache. It pins one UAT callback's protected call but cannot establish
which callback table the device selects at runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re

import capstone

from analyze_sptm_txm import MachOImage
from analyze_devicetree import parse_node, walk


IMAGE_SHA256 = "8867208c59bfa426611c36fcfe570ffc41cc75ee293472fe7197860d0c5223f1"
DEVICETREE_SHA256 = "c7d59f0364cdb504ee32881142b03dadcea85fe5808de7dd69e63bea7a9d5725"
AGX_NAME = "com.apple.AGXG14P"
IOGPU_NAME = "com.apple.iokit.IOGPUFamily"
KERNEL_NAME = "com.apple.kernel"
KERNEL_STATIC_BASE = 0xfffffff007004000
INDIRECT_ENTRIES = (
    ("upstream-map-dispatch", 0xfffffff007b21978, 0x801134f8018752ac, 0xfffffff0088792ac),
    ("map-dispatch", 0xfffffff007b1c670, 0x8011a68c018768a4, 0xfffffff00887a8a4),
    ("map2-dispatch", 0xfffffff007b1c5a8, 0x8011edc1018780ac, 0xfffffff00887c0ac),
)
AGX_MODE_INIT_VTABLE_ENTRY = (
    ("agx-g14p-mode-init", 0xfffffff007b1e6e8,
     0x80112d1401853ee4, 0xfffffff008857ee4),
)
AGX_GART_VTABLE = 0xfffffff007b1c4d8
AGX_GART_SETUP_ENTRY = (
    ("agx-gart-setup-wrapper", 0xfffffff007b1c588,
     0x801193620187857c, 0xfffffff00887c57c),
)
AGX_GART_FACTORY_ENTRIES = (
    ("agx-g14p-create-gart", 0xfffffff007b1e7c8,
     0x80117cbe017d7e18, 0xfffffff0087dbe18),
    ("agx-g14p-allocate-gart", 0xfffffff007b1e920,
     0x80118a940184c840, 0xfffffff008850840),
)
AGX_GART_SERVICE_FIELD = 0xeb20 + 0x360
AGX_GART_CLASS_TAG_SLOT = 0xfffffff007b24610
AGX_GART_CLASS_TAG_ENCODING = 0x00200000000fca68
AGX_GART_CLASS_TAG = "site.AGXGartG14"
AGX_UAT_MUX_VTABLE = 0xfffffff007b22ae0
AGX_UAT_MUX_CLASS_TAG_SLOT = 0xfffffff007b25590
AGX_UAT_MUX_CLASS_TAG_ENCODING = 0x0020000000101d5b
AGX_UAT_MUX_CLASS_TAG = "site.AGXUATMux"
IOUAT_FACTORY_VTABLE = 0xfffffff007aed3a0
AGX_MODE_GLOBAL = 0xfffffff00ab61150
AGX_MODE_INITIALIZED_GLOBAL = 0xfffffff00ab61160
IOGPU_INDIRECT_ENTRIES = (
    ("resource-map-dispatch", 0xfffffff007e40c98, 0x8011dc5902f10a5c, 0xfffffff009f14a5c),
    ("resource-forward-dispatch", 0xfffffff007e40c80, 0x80117bbd02f12e1c, 0xfffffff009f16e1c),
    ("command-handler-dispatch", 0xfffffff007e46c08, 0x8011fa0f02f46678, 0xfffffff009f4a678),
    ("command-framing-dispatch", 0xfffffff007e46c00, 0x8011006d02f47d6c, 0xfffffff009f4bd6c),
    ("packet-process-dispatch", 0xfffffff007e46c50, 0x80119dcc02f47e9c, 0xfffffff009f4be9c),
    ("packet-object-init-dispatch", 0xfffffff007e46c10, 0x8011fcfc02f44aec, 0xfffffff009f48aec),
)
IOGPU_COMMAND_TABLE = 0xfffffff009f4bb28
IOGPU_COMMAND_BASE = 0xfffffff009f4a6cc
IOGPU_COMMAND_16 = 0xfffffff009f4a7cc
IOGPU_ARRAY_PROVIDER_ENTRY = (
    ("granule-array-provider-candidate", 0xfffffff007e478e8,
     0x80119e4102f50fec, 0xfffffff009f54fec),
)
IOGPU_SELECTOR_0_ENTRIES = (
    ("selector-0-mode-clear", 0xfffffff007e429b8,
     0x8030705d02f18684, 0xfffffff009f1c684),
    ("selector-0-mode-set", 0xfffffff007e42b08,
     0x8030705d02f18684, 0xfffffff009f1c684),
)
IOGPU_EXTERNAL_METHOD_TABLES = (
    ("mode-clear", 0xfffffff007e41f30),
    ("mode-set", 0xfffffff007e42470),
)
IOGPU_EXTERNAL_METHOD_ENTRIES = (
    (6, "new-command-queue", 0x8030bcad02f16524,
     0xffffffff00000000, 0x1000000000, 0xfffffff009f1a524),
    (7, "other-queue-method", 0x8030bcad02f16890,
     0x1, 0x0, 0xfffffff009f1a890),
    (12, "shared-memory-contract-candidate", 0x8030bcad02f16b24,
     0x2, 0x1000000000, 0xfffffff009f1ab24),
    (13, "other-one-scalar-method", 0x8030bcad02f16b4c,
     0x1, 0x0, 0xfffffff009f1ab4c),
    (14, "notification-queue-contract-candidate", 0x8030bcad02f16b60,
     0x2, 0x1000000000, 0xfffffff009f1ab60),
    (15, "other-one-scalar-method", 0x8030bcad02f16b80,
     0x1, 0x0, 0xfffffff009f1ab80),
    (24, "set-notification-contract-candidate", 0x8030bcad02f16c24,
     0x2, 0x0, 0xfffffff009f1ac24),
    (25, "submit-command-buffers", 0x8030bcad02f16cec,
     0xffffffff00000004, 0x1, 0xfffffff009f1acec),
    (26, "other-buffer-method", 0x8030bcad02f16fc0,
     0xc00000001, 0x1, 0xfffffff009f1afc0),
)
TITAN_SELECTOR_CONTRACT = (
    ("IOGPU_SELECTOR_CREATE_COMMAND_QUEUE", 7, 6),
    ("IOGPU_SELECTOR_CREATE_NOTIFICATION_QUEUE", 15, 14),
    ("IOGPU_SELECTOR_CREATE_SHARED_MEMORY", 13, 12),
    ("IOGPU_SELECTOR_SET_NOTIFICATION_QUEUE", 25, 24),
    ("IOGPU_SELECTOR_SUBMIT_COMMAND_BUFFERS", 26, 25),
)
IOGPU_BUFFER_ADDRESS_ENTRIES = (
    ("buffer-address-base-candidate", 0xfffffff007e43f78,
     0x8011880702f20914, 0xfffffff009f24914),
    ("buffer-address-slice-candidate", 0xfffffff007e440c8,
     0x8011880702f21130, 0xfffffff009f25130),
)
IOGPU_BASE_BUFFER_VTABLE = 0xfffffff007e44048
IOGPU_PACKET_GETTER_OFFSET = 0x80
AGX_PREPARSER_CLASSES = (
    ("AGXCommandQueue", 0xfffffff0070faf02),
    ("AGXBlockFence", 0xfffffff0070fa75c),
)
AGX_PREPARSER_FACTORY_ENTRIES = (
    ("agx-command-queue-factory", 0xfffffff007b1e768,
     0x80110bd5017d8520, 0xfffffff0087dc520),
    ("agx-command-queue-allocate", 0xfffffff007b17738,
     0x804116010180cb50, 0xfffffff008810b50),
    ("agx-block-fence-factory", 0xfffffff007b1e690,
     0x8011419a017e0280, 0xfffffff0087e4280),
    ("agx-block-fence-allocate", 0xfffffff007b16e48,
     0x80411601017f230c, 0xfffffff0087f630c),
    ("agx-block-fence-prepare", 0xfffffff007b16db0,
     0x80115c71017f1ca8, 0xfffffff0087f5ca8),
)
AGX_QUEUE_CREATION_ENTRIES = (
    ("agx-command-queue-initialize", 0xfffffff007b17628,
     0x8011fcfc018001e8, 0xfffffff0088041e8),
    ("agx-device-queue-setup", 0xfffffff007b1edf0,
     0x8011f5a50180d7a0, 0xfffffff0088117a0),
    ("agx-command-queue-resource-setup", 0xfffffff007b176b0,
     0x80415880017fb07c, 0xfffffff0087ff07c),
)
IOGPU_REGISTRY_ARRAY_VTABLE = 0xfffffff007e41030
IOGPU_REGISTRY_INSERT_ENTRY = (
    ("registry-array-insert", 0xfffffff007e410a8,
     0x8041c8dd02f13ed4, 0xfffffff009f17ed4),
)
BACKING_FACTORY_METACLASS_POINTER = 0xfffffff00aa9eb98
BACKING_FACTORY_CLASS_NAME = "IOBufferMemoryDescriptor"
BACKING_FACTORY_CLASS_NAME_ADDRESS = 0xfffffff0070a53e1
IOBUFFER_BACKING_OPTIONS = 0x10060
IOBUFFER_TASK_MAP_OPTIONS = ((IOBUFFER_BACKING_OPTIONS & 0x1fffff00) & 0xf0000fff) | 1
BACKING_FACTORY_VIRTUAL_ENTRIES = (
    ("iobuffer-metaclass-allocate", 0xfffffff007ab3750,
     0x80211601016d06b0, 0xfffffff0086d46b0),
    ("iobuffer-object-initialize", 0xfffffff007aecd20,
     0x80111c03016cfbf4, 0xfffffff0086d3bf4),
)
IOBUFFER_KERNEL_MAP_ENTRY = (
    ("iobuffer-map-kernel", 0xfffffff007aecce0,
     0x80113ed6016dcabc, 0xfffffff0086e0abc),
)
IOGPU_TABLE_FACTORY_ENTRIES = (
    ("client-table-factory", 0xfffffff007e46950,
     0x8011c85602f429b0, 0xfffffff009f469b0),
    ("table-init-wrapper", 0xfffffff007e45038,
     0x80110a2102f33820, 0xfffffff009f37820),
    ("table-init-base", 0xfffffff007e45030,
     0x8011b89802f3384c, 0xfffffff009f3784c),
)
AGX_TABLE_FACTORY_ENTRIES = (
    ("agx-client-table-factory-a", 0xfffffff007b1d858,
     0x8011c85602f429b0, 0xfffffff009f469b0),
    ("agx-client-table-factory-b", 0xfffffff007b1e658,
     0x8011c85602f429b0, 0xfffffff009f469b0),
    ("agx-table-init-override", 0xfffffff007b21cd8,
     0x80110a210187b15c, 0xfffffff00887f15c),
    ("agx-table-init-base", 0xfffffff007b21cd0,
     0x8011b89802f3384c, 0xfffffff009f3784c),
)
IOGPU_SHARED_BUFFER_FACTORY_ENTRY = (
    ("shared-buffer-base", 0xfffffff007e45058,
     0x801100d802f347d4, 0xfffffff009f387d4),
)
AGX_SHARED_BUFFER_FACTORY_ENTRY = (
    ("shared-buffer-agx-override", 0xfffffff007b21cf8,
     0x801100d80187a5bc, 0xfffffff00887e5bc),
)
AGX_BASE_TABLE_FALLBACK = (
    0xfffffff007b15ce0, 0x10000000e40fa0,
    0xfffffff007e44fa0, 0xb8, 0xfffffff007e45058,
)
KERNEL_BUFFER_ADDRESS_ENTRY = (
    ("buffer-base-virtual-candidate", 0xfffffff007ab4898,
     0x801134f6016dc5dc, 0xfffffff0086e05dc),
)
CONSTRUCTOR_ENTRY = (0xfffffff007aed448, 0x8041511b0175aa20, 0xfffffff00875ea20)
CALLBACK_ENTRIES = (
    ("uat", 0xfffffff007a7d7f0, 0x400000000532dd,
     0xfffffff007a7d820, 0x8010325e01132508, 0xfffffff008136508),
    ("t8110dart", 0xfffffff007a7d840, 0x40000000053704,
     0xfffffff007a7d870, 0x8010325e011340c0, 0xfffffff0081380c0),
    ("ans2_sart", 0xfffffff007a7d890, 0x400000000544b9,
     0xfffffff007a7d8c0, 0x8010325e01136d60, 0xfffffff00813ad60),
    ("nvme", 0xfffffff007a7d8e0, 0x400000000545b4,
     0xfffffff007a7d910, 0x8010325e011372f4, 0xfffffff00813b2f4),
)

# The two branches use the same GPU-derived mode byte and have the same
# IOUAT-vs-AGXUAT polarity. Include the segment producer and its callback.
ANCHORS = (
    (IOGPU_NAME, "external.enabled", 0xfffffff009f1d408, "tbz", "w9, #0, #0xfffffff009f1d488"),
    (IOGPU_NAME, "external.bound", 0xfffffff009f1d40c, "cmp", "w1, #0x37"),
    (IOGPU_NAME, "external.stride", 0xfffffff009f1d424, "umull", "x9, w1, w9"),
    (IOGPU_NAME, "external.mode-set-table", 0xfffffff009f1d42c, "add", "x10, x10, #0x470"),
    (IOGPU_NAME, "external.mode-clear-table", 0xfffffff009f1d448, "add", "x10, x10, #0xf30"),
    (IOGPU_NAME, "external.table-choice", 0xfffffff009f1d464, "csel", "x3, x11, x12, ne"),
    (IOGPU_NAME, "external.forward", 0xfffffff009f1d484, "braa", "x16, x17"),
    (IOGPU_NAME, "submit.four-scalars", 0xfffffff009f1adbc, "cmp", "w8, #4"),
    (IOGPU_NAME, "submit.queue-lookup", 0xfffffff009f1ae40, "bl", "#0xfffffff009f38aa8"),
    (IOGPU_NAME, "submit.queue-missing", 0xfffffff009f1ae44, "cbz", "x0, #0xfffffff009f1aef8"),
    (IOGPU_NAME, "submit.queue-field-compare", 0xfffffff009f1ae54, "cmp", "x24, x8"),
    (IOGPU_NAME, "submit.queue-mismatch", 0xfffffff009f1ae58, "b.ne", "#0xfffffff009f1af44"),
    (IOGPU_NAME, "submit.batch-entry", 0xfffffff009f1ae74, "bl", "#0xfffffff009f49254"),
    (IOGPU_NAME, "batch.state-active", 0xfffffff009f492a0, "strb", "w8, [x19, #0x52f]"),
    (IOGPU_NAME, "batch.queue-lock", 0xfffffff009f492b0, "bl", "#0xfffffff007fe12ac"),
    (IOGPU_NAME, "batch.process-entry", 0xfffffff009f49398, "bl", "#0xfffffff009f4956c"),
    (IOGPU_NAME, "batch.backend-setup", 0xfffffff009f4960c, "blraa", "x8, x17"),
    (IOGPU_NAME, "batch.parser-dispatch", 0xfffffff009f49680, "blraa", "x9, x17"),
    (AGX_NAME, "queue.factory-class", 0xfffffff0087dc528, "add", "x0, x0, #0x980"),
    (AGX_NAME, "queue.class-name", 0xfffffff008810d9c, "add", "x1, x1, #0xf02"),
    (AGX_NAME, "queue.vtable-base", 0xfffffff008810b88, "add", "x16, x16, #0x540"),
    (AGX_NAME, "queue.vtable-adjust", 0xfffffff008810b8c, "add", "x16, x16, #0x10"),
    (AGX_NAME, "queue.vtable-store", 0xfffffff008810b9c, "str", "x16, [x0]"),
    (AGX_NAME, "fence.factory-class", 0xfffffff0087e4288, "add", "x0, x0, #0x6d0"),
    (AGX_NAME, "fence.class-name", 0xfffffff0087f643c, "add", "x1, x1, #0x75c"),
    (AGX_NAME, "fence.vtable-base", 0xfffffff0087f6344, "add", "x16, x16, #0xd10"),
    (AGX_NAME, "fence.vtable-adjust", 0xfffffff0087f6348, "add", "x16, x16, #0x10"),
    (AGX_NAME, "fence.vtable-store", 0xfffffff0087f6358, "str", "x16, [x0]"),
    (AGX_NAME, "fence.pool-lock", 0xfffffff0087f5cfc, "bl", "#0xfffffff007fe12ac"),
    (AGX_NAME, "fence.pool-bitmap-write", 0xfffffff0087f5d34, "str", "x10, [x9]"),
    (IOGPU_NAME, "external.queue-object-table", 0xfffffff009f1a6a4, "ldr", "x2, [x19, #0x120]"),
    (IOGPU_NAME, "queue.base-input-size", 0xfffffff009f43ad4, "mov", "w8, #0x408"),
    (AGX_NAME, "queue.agx-input-size", 0xfffffff0087e734c, "mov", "w8, #0x410"),
    (AGX_NAME, "queue.agx-input-size-store", 0xfffffff0087e7350, "str", "w8, [x19, #0x278]"),
    (IOGPU_NAME, "external.queue-input-size", 0xfffffff009f1a618, "ldr", "w8, [x20, #0x38]"),
    (IOGPU_NAME, "external.queue-device-size", 0xfffffff009f1a61c, "ldr", "w9, [x0, #0x278]"),
    (IOGPU_NAME, "external.queue-minimum-size", 0xfffffff009f1a620, "cmp", "w8, #0x408"),
    (IOGPU_NAME, "external.queue-exact-size", 0xfffffff009f1a624, "ccmp", "w8, w9, #0, hs"),
    (IOGPU_NAME, "external.queue-size-accepted", 0xfffffff009f1a628, "b.eq", "#0xfffffff009f1a66c"),
    (IOGPU_NAME, "external.queue-size-reject", 0xfffffff009f1a664, "add", "w19, w8, #5"),
    (IOGPU_NAME, "external.queue-init", 0xfffffff009f1a6cc, "blraa", "x8, x17"),
    (IOGPU_NAME, "external.queue-register", 0xfffffff009f1a6e0, "bl", "#0xfffffff009f17f08"),
    (IOGPU_NAME, "external.queue-return", 0xfffffff009f1a710, "stp", "x8, x9, [x22]"),
    (AGX_NAME, "queue.init-device-call", 0xfffffff00880426c, "blraa", "x9, x17"),
    (AGX_NAME, "queue.init-base-call", 0xfffffff008804298, "blraa", "x8, x17"),
    (AGX_NAME, "queue.init-resource-array", 0xfffffff008804308, "bl", "#0xfffffff00866a21c"),
    (AGX_NAME, "queue.init-resource-call-zero", 0xfffffff00880459c, "mov", "w1, #0"),
    (AGX_NAME, "queue.init-resource-call", 0xfffffff0088045a8, "blraa", "x8, x17"),
    (AGX_NAME, "queue.agx-options-low", 0xfffffff0088045cc, "ldr", "w8, [x20, #0x408]"),
    (AGX_NAME, "queue.agx-options-all", 0xfffffff0088045fc, "ldr", "x8, [x20, #0x408]"),
    (AGX_NAME, "queue.resource-allocate", 0xfffffff0087ff120, "blraa", "x8, x17"),
    (AGX_NAME, "queue.resource-setup", 0xfffffff0087ff15c, "bl", "#0xfffffff00885a230"),
    (AGX_NAME, "queue.resource-store", 0xfffffff0087ff194, "str", "x20, [x19, #0x8e0]"),
    (AGX_NAME, "queue.resource-finalize", 0xfffffff0087ff384, "bl", "#0xfffffff0087ff4dc"),
    (AGX_NAME, "queue.resource-ready", 0xfffffff0087ff390, "strb", "w0, [x19, #0x5e8]"),
    (IOGPU_NAME, "external.shared-input", 0xfffffff009f1ab30, "ldr", "w8, [x8, #8]"),
    (IOGPU_NAME, "external.shared-output-address", 0xfffffff009f1ab3c, "add", "x4, x3, #8"),
    (IOGPU_NAME, "external.shared-output-id", 0xfffffff009f1ab40, "add", "x5, x3, #0xc"),
    (IOGPU_NAME, "external.shared-size", 0xfffffff009f1ab2c, "ldr", "w1, [x8]"),
    (IOGPU_NAME, "shared.client-table", 0xfffffff009f1ab38, "ldr", "x0, [x0, #0x120]"),
    (IOGPU_NAME, "shared.creator-call", 0xfffffff009f1ab48, "b", "#0xfffffff009f3866c"),
    (IOGPU_NAME, "shared.size-bound", 0xfffffff009f38698, "cmp", "w1, w8"),
    (IOGPU_NAME, "shared.factory-context", 0xfffffff009f386c4, "ldr", "x8, [x0, #0x50]"),
    (IOGPU_NAME, "shared.factory-call", 0xfffffff009f386f0, "blraa", "x9, x17"),
    (IOGPU_NAME, "shared.base-map-options", 0xfffffff009f387dc, "mov", "w3, #1"),
    (IOGPU_NAME, "shared.base-vtable-base", 0xfffffff009f24ef0, "add", "x16, x16, #0x38"),
    (IOGPU_NAME, "shared.base-vtable-adjust", 0xfffffff009f24ef4, "add", "x16, x16, #0x10"),
    (IOGPU_NAME, "shared.base-vtable-store", 0xfffffff009f24f04, "str", "x16, [x0]"),
    (IOGPU_NAME, "shared.registration-array", 0xfffffff009f386fc, "ldr", "x0, [x23, #0x78]"),
    (IOGPU_NAME, "shared.registration-object", 0xfffffff009f38700, "mov", "x1, x20"),
    (IOGPU_NAME, "shared.register-object", 0xfffffff009f38704, "bl", "#0xfffffff009f17f08"),
    (IOGPU_NAME, "shared.output-id", 0xfffffff009f38708, "str", "w0, [x21]"),
    (IOGPU_NAME, "shared.output-address-call", 0xfffffff009f38714, "bl", "#0xfffffff009f251c0"),
    (IOGPU_NAME, "shared.output-address", 0xfffffff009f38718, "str", "x0, [x22]"),
    (IOGPU_NAME, "shared.user-map", 0xfffffff009f251c4, "ldr", "x0, [x0, #0x48]"),
    (IOGPU_NAME, "shared.user-address-call", 0xfffffff009f251ec, "braa", "x16, x17"),
    (IOGPU_NAME, "shared.backing-create", 0xfffffff009f24fb8, "bl", "#0xfffffff0086d515c"),
    (IOGPU_NAME, "shared.read-only-test", 0xfffffff009f24f98, "tst", "w4, #0x1000"),
    (IOGPU_NAME, "shared.backing-task-choice", 0xfffffff009f24f9c, "csel", "x0, x2, xzr, eq"),
    (IOGPU_NAME, "shared.backing-options-low", 0xfffffff009f24fa0, "mov", "w1, #0x60"),
    (IOGPU_NAME, "shared.backing-options-high", 0xfffffff009f24fa4, "movk", "w1, #1, lsl #16"),
    (IOGPU_NAME, "shared.backing-capacity", 0xfffffff009f24fa8, "mov", "x2, x3"),
    (IOGPU_NAME, "shared.backing-alignment", 0xfffffff009f24fac, "mov", "w3, #1"),
    (IOGPU_NAME, "shared.backing-user-tag", 0xfffffff009f24fb4, "mov", "w5, #0x64"),
    (KERNEL_NAME, "shared.backing-kernel-tag-store", 0xfffffff0086d51bc, "strh", "w24, [x0, #0x30]"),
    (KERNEL_NAME, "shared.metaclass-global-page", 0xfffffff0086d4bc0, "adrp", "x19, #0xfffffff00aa9e000"),
    (KERNEL_NAME, "shared.metaclass-global-address", 0xfffffff0086d4bc4, "add", "x19, x19, #0xb98"),
    (KERNEL_NAME, "shared.metaclass-name-page", 0xfffffff0086d4bc8, "adrp", "x1, #0xfffffff0070a5000"),
    (KERNEL_NAME, "shared.metaclass-name-address", 0xfffffff0086d4bcc, "add", "x1, x1, #0x3e1"),
    (KERNEL_NAME, "shared.metaclass-object", 0xfffffff0086d4bd8, "mov", "x0, x19"),
    (KERNEL_NAME, "shared.metaclass-size", 0xfffffff0086d4bdc, "mov", "w3, #0xe8"),
    (KERNEL_NAME, "shared.metaclass-register", 0xfffffff0086d4be0, "bl", "#0xfffffff0085f7d6c"),
    (KERNEL_NAME, "shared.metaclass-vtable-page", 0xfffffff0086d4c14, "adrp", "x16, #0xfffffff007ab3000"),
    (KERNEL_NAME, "shared.metaclass-vtable-base", 0xfffffff0086d4c18, "add", "x16, x16, #0x6d8"),
    (KERNEL_NAME, "shared.metaclass-vtable-adjust", 0xfffffff0086d4c1c, "add", "x16, x16, #0x10"),
    (KERNEL_NAME, "shared.metaclass-vtable-store", 0xfffffff0086d4c2c, "str", "x16, [x19]"),
    (KERNEL_NAME, "shared.object-vtable-page", 0xfffffff0086d4718, "adrp", "x16, #0xfffffff007aec000"),
    (KERNEL_NAME, "shared.object-vtable-base", 0xfffffff0086d471c, "add", "x16, x16, #0xbe8"),
    (KERNEL_NAME, "shared.object-vtable-adjust", 0xfffffff0086d4720, "add", "x16, x16, #0x10"),
    (KERNEL_NAME, "shared.object-vtable-store", 0xfffffff0086d4730, "str", "x16, [x0]"),
    (KERNEL_NAME, "shared.factory-metaclass-page", 0xfffffff0086d518c, "adrp", "x0, #0xfffffff00aa9e000"),
    (KERNEL_NAME, "shared.factory-metaclass-address", 0xfffffff0086d5190, "add", "x0, x0, #0xb98"),
    (KERNEL_NAME, "shared.factory-metaclass-load", 0xfffffff0086d5194, "ldr", "x16, [x0]"),
    (KERNEL_NAME, "shared.factory-allocate-slot", 0xfffffff0086d51a4, "ldr", "x8, [x16, #0x68]!"),
    (KERNEL_NAME, "shared.factory-init-offset", 0xfffffff0086d51d4, "mov", "x17, #0x128"),
    (KERNEL_NAME, "shared.factory-init-address", 0xfffffff0086d51d8, "add", "x16, x16, x17"),
    (KERNEL_NAME, "shared.factory-init-slot", 0xfffffff0086d51dc, "ldr", "x8, [x16]"),
    (KERNEL_NAME, "shared.init-capacity-required", 0xfffffff0086d3c18, "cbz", "x3, #0xfffffff0086d40f0"),
    (KERNEL_NAME, "shared.init-task-argument", 0xfffffff0086d3c20, "mov", "x20, x1"),
    (KERNEL_NAME, "shared.init-task-selection", 0xfffffff0086d408c, "csel", "x4, x8, x20, eq"),
    (KERNEL_NAME, "shared.init-range-count", 0xfffffff0086d4094, "mov", "w2, #1"),
    (KERNEL_NAME, "shared.init-descriptor-call", 0xfffffff0086d40a4, "bl", "#0xfffffff0086e6be8"),
    (KERNEL_NAME, "shared.init-map-guard", 0xfffffff0086d4114, "cbz", "x21, #0xfffffff0086d4248"),
    (KERNEL_NAME, "shared.task-map-mask-a", 0xfffffff0086d4148, "and", "w8, w26, #0x1fffff00"),
    (KERNEL_NAME, "shared.task-map-mask-b", 0xfffffff0086d414c, "and", "w8, w8, #0xf0000fff"),
    (KERNEL_NAME, "shared.task-map-options", 0xfffffff0086d4150, "orr", "w3, w8, #1"),
    (KERNEL_NAME, "shared.task-map-task", 0xfffffff0086d4158, "mov", "x1, x21"),
    (KERNEL_NAME, "shared.task-map-create", 0xfffffff0086d4168, "bl", "#0xfffffff0086dfc84"),
    (KERNEL_NAME, "shared.task-map-store", 0xfffffff0086d4170, "str", "x0, [x8]"),
    (KERNEL_NAME, "shared.task-map-null", 0xfffffff0086d417c, "cbz", "x8, #0xfffffff0086d4284"),
    (KERNEL_NAME, "shared.task-map-get-address", 0xfffffff0086d422c, "blraa", "x9, x17"),
    (KERNEL_NAME, "shared.task-map-buffer-address", 0xfffffff0086d4230, "str", "x0, [x19, #0xb8]"),
    (KERNEL_NAME, "shared.map-object-task", 0xfffffff0086dfd94, "str", "x16, [x0, #0x40]"),
    (KERNEL_NAME, "shared.map-object-dispatch-slot", 0xfffffff0086dfdc8, "ldr", "x9, [x16, #0x100]"),
    (KERNEL_NAME, "shared.map-object-dispatch", 0xfffffff0086dfdf0, "blraa", "x9, x17"),
    (KERNEL_NAME, "shared.backing-user-tag-store", 0xfffffff0086d51c0, "strh", "w23, [x0, #0x32]"),
    (KERNEL_NAME, "shared.backing-task-forward", 0xfffffff0086d51e8, "mov", "x1, x22"),
    (KERNEL_NAME, "shared.backing-options-forward", 0xfffffff0086d51ec, "mov", "x2, x21"),
    (KERNEL_NAME, "shared.backing-capacity-forward", 0xfffffff0086d51f0, "mov", "x3, x20"),
    (KERNEL_NAME, "shared.backing-init-call", 0xfffffff0086d5204, "blraa", "x8, x17"),
    (IOGPU_NAME, "shared.backing-store", 0xfffffff009f24fbc, "str", "x0, [x19, #0x40]"),
    (IOGPU_NAME, "shared.backing-reload", 0xfffffff009f24fd4, "ldr", "x23, [x19, #0x40]"),
    (IOGPU_NAME, "shared.derived-object-call", 0xfffffff009f25030, "blraa", "x8, x17"),
    (IOGPU_NAME, "shared.backing-alias-store", 0xfffffff009f25034, "str", "x23, [x19, #0x28]"),
    (IOGPU_NAME, "shared.user-map-backing", 0xfffffff009f25038, "ldr", "x0, [x19, #0x40]"),
    (IOGPU_NAME, "shared.user-map-task", 0xfffffff009f2503c, "mov", "x1, x21"),
    (IOGPU_NAME, "shared.user-map-options", 0xfffffff009f25044, "mov", "x3, x20"),
    (IOGPU_NAME, "shared.user-map-create", 0xfffffff009f25050, "bl", "#0xfffffff0086dfc84"),
    (IOGPU_NAME, "shared.user-map-store", 0xfffffff009f25054, "str", "x0, [x19, #0x48]"),
    (KERNEL_NAME, "shared.mapping-task-argument", 0xfffffff0086dfcb0, "mov", "x19, x1"),
    (KERNEL_NAME, "shared.mapping-task-map", 0xfffffff0086dfd80, "ldr", "x16, [x19, #0x28]"),
    (IOGPU_NAME, "shared.kernel-map-source", 0xfffffff009f24ab0, "ldr", "x0, [x0, #0x28]"),
    (IOGPU_NAME, "shared.kernel-map-null-guard", 0xfffffff009f24a90, "cbz", "x8, #0xfffffff009f24a9c"),
    (IOGPU_NAME, "shared.kernel-map-dispatch-slot", 0xfffffff009f24ac4, "ldr", "x8, [x16, #0xe8]!"),
    (IOGPU_NAME, "shared.kernel-map-options", 0xfffffff009f24acc, "mov", "w1, #0"),
    (IOGPU_NAME, "shared.kernel-map-call", 0xfffffff009f24ad8, "blraa", "x8, x17"),
    (IOGPU_NAME, "shared.kernel-map-store", 0xfffffff009f24adc, "str", "x0, [x19, #0x30]"),
    (IOGPU_NAME, "shared.kernel-map-lazy-call", 0xfffffff009f249e4, "bl", "#0xfffffff009f24a88"),
    (KERNEL_NAME, "shared.kernel-map-task-load", 0xfffffff0086e0adc, "ldr", "x21, [x8, #0x4e0]"),
    (KERNEL_NAME, "shared.kernel-map-option-anywhere", 0xfffffff0086e0b08, "orr", "w3, w19, #1"),
    (KERNEL_NAME, "shared.kernel-map-task-forward", 0xfffffff0086e0b10, "mov", "x1, x21"),
    (KERNEL_NAME, "shared.kernel-map-create", 0xfffffff0086e0b2c, "b", "#0xfffffff0086dfc84"),
    (IOGPU_NAME, "external.notification-input", 0xfffffff009f1ab70, "ldr", "w8, [x8, #8]"),
    (IOGPU_NAME, "external.notification-output", 0xfffffff009f1ab74, "ldr", "x3, [x2, #0x58]"),
    (IOGPU_NAME, "external.set-notification-first", 0xfffffff009f1ac48, "ldr", "w1, [x8]"),
    (IOGPU_NAME, "external.set-notification-second", 0xfffffff009f1ac4c, "ldr", "w22, [x8, #8]"),
    (IOGPU_NAME, "external.submit-object-table", 0xfffffff009f1ae3c, "ldr", "x0, [x22, #0x120]"),
    (IOGPU_NAME, "external.submit-lookup", 0xfffffff009f1ae40, "bl", "#0xfffffff009f38aa8"),
    (IOGPU_NAME, "external.submit-packet", 0xfffffff009f1ae74, "bl", "#0xfffffff009f49254"),
    (IOGPU_NAME, "selector.bound", 0xfffffff009f1d4b4, "cmp", "w2, #0xd"),
    (IOGPU_NAME, "selector.stride", 0xfffffff009f1d4c8, "umull", "x9, w2, w9"),
    (IOGPU_NAME, "selector.mode-set-table", 0xfffffff009f1d4d0, "add", "x10, x10, #0xb00"),
    (IOGPU_NAME, "selector.mode-clear-table", 0xfffffff009f1d4ec, "add", "x10, x10, #0x9b0"),
    (IOGPU_NAME, "selector.table-choice", 0xfffffff009f1d508, "csel", "x0, x11, x12, ne"),
    (IOGPU_NAME, "selector.copy-limit", 0xfffffff009f1c6b8, "cmp", "x2, #0x40"),
    (IOGPU_NAME, "selector.copy-call", 0xfffffff009f1c6e8, "bl", "#0xfffffff00811c320"),
    (IOGPU_NAME, "selector.copy-result", 0xfffffff009f1c6ec, "cbnz", "w0, #0xfffffff009f1c75c"),
    (IOGPU_NAME, "selector.object-lookup", 0xfffffff009f1c6f8, "bl", "#0xfffffff009f38aa8"),
    (IOGPU_NAME, "selector.object-table", 0xfffffff009f1c6f0, "ldr", "x0, [x23, #0x120]"),
    (IOGPU_NAME, "selector.packet-call", 0xfffffff009f1c718, "bl", "#0xfffffff009f49254"),
    (IOGPU_NAME, "selector.result-copy", 0xfffffff009f1c730, "bl", "#0xfffffff00811cdd8"),
    (IOGPU_NAME, "packet.submit-call", 0xfffffff009f49398, "bl", "#0xfffffff009f4956c"),
    (IOGPU_NAME, "client.initial-context", 0xfffffff009f19cdc, "mov", "x21, x3"),
    (IOGPU_NAME, "client.device-context-store", 0xfffffff009f19d34, "str", "x20, [x8]"),
    (IOGPU_NAME, "client.table-context-store", 0xfffffff009f19d38, "str", "x21, [x19, #0x128]"),
    (IOGPU_NAME, "client.device-context-load", 0xfffffff009f1d024, "ldr", "x1, [x8]"),
    (IOGPU_NAME, "client.table-context-source", 0xfffffff009f1d028, "ldr", "x2, [x19, #0x128]"),
    (IOGPU_NAME, "client.table-factory-call", 0xfffffff009f1d054, "blraa", "x8, x17"),
    (IOGPU_NAME, "client.table-store", 0xfffffff009f1d058, "str", "x0, [x19, #0x120]"),
    (IOGPU_NAME, "table.factory-allocate", 0xfffffff009f469f8, "blraa", "x8, x17"),
    (IOGPU_NAME, "table.factory-init", 0xfffffff009f46a34, "blraa", "x8, x17"),
    (IOGPU_NAME, "table.init-context-store", 0xfffffff009f37898, "str", "x20, [x19, #0x50]"),
    (IOGPU_NAME, "table.init-array-create", 0xfffffff009f379b8, "bl", "#0xfffffff009f17d5c"),
    (IOGPU_NAME, "table.init-array-store", 0xfffffff009f379bc, "str", "x0, [x19, #0x78]"),
    (IOGPU_NAME, "table.array-vtable-adjust", 0xfffffff009f17d30, "add", "x16, x16, #0x10"),
    (IOGPU_NAME, "table.array-vtable-store", 0xfffffff009f17d40, "str", "x16, [x0]"),
    (IOGPU_NAME, "table.insert-argument", 0xfffffff009f17670, "mov", "x2, x20"),
    (IOGPU_NAME, "table.insert-dispatch", 0xfffffff009f1767c, "blraa", "x8, x17"),
    (IOGPU_NAME, "table.insert-slot-store", 0xfffffff009f17edc, "str", "x2, [x1]"),
    (IOGPU_NAME, "table.lookup-id-guard", 0xfffffff009f17f20, "cbz", "w1, #0xfffffff009f17f7c"),
    (IOGPU_NAME, "table.lookup-slot-load", 0xfffffff009f17f4c, "ldr", "x0, [x10]"),
    (IOGPU_NAME, "table.lookup-retain", 0xfffffff009f17f5c, "ldadd", "w9, w8, [x8]"),
    (AGX_NAME, "shared.agx-mode-compare", 0xfffffff00887e5c0, "cmp", "w3, #2"),
    (AGX_NAME, "shared.agx-mode-branch", 0xfffffff00887e5c4, "b.ne", "#0xfffffff00887e674"),
    (AGX_NAME, "shared.agx-read-only-options", 0xfffffff00887e624, "mov", "w4, #0x1001"),
    (AGX_NAME, "shared.agx-fallback", 0xfffffff00887e698, "braa", "x16, x17"),
    (AGX_NAME, "table.agx-base-init", 0xfffffff00887f1e8, "blraa", "x8, x17"),
    (IOGPU_NAME, "packet.process-discriminator", 0xfffffff009f4967c, "movk", "x17, #0x9dcc, lsl #48"),
    (IOGPU_NAME, "packet.process-call", 0xfffffff009f49680, "blraa", "x9, x17"),
    (IOGPU_NAME, "client.init-object-table", 0xfffffff009f1a6a4, "ldr", "x2, [x19, #0x120]"),
    (IOGPU_NAME, "client.init-object-call", 0xfffffff009f1a6cc, "blraa", "x8, x17"),
    (IOGPU_NAME, "packet.object-table-store", 0xfffffff009f48be4, "str", "x21, [x19, #0x490]"),
    (IOGPU_NAME, "packet.copied-handle", 0xfffffff009f49354, "ldr", "w1, [x23, #0x20]"),
    (IOGPU_NAME, "packet.buffer-table", 0xfffffff009f4bec8, "ldr", "x0, [x0, #0x490]"),
    (IOGPU_NAME, "packet.buffer-id", 0xfffffff009f4becc, "ldr", "w1, [x1]"),
    (IOGPU_NAME, "packet.buffer-lookup", 0xfffffff009f4bed0, "bl", "#0xfffffff009f38834"),
    (IOGPU_NAME, "packet.first-buffer-id", 0xfffffff009f4becc, "ldr", "w1, [x1]"),
    (IOGPU_NAME, "packet.optional-buffer-id", 0xfffffff009f4bed8, "ldr", "w1, [x20, #8]"),
    (IOGPU_NAME, "packet.third-buffer-id", 0xfffffff009f4bef8, "ldr", "w1, [x20, #4]"),
    (IOGPU_NAME, "table.buffer-array", 0xfffffff009f38838, "ldr", "x0, [x0, #0x78]"),
    (IOGPU_NAME, "table.client-array", 0xfffffff009f38aac, "ldr", "x0, [x0, #0x88]"),
    (IOGPU_NAME, "table.reject-zero", 0xfffffff009f17f20, "cbz", "w1, #0xfffffff009f17f7c"),
    (IOGPU_NAME, "table.check-limit", 0xfffffff009f17f28, "cmp", "w8, w1"),
    (IOGPU_NAME, "table.load-object", 0xfffffff009f17f4c, "ldr", "x0, [x10]"),
    (IOGPU_NAME, "table.retain-object", 0xfffffff009f17f5c, "ldadd", "w9, w8, [x8]"),
    (IOGPU_NAME, "packet.buffer-map-call", 0xfffffff009f4bff8, "blraa", "x8, x17"),
    (IOGPU_NAME, "packet.buffer-getter-slot", 0xfffffff009f4bfe4, "ldr", "x8, [x16, #0x80]!"),
    (IOGPU_NAME, "packet.buffer-getter-pac", 0xfffffff009f4bff4, "movk", "x17, #0x8807, lsl #48"),
    (IOGPU_NAME, "packet.buffer-object", 0xfffffff009f4bed4, "mov", "x28, x0"),
    (IOGPU_NAME, "packet.buffer-address", 0xfffffff009f4bffc, "mov", "x25, x0"),
    (IOGPU_NAME, "buffer.base-candidate", 0xfffffff009f25144, "bl", "#0xfffffff009f24914"),
    (IOGPU_NAME, "buffer.slice-offset", 0xfffffff009f25148, "ldr", "x8, [x19, #0x50]"),
    (IOGPU_NAME, "buffer.slice-address", 0xfffffff009f2514c, "add", "x0, x8, x0"),
    (IOGPU_NAME, "buffer.base-object", 0xfffffff009f24934, "ldr", "x8, [x19, #0x30]"),
    (IOGPU_NAME, "buffer.base-virtual", 0xfffffff009f24988, "ldr", "x9, [x16, #0x78]"),
    (IOGPU_NAME, "buffer.base-call", 0xfffffff009f24994, "blraa", "x9, x17"),
    (IOGPU_NAME, "packet.record-offset", 0xfffffff009f4c230, "ldp", "w8, w9, [x19, #-4]"),
    (IOGPU_NAME, "packet.offset-check", 0xfffffff009f4c23c, "b.hi", "#0xfffffff009f4c270"),
    (IOGPU_NAME, "packet.record-begin", 0xfffffff009f4c258, "add", "x1, x25, x8"),
    (IOGPU_NAME, "packet.record-end", 0xfffffff009f4c25c, "add", "x2, x25, x9"),
    (IOGPU_NAME, "packet.framing-call", 0xfffffff009f4c26c, "blraa", "x10, x17"),
    (IOGPU_NAME, "frame.minimum", 0xfffffff009f4bda0, "add", "x8, x1, #8"),
    (IOGPU_NAME, "frame.length", 0xfffffff009f4bdac, "ldr", "w8, [x1, #4]"),
    (IOGPU_NAME, "frame.end-overflow", 0xfffffff009f4bdb4, "b.hs", "#0xfffffff009f4be44"),
    (IOGPU_NAME, "frame.length-minimum", 0xfffffff009f4bdbc, "cmp", "w8, #8"),
    (IOGPU_NAME, "frame.length-alignment", 0xfffffff009f4bdb8, "and", "x9, x8, #3"),
    (IOGPU_NAME, "frame.dispatch", 0xfffffff009f4bdf4, "blraa", "x8, x17"),
    (IOGPU_NAME, "command.id", 0xfffffff009f4a69c, "ldr", "w23, [x1]"),
    (IOGPU_NAME, "command.payload-length", 0xfffffff009f4a6a4, "sub", "x21, x2, x8"),
    (IOGPU_NAME, "command.16-minimum", 0xfffffff009f4a7d0, "cmp", "x21, #0xb"),
    (IOGPU_NAME, "command.16-count", 0xfffffff009f4abe8, "ldr", "w23, [x20, #0x10]"),
    (IOGPU_NAME, "command.16-record-size", 0xfffffff009f4abf0, "orr", "x9, x9, x23, lsl #4"),
    (IOGPU_NAME, "command.16-length-check", 0xfffffff009f4abf8, "b.hs", "#0xfffffff009f4aecc"),
    (IOGPU_NAME, "command.16-records", 0xfffffff009f4b770, "add", "x2, x20, #0x14"),
    (IOGPU_NAME, "command.16-dispatch", 0xfffffff009f4b784, "bl", "#0xfffffff009f2a6a4"),
    (IOGPU_NAME, "record.input", 0xfffffff009f2a6cc, "str", "x2, [sp, #0x20]"),
    (IOGPU_NAME, "record.provider-class", 0xfffffff009f2a7dc, "ldr", "x1, [x8]"),
    (IOGPU_NAME, "record.array-provider", 0xfffffff009f2a7fc, "ldr", "x8, [x16, #0xe8]!"),
    (IOGPU_NAME, "record.array-call", 0xfffffff009f2a814, "blraa", "x8, x17"),
    (IOGPU_NAME, "record.array-result", 0xfffffff009f2a81c, "mov", "x25, x0"),
    (IOGPU_NAME, "record.stride", 0xfffffff009f2a8b8, "lsl", "x9, x28, #4"),
    (IOGPU_NAME, "record.index-and-count", 0xfffffff009f2a8d4, "ldp", "w27, w26, [x8, #8]"),
    (IOGPU_NAME, "record.end-overflow", 0xfffffff009f2a8dc, "b.hs", "#0xfffffff009f2a9ec"),
    (IOGPU_NAME, "record.start-index", 0xfffffff009f2a8e4, "ldr", "w21, [x8, #4]"),
    (IOGPU_NAME, "record.index-overflow", 0xfffffff009f2a8ec, "b.hs", "#0xfffffff009f2a9ec"),
    (IOGPU_NAME, "record.flags", 0xfffffff009f2a8f0, "ldrb", "w20, [x8]"),
    (IOGPU_NAME, "record.null-object", 0xfffffff009f2a928, "mov", "x2, #0"),
    (IOGPU_NAME, "record.array-object", 0xfffffff009f2a94c, "ldr", "x2, [x10]"),
    (IOGPU_NAME, "record.resource-call", 0xfffffff009f2a984, "blraa", "x8, x17"),
    (IOGPU_NAME, "provider.granule-4k", 0xfffffff009f55020, "cmp", "w1, #4, lsl #12"),
    (IOGPU_NAME, "provider.granule-64k", 0xfffffff009f55028, "cmp", "w21, #0x40, lsl #12"),
    (IOGPU_NAME, "provider.granule-16k", 0xfffffff009f55030, "cmp", "w21, #0x10, lsl #12"),
    (IOGPU_NAME, "provider.parent-length", 0xfffffff009f5504c, "ldr", "x8, [x19, #0x30]"),
    (IOGPU_NAME, "provider.length-alignment", 0xfffffff009f55054, "tst", "x8, x9"),
    (IOGPU_NAME, "provider.parent-object", 0xfffffff009f55170, "ldr", "x0, [x19, #0x88]"),
    (IOGPU_NAME, "provider.slice-offset", 0xfffffff009f55174, "mov", "x1, x25"),
    (IOGPU_NAME, "provider.slice-granule", 0xfffffff009f55178, "mov", "x2, x24"),
    (IOGPU_NAME, "provider.slice-build", 0xfffffff009f55180, "bl", "#0xfffffff009f19600"),
    (IOGPU_NAME, "provider.array-store", 0xfffffff009f55188, "str", "x0, [x8]"),
    (IOGPU_NAME, "provider.array-publish", 0xfffffff009f55294, "str", "x21, [x27, x26, lsl #3]"),
    (IOGPU_NAME, "resource.batch-array", 0xfffffff009f15024, "ldr", "x8, [x19, #0x90]"),
    (IOGPU_NAME, "resource.batch-object", 0xfffffff009f1502c, "ldr", "x2, [x8]"),
    (IOGPU_NAME, "resource.input-object", 0xfffffff009f14a90, "mov", "x22, x2"),
    (IOGPU_NAME, "resource.null-branch", 0xfffffff009f14ad4, "cbz", "x22, #0xfffffff009f14b34"),
    (IOGPU_NAME, "resource.check-slot", 0xfffffff009f14e84, "ldr", "x9, [x16, #0xd8]!"),
    (IOGPU_NAME, "resource.check-call", 0xfffffff009f14e9c, "blraa", "x9, x17"),
    (IOGPU_NAME, "resource.check-result", 0xfffffff009f14ea4, "cbnz", "w0, #0xfffffff009f14f08"),
    (IOGPU_NAME, "resource.object-forward", 0xfffffff009f14ecc, "mov", "x3, x22"),
    (IOGPU_NAME, "resource.forward-call", 0xfffffff009f14ed8, "blraa", "x8, x17"),
    (IOGPU_NAME, "forward.descriptor-input", 0xfffffff009f16e34, "mov", "x21, x3"),
    (IOGPU_NAME, "forward.descriptor-forward", 0xfffffff009f16e7c, "mov", "x3, x21"),
    (IOGPU_NAME, "forward.wrapper-call", 0xfffffff009f16e80, "bl", "#0xfffffff009f52274"),
    (IOGPU_NAME, "wrapper.descriptor-input", 0xfffffff009f52294, "mov", "x20, x3"),
    (IOGPU_NAME, "wrapper.map-slot", 0xfffffff009f52344, "ldr", "x8, [x16, #0xe8]!"),
    (IOGPU_NAME, "wrapper.descriptor-forward", 0xfffffff009f52358, "mov", "x3, x20"),
    (IOGPU_NAME, "wrapper.map-call", 0xfffffff009f52364, "blraa", "x8, x17"),
    (AGX_NAME, "upstream.descriptor-input", 0xfffffff0088792c8, "mov", "x20, x3"),
    (AGX_NAME, "upstream.map-slot", 0xfffffff008879468, "ldr", "x9, [x16, #0xd0]"),
    (AGX_NAME, "upstream.descriptor-forward", 0xfffffff008879470, "mov", "x1, x20"),
    (AGX_NAME, "upstream.map-call", 0xfffffff008879488, "blraa", "x9, x17"),
    (AGX_NAME, "mode.instance", 0xfffffff008857f00, "mov", "x19, x0"),
    (AGX_NAME, "mode.source-base-offset", 0xfffffff008857f04, "mov", "w8, #0xdab8"),
    (AGX_NAME, "mode.source-base", 0xfffffff008857f08, "add", "x24, x0, x8"),
    (AGX_NAME, "mode.source", 0xfffffff008857f1c, "ldrb", "w8, [x24, #0x28]"),
    (AGX_NAME, "mode.global-base", 0xfffffff008857f20, "adrp", "x9, #0xfffffff00ab61000"),
    (AGX_NAME, "mode.mask", 0xfffffff008857f24, "ands", "w8, w8, #1"),
    (AGX_NAME, "mode.store", 0xfffffff008857f28, "strb", "w8, [x9, #0x150]"),
    (AGX_NAME, "mode.initialized-base", 0xfffffff008857f40, "adrp", "x8, #0xfffffff00ab61000"),
    (AGX_NAME, "mode.initialized-value", 0xfffffff008857f44, "mov", "w22, #1"),
    (AGX_NAME, "mode.initialized-store", 0xfffffff008857f48, "strb", "w22, [x8, #0x160]"),
    (AGX_NAME, "gart.constructor-vtable-base", 0xfffffff00885273c, "add", "x16, x16, #0x4c8"),
    (AGX_NAME, "gart.constructor-vtable-adjust", 0xfffffff008852740, "add", "x16, x16, #0x10"),
    (AGX_NAME, "gart.constructor-vtable-store", 0xfffffff008852750, "str", "x16, [x0]"),
    (AGX_NAME, "gart.wrapper-argument", 0xfffffff00887c580, "mov", "x3, x2"),
    (AGX_NAME, "gart.wrapper-branch", 0xfffffff00887c59c, "b", "#0xfffffff00887c5a0"),
    (AGX_NAME, "gart.setup-self", 0xfffffff00887c5cc, "mov", "x19, x0"),
    (AGX_NAME, "gart.setup-other", 0xfffffff00887c5c8, "mov", "x21, x1"),
    (AGX_NAME, "gart.factory-slot", 0xfffffff0087e7324, "ldr", "x9, [x16, #0x6f8]"),
    (AGX_NAME, "gart.factory-self", 0xfffffff0087e7328, "mov", "x0, x19"),
    (AGX_NAME, "gart.factory-call", 0xfffffff0087e7338, "blraa", "x9, x17"),
    (AGX_NAME, "gart.factory-nonnull", 0xfffffff0087e733c, "cbz", "x0, #0xfffffff0087e6f5c"),
    (AGX_NAME, "gart.service-self", 0xfffffff0087e5c0c, "mov", "x19, x0"),
    (AGX_NAME, "gart.service-field-base", 0xfffffff0087e5c20, "mov", "w8, #0xeb20"),
    (AGX_NAME, "gart.service-field-add", 0xfffffff0087e5c24, "add", "x25, x0, x8"),
    (AGX_NAME, "gart.service-field-store", 0xfffffff0087e7340, "str", "x0, [x25, #0x360]"),
    (AGX_NAME, "gart.allocate-slot", 0xfffffff0087dbe44, "mov", "x17, #0x850"),
    (AGX_NAME, "gart.allocate-call", 0xfffffff0087dbe5c, "blraa", "x8, x17"),
    (AGX_NAME, "gart.setup-slot", 0xfffffff0087dbe74, "ldr", "x8, [x16, #0xb0]!"),
    (AGX_NAME, "gart.setup-call", 0xfffffff0087dbe94, "blraa", "x8, x17"),
    (AGX_NAME, "uat-mux.constructor-vtable-page", 0xfffffff00888c7bc, "adrp", "x16, #0xfffffff007b22000"),
    (AGX_NAME, "uat-mux.constructor-vtable-base", 0xfffffff00888c7c0, "add", "x16, x16, #0xad0"),
    (AGX_NAME, "uat-mux.constructor-vtable-adjust", 0xfffffff00888c7c4, "add", "x16, x16, #0x10"),
    (AGX_NAME, "uat-mux.constructor-vtable-pac", 0xfffffff00888c7d0, "pacda", "x16, x17"),
    (AGX_NAME, "uat-mux.constructor-vtable-store", 0xfffffff00888c7d4, "str", "x16, [x0]"),
    (KERNEL_NAME, "iouat-factory-vtable-page", 0xfffffff00875f35c, "adrp", "x16, #0xfffffff007aed000"),
    (KERNEL_NAME, "iouat-factory-vtable-base", 0xfffffff00875f360, "add", "x16, x16, #0x390"),
    (KERNEL_NAME, "iouat-factory-vtable-adjust", 0xfffffff00875f364, "add", "x16, x16, #0x10"),
    (KERNEL_NAME, "iouat-factory-vtable-pac", 0xfffffff00875f370, "pacda", "x16, x17"),
    (KERNEL_NAME, "iouat-factory-vtable-store", 0xfffffff00875f374, "str", "x16, [x0]"),
    (KERNEL_NAME, "iouat-factory-init-call", 0xfffffff00875f3c4, "blraa", "x8, x17"),
    (AGX_NAME, "map.options-input", 0xfffffff00887a8c8, "mov", "x21, x2"),
    (AGX_NAME, "map.global-base", 0xfffffff00887acb8, "adrp", "x8, #0xfffffff00ab61000"),
    (AGX_NAME, "map.mode-load", 0xfffffff00887acbc, "ldrb", "w8, [x8, #0x150]"),
    (AGX_NAME, "map.mode-branch", 0xfffffff00887acc0, "tbz", "w8, #0, #0xfffffff00887ae54"),
    (AGX_NAME, "map.iouat", 0xfffffff00887acd4, "bl", "#0xfffffff008761094"),
    (AGX_NAME, "map.agxuat", 0xfffffff00887ae64, "bl", "#0xfffffff00889472c"),
    (AGX_NAME, "map2.mode-branch", 0xfffffff00887c3dc, "tbz", "w9, #0, #0xfffffff00887c3fc"),
    (AGX_NAME, "map2.descriptor-input", 0xfffffff00887c0dc, "mov", "x21, x1"),
    (AGX_NAME, "map2.descriptor-forward", 0xfffffff00887c3e4, "mov", "x1, x21"),
    (AGX_NAME, "map2.iouat", 0xfffffff00887c3f4, "bl", "#0xfffffff008761094"),
    (AGX_NAME, "map2.agxuat", 0xfffffff00887c410, "bl", "#0xfffffff00889472c"),
    (AGX_NAME, "map2.state-object", 0xfffffff00887c3d0, "ldr", "x8, [x22, #0x2e8]"),
    (AGX_NAME, "map2.iouat-object", 0xfffffff00887c3e0, "ldr", "x0, [x8, #0x10]"),
    (AGX_NAME, "setup.mode-branch", 0xfffffff00887c950, "tbz", "w8, #0, #0xfffffff00887c98c"),
    (AGX_NAME, "setup.iouat-factory", 0xfffffff00887c95c, "bl", "#0xfffffff00875f2c8"),
    (AGX_NAME, "setup.iouat-store", 0xfffffff00887c960, "str", "x0, [x22, #0x10]"),
    (AGX_NAME, "setup.state-store", 0xfffffff00887c9f4, "str", "x20, [x19, #0x2e8]"),
    (AGX_NAME, "agxuat.options", 0xfffffff008894918, "ldr", "w3, [sp, #0x4c]"),
    (KERNEL_NAME, "factory.mode-gate", 0xfffffff00875f2e8, "cmp", "w9, #1"),
    (KERNEL_NAME, "factory.vtable-base", 0xfffffff00875f360, "add", "x16, x16, #0x390"),
    (KERNEL_NAME, "factory.init-slot", 0xfffffff00875f3a4, "ldr", "x8, [x16, #0xa8]!"),
    (KERNEL_NAME, "factory.null-provider", 0xfffffff00875f3b8, "mov", "x3, #0"),
    (KERNEL_NAME, "factory.init-call", 0xfffffff00875f3c4, "blraa", "x8, x17"),
    (KERNEL_NAME, "iouat.provider-input", 0xfffffff00875ea40, "mov", "x20, x3"),
    (KERNEL_NAME, "iouat.provider-field", 0xfffffff00875edd0, "add", "x4, x19, #0x20"),
    (KERNEL_NAME, "iouat.default-branch", 0xfffffff00875edd4, "cbz", "x20, #0xfffffff00875ee58"),
    (KERNEL_NAME, "iouat.explicit-provider", 0xfffffff00875edd8, "str", "x20, [x4]"),
    (KERNEL_NAME, "iouat.default-uat-header", 0xfffffff00875ee5c, "add", "x0, x0, #0x7f0"),
    (KERNEL_NAME, "iouat.default-create", 0xfffffff00875ee70, "bl", "#0xfffffff00811520c"),
    (KERNEL_NAME, "provider.table-store", 0xfffffff008115264, "str", "x21, [x8]"),
    (KERNEL_NAME, "provider.field-store", 0xfffffff008115270, "str", "x8, [x19]"),
    (KERNEL_NAME, "iouat.align-length", 0xfffffff008761120, "tst", "x21, #0x3fff"),
    (KERNEL_NAME, "iouat.align-address", 0xfffffff008761128, "tst", "x19, #0x3fff"),
    (KERNEL_NAME, "iouat.allocate", 0xfffffff008761244, "bl", "#0xfffffff007fdb8c8"),
    (KERNEL_NAME, "iouat.segment-address", 0xfffffff00876131c, "stp", "x11, x12, [x25]"),
    (KERNEL_NAME, "iouat.segment-length", 0xfffffff008761330, "str", "x10, [x25, #0x10]"),
    (KERNEL_NAME, "iouat.segment-stride", 0xfffffff00876133c, "add", "x25, x25, #0x28"),
    (KERNEL_NAME, "iouat.map-object", 0xfffffff0087613b4, "ldr", "x0, [x20, #0x20]"),
    (KERNEL_NAME, "iouat.map-options", 0xfffffff0087613c4, "mov", "x3, x22"),
    (KERNEL_NAME, "iouat.map-callback", 0xfffffff0087613cc, "bl", "#0xfffffff0081152ec"),
    (KERNEL_NAME, "callback.virtual-slot", 0xfffffff008115354, "ldr", "x9, [x9, #0x30]"),
    (KERNEL_NAME, "callback.pac-dispatch", 0xfffffff008115364, "blraa", "x9, x17"),
    (KERNEL_NAME, "uat.protected-call", 0xfffffff008136820, "bl", "#0xfffffff0087b3474"),
    (KERNEL_NAME, "uat.table-id", 0xfffffff0087b347c, "movk", "x16, #7, lsl #32"),
    (KERNEL_NAME, "uat.entry-id", 0xfffffff0087b3484, "movk", "x16, #4"),
    (KERNEL_NAME, "usercopy.range-start", 0xfffffff00811c390, "ldr", "x10, [x8, #0x20]"),
    (KERNEL_NAME, "usercopy.range-end", 0xfffffff00811c3a4, "ldr", "x8, [x8, #0x28]"),
    (KERNEL_NAME, "usercopy.pan-off", 0xfffffff00811c448, "msr", "pan, #0"),
    (KERNEL_NAME, "usercopy.copy", 0xfffffff00811c454, "bl", "#0xfffffff007f8cdf0"),
    (KERNEL_NAME, "usercopy.pan-on", 0xfffffff00811c458, "msr", "pan, #1"),
    (KERNEL_NAME, "buffer.virtual-address-field", 0xfffffff0086e05e0, "ldr", "x0, [x0, #0x28]"),
)


def validate_anchors(observed: dict[int, tuple[str, str]]) -> list[dict]:
    evidence = []
    for image, label, address, mnemonic, operands in ANCHORS:
        actual = observed.get(address)
        if actual != (mnemonic, operands):
            raise ValueError(
                f"{label} at {address:#x}: expected {mnemonic} {operands}, got {actual}"
            )
        evidence.append({
            "image": image,
            "label": label,
            "address": f"{address:#x}",
            "instruction": f"{mnemonic} {operands}",
        })
    return evidence


def validate_iogpu_command_16(read_i32) -> dict:
    slot = IOGPU_COMMAND_TABLE + (16 - 2) * 4
    displacement = read_i32(slot)
    target = None if displacement is None else IOGPU_COMMAND_BASE + displacement
    if target != IOGPU_COMMAND_16:
        raise ValueError(
            f"IOGPU command 16 at {slot:#x}: expected {IOGPU_COMMAND_16:#x}, got {target}"
        )
    return {"command": 16, "slot": f"{slot:#x}", "handler": f"{target:#x}"}


def validate_indirect_entries(read_u64, expected=INDIRECT_ENTRIES) -> list[dict]:
    entries = []
    for label, address, expected_encoding, target in expected:
        encoded = read_u64(address)
        decoded = None if encoded is None else KERNEL_STATIC_BASE + (encoded & 0xffffffff)
        if encoded != expected_encoding or decoded != target:
            raise ValueError(
                f"{label} at {address:#x}: expected {expected_encoding:#x} -> "
                f"{target:#x}, got {encoded} -> {decoded}"
            )
        entries.append({
            "label": label,
            "address": f"{address:#x}",
            "encoded": f"{encoded:#x}",
            "decoded_static_target": f"{target:#x}",
        })
    return entries


def validate_mode_references(mode_refs, initialized_refs) -> dict:
    mode_writes = [ref.address for ref in mode_refs if ref.kind.startswith("str")]
    initialized_writes = [ref.address for ref in initialized_refs
                          if ref.kind.startswith("str")]
    if mode_writes != [0xfffffff008857f28]:
        raise ValueError(f"AGX mode global write sites changed: {mode_writes}")
    if initialized_writes != [0xfffffff008857f48]:
        raise ValueError(f"AGX mode initialized write sites changed: {initialized_writes}")
    mode_reads = {ref.address for ref in mode_refs if ref.kind.startswith("ldr")}
    initialized_reads = {ref.address for ref in initialized_refs
                         if ref.kind.startswith("ldr")}
    if not {0xfffffff00887acbc, 0xfffffff00887c94c}.issubset(mode_reads) or \
       0xfffffff00887b818 not in initialized_reads:
        raise ValueError("AGX mode or initialized consumer changed")
    return {"mode_global": f"{AGX_MODE_GLOBAL:#x}",
            "mode_write": f"{mode_writes[0]:#x}",
            "mode_reference_count": len(mode_refs),
            "initialized_global": f"{AGX_MODE_INITIALIZED_GLOBAL:#x}",
            "initialized_write": f"{initialized_writes[0]:#x}",
            "initialized_reference_count": len(initialized_refs)}


def validate_agx_gart_class_tag(read_u64, read_cstring) -> dict:
    encoded = read_u64(AGX_GART_CLASS_TAG_SLOT)
    target = None if encoded is None else KERNEL_STATIC_BASE + (encoded & 0xffffffff)
    label = None if target is None else read_cstring(target)
    if encoded != AGX_GART_CLASS_TAG_ENCODING or label != AGX_GART_CLASS_TAG:
        raise ValueError(f"AGX GART class tag changed: {encoded}, {label}")
    return {"slot": f"{AGX_GART_CLASS_TAG_SLOT:#x}",
            "tag": label, "vtable": f"{AGX_GART_VTABLE:#x}"}


def validate_agx_uat_mux_class_tag(read_u64, read_cstring) -> dict:
    encoded = read_u64(AGX_UAT_MUX_CLASS_TAG_SLOT)
    target = None if encoded is None else KERNEL_STATIC_BASE + (encoded & 0xffffffff)
    label = None if target is None else read_cstring(target)
    if encoded != AGX_UAT_MUX_CLASS_TAG_ENCODING or label != AGX_UAT_MUX_CLASS_TAG:
        raise ValueError(f"AGX UAT mux class tag changed: {encoded}, {label}")
    return {"slot": f"{AGX_UAT_MUX_CLASS_TAG_SLOT:#x}",
            "tag": label, "vtable": f"{AGX_UAT_MUX_VTABLE:#x}"}


def validate_agx_base_table_fallback(read_agx_u64, read_iogpu_u64) -> dict:
    address, expected, table, displacement, slot = AGX_BASE_TABLE_FALLBACK
    encoded = read_agx_u64(address)
    decoded = None if encoded is None else KERNEL_STATIC_BASE + (encoded & 0xffffffff)
    if encoded != expected or decoded != table or table + displacement != slot:
        raise ValueError("AGX shared-buffer base-table fallback mismatch")
    method = IOGPU_SHARED_BUFFER_FACTORY_ENTRY[0]
    if read_iogpu_u64(slot) != method[2]:
        raise ValueError("AGX shared-buffer base-table method mismatch")
    return {
        "pointer_address": f"{address:#x}",
        "encoded_pointer": f"{encoded:#x}",
        "decoded_static_table": f"{table:#x}",
        "slot": f"{slot:#x}",
        "decoded_static_target": f"{method[3]:#x}",
    }


def validate_iogpu_base_buffer_getter(read_u64) -> dict:
    slot = IOGPU_BASE_BUFFER_VTABLE + IOGPU_PACKET_GETTER_OFFSET
    expected = IOGPU_BUFFER_ADDRESS_ENTRIES[1]
    if slot != expected[1] or read_u64(slot) != expected[2]:
        raise ValueError("IOGPU base-buffer packet getter mismatch")
    return {
        "vtable": f"{IOGPU_BASE_BUFFER_VTABLE:#x}",
        "slot": f"{slot:#x}",
        "decoded_static_target": f"{expected[3]:#x}",
    }


def validate_agx_preparser_classes(read_cstring) -> dict[str, str]:
    for name, address in AGX_PREPARSER_CLASSES:
        if read_cstring(address) != name:
            raise ValueError(f"AGX pre-parser class mismatch: {name} at {address:#x}")
    return {name: f"{address:#x}" for name, address in AGX_PREPARSER_CLASSES}


def validate_backing_factory_runtime_pointer(sections) -> dict:
    address = BACKING_FACTORY_METACLASS_POINTER
    matches = [section for section in sections
               if int(section.virtual_address) <= address
               < int(section.virtual_address) + int(section.size)]
    if len(matches) != 1 or matches[0].name != "__common" or len(matches[0].content) != 0:
        raise ValueError("backing factory metaclass is not in zero-fill __common")
    return {
        "address": f"{address:#x}",
        "section": "__common",
        "file_backed_bytes": 0,
        "runtime_value_unobserved": True,
    }


def validate_backing_factory_class_name(read_cstring) -> dict:
    name = read_cstring(BACKING_FACTORY_CLASS_NAME_ADDRESS)
    if name != BACKING_FACTORY_CLASS_NAME:
        raise ValueError(f"backing factory class name mismatch: {name!r}")
    return {
        "class_name": name,
        "name_address": f"{BACKING_FACTORY_CLASS_NAME_ADDRESS:#x}",
        "metaclass_global": f"{BACKING_FACTORY_METACLASS_POINTER:#x}",
        "class_registration_static": True,
        "runtime_allocation_unobserved": True,
    }


def validate_external_methods(read_u64) -> list[dict]:
    entries = []
    for mode, base in IOGPU_EXTERNAL_METHOD_TABLES:
        for index, label, encoding, input_contract, output_contract, target in IOGPU_EXTERNAL_METHOD_ENTRIES:
            slot = base + 0x18 * index
            actual = tuple(read_u64(slot + offset) for offset in (0, 8, 16))
            expected = (encoding, input_contract, output_contract)
            decoded = None if actual[0] is None else KERNEL_STATIC_BASE + (actual[0] & 0xffffffff)
            if actual != expected or decoded != target:
                raise ValueError(f"external {mode} index {index} {label} mismatch at {slot:#x}")
            entries.append({
                "mode": mode,
                "index": index,
                "label": label,
                "slot": f"{slot:#x}",
                "encoded": f"{encoding:#x}",
                "input_contract": f"{input_contract:#x}",
                "output_contract": f"{output_contract:#x}",
                "decoded_static_target": f"{target:#x}",
            })
    return entries


def validate_titan_selector_contract(header: str) -> list[dict]:
    definitions = {
        name: int(value)
        for name, value in re.findall(
            r"^#define\s+(IOGPU_SELECTOR_[A-Z_]+)\s+\((\d+)\)",
            header,
            re.MULTILINE,
        )
    }
    evidence = []
    for name, historical, compatible in TITAN_SELECTOR_CONTRACT:
        actual = definitions.get(name)
        if actual != historical or actual - compatible != 1:
            raise ValueError(f"Titan selector contract mismatch for {name}: {actual}")
        evidence.append({
            "name": name,
            "source_index": actual,
            "compatible_23A355_index": compatible,
            "difference": actual - compatible,
        })
    return evidence


def validate_constructor_entry(read_u64) -> dict:
    address, expected_encoding, target = CONSTRUCTOR_ENTRY
    encoded = read_u64(address)
    decoded = None if encoded is None else KERNEL_STATIC_BASE + (encoded & 0xffffffff)
    if encoded != expected_encoding or decoded != target:
        raise ValueError(f"IOUAT constructor entry mismatch at {address:#x}")
    return {
        "address": f"{address:#x}",
        "encoded": f"{encoded:#x}",
        "decoded_static_target": f"{target:#x}",
    }


def validate_callback_entries(read_u64, read_cstring) -> list[dict]:
    entries = []
    for name, header_address, header_expected, slot_address, encoding, target in CALLBACK_ENTRIES:
        header = read_u64(header_address)
        encoded = read_u64(slot_address)
        decoded = None if encoded is None else KERNEL_STATIC_BASE + (encoded & 0xffffffff)
        name_address = KERNEL_STATIC_BASE + (header_expected & 0xffffffff)
        actual_name = read_cstring(name_address)
        if header != header_expected or encoded != encoding or decoded != target or actual_name != name:
            raise ValueError(f"{name} callback table mismatch at {header_address:#x}")
        entries.append({
            "name": name,
            "header_address": f"{header_address:#x}",
            "slot_address": f"{slot_address:#x}",
            "encoded": f"{encoding:#x}",
            "decoded_static_target": f"{target:#x}",
        })
    return entries


def summarize_devicetree(path: pathlib.Path) -> dict:
    blob = path.read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != DEVICETREE_SHA256:
        raise ValueError(f"DeviceTree SHA-256 mismatch: {digest}")
    root, end = parse_node(blob)
    if any(blob[end:]):
        raise ValueError("nonzero DeviceTree trailing data")
    nodes = dict(walk(root))
    targets = {
        "/device-tree/chosen": ("gpu-iouat",),
        "/device-tree/arm-io/sgx": ("gpu", "gpu_iouat"),
    }
    missing = set(targets) - set(nodes)
    if missing:
        raise ValueError(f"missing DeviceTree nodes: {sorted(missing)}")
    return {
        "sha256": digest,
        "static_properties": {
            node_path: {
                name: name in nodes[node_path].properties
                for name in names
            }
            for node_path, names in targets.items()
        },
        "runtime_properties_unobserved": True,
    }


def audit(path: pathlib.Path, devicetree: pathlib.Path | None = None) -> dict:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != IMAGE_SHA256:
        raise ValueError(f"kernelcache SHA-256 mismatch: {digest}")

    agx = MachOImage(path, AGX_NAME)
    iogpu = MachOImage(path, IOGPU_NAME)
    kernel = next(entry for entry in agx.container.filesets if entry.fileset_name == KERNEL_NAME)
    kernel_text = next(section for section in kernel.sections if section.name == "__text")
    kernel_content = bytes(kernel_text.content)
    def kernel_bytes(address: int, size: int) -> bytes | None:
        for section in kernel.sections:
            offset = address - int(section.virtual_address)
            if 0 <= offset and offset + size <= int(section.size):
                return bytes(section.content)[offset:offset + size]
        return None

    def kernel_u64(address: int) -> int | None:
        content = kernel_bytes(address, 8)
        return None if content is None else int.from_bytes(content, "little")

    def kernel_cstring(address: int) -> str | None:
        content = kernel_bytes(address, 64)
        return None if content is None else content.split(b"\0", 1)[0].decode("ascii")

    def iogpu_i32(address: int) -> int | None:
        content = iogpu.mapped_bytes(address, 4)
        return None if content is None else int.from_bytes(content, "little", signed=True)

    disassembler = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    observed = {}
    for image, _, address, _, _ in ANCHORS:
        if image == AGX_NAME:
            instruction = agx.instruction_at(address)
        elif image == IOGPU_NAME:
            instruction = iogpu.instruction_at(address)
        else:
            offset = address - int(kernel_text.virtual_address)
            instruction = next(disassembler.disasm(kernel_content[offset:offset + 4], address), None)
        observed[address] = None if instruction is None else (
            instruction.mnemonic, instruction.op_str
        )

    result = {
        "build": "23A355",
        "kernelcache_sha256": digest,
        "status": "static-control-flow-only",
        "evidence": validate_anchors(observed),
        "agx_mode_init_vtable": validate_indirect_entries(
            agx.read_u64, AGX_MODE_INIT_VTABLE_ENTRY
        ),
        "agx_gart_setup_vtable": validate_indirect_entries(
            agx.read_u64, AGX_GART_SETUP_ENTRY
        ),
        "agx_gart_factory_vtable": validate_indirect_entries(
            agx.read_u64, AGX_GART_FACTORY_ENTRIES
        ),
        "agx_gart_service_field": f"{AGX_GART_SERVICE_FIELD:#x}",
        "agx_gart_class_tag": validate_agx_gart_class_tag(
            agx.read_u64, agx.read_cstring
        ),
        "agx_uat_mux_class_tag": validate_agx_uat_mux_class_tag(
            agx.read_u64, agx.read_cstring
        ),
        "iouat_factory_vtable": f"{IOUAT_FACTORY_VTABLE:#x}",
        "agx_mode_references": validate_mode_references(
            agx.references_to(AGX_MODE_GLOBAL),
            agx.references_to(AGX_MODE_INITIALIZED_GLOBAL)
        ),
        "iogpu_command_16": validate_iogpu_command_16(iogpu_i32),
        "iogpu_array_provider_candidate": validate_indirect_entries(
            iogpu.read_u64, IOGPU_ARRAY_PROVIDER_ENTRY
        ),
        "iogpu_selector_0_entries": validate_indirect_entries(
            iogpu.read_u64, IOGPU_SELECTOR_0_ENTRIES
        ),
        "iogpu_external_methods": validate_external_methods(iogpu.read_u64),
        "historical_titan_selector_contract": validate_titan_selector_contract(
            (pathlib.Path(__file__).resolve().parents[2] /
             "Application/Dopamine/Exploits/Titan/exploit/IOGPUDevice.h").read_text()
        ),
        "iogpu_buffer_address_candidates": validate_indirect_entries(
            iogpu.read_u64, IOGPU_BUFFER_ADDRESS_ENTRIES
        ),
        "iogpu_table_factory_candidates": validate_indirect_entries(
            iogpu.read_u64, IOGPU_TABLE_FACTORY_ENTRIES
        ),
        "agx_table_factory_candidates": validate_indirect_entries(
            agx.read_u64, AGX_TABLE_FACTORY_ENTRIES
        ),
        "iogpu_shared_buffer_factory_candidate": validate_indirect_entries(
            iogpu.read_u64, IOGPU_SHARED_BUFFER_FACTORY_ENTRY
        ),
        "agx_shared_buffer_factory_candidate": validate_indirect_entries(
            agx.read_u64, AGX_SHARED_BUFFER_FACTORY_ENTRY
        ),
        "agx_shared_buffer_base_fallback": validate_agx_base_table_fallback(
            agx.read_u64, iogpu.read_u64
        ),
        "iogpu_base_buffer_packet_getter": validate_iogpu_base_buffer_getter(
            iogpu.read_u64
        ),
        "agx_preparser_classes": validate_agx_preparser_classes(agx.read_cstring),
        "agx_preparser_factory_entries": validate_indirect_entries(
            agx.read_u64, AGX_PREPARSER_FACTORY_ENTRIES
        ),
        "agx_queue_creation_entries": validate_indirect_entries(
            agx.read_u64, AGX_QUEUE_CREATION_ENTRIES
        ),
        "iogpu_registry_array_insert_entry": validate_indirect_entries(
            iogpu.read_u64, IOGPU_REGISTRY_INSERT_ENTRY
        ),
        "backing_factory_runtime_pointer": validate_backing_factory_runtime_pointer(
            kernel.sections
        ),
        "backing_factory_class": validate_backing_factory_class_name(kernel_cstring),
        "backing_factory_virtual_entries": validate_indirect_entries(
            kernel_u64, BACKING_FACTORY_VIRTUAL_ENTRIES
        ),
        "iobuffer_kernel_map_entry": validate_indirect_entries(
            kernel_u64, IOBUFFER_KERNEL_MAP_ENTRY
        ),
        "backing_task_mapping_static": {
            "backing_options": f"{IOBUFFER_BACKING_OPTIONS:#x}",
            "task_map_options": f"{IOBUFFER_TASK_MAP_OPTIONS:#x}",
            "read_only_bit_requested": bool(IOBUFFER_TASK_MAP_OPTIONS & 0x1000),
            "backing_bit_0x10000_cleared": bool(
                IOBUFFER_BACKING_OPTIONS & 0x10000
                and not IOBUFFER_TASK_MAP_OPTIONS & 0x10000
            ),
            "runtime_permissions_unobserved": True,
        },
        "kernel_buffer_address_candidate": validate_indirect_entries(
            kernel_u64, KERNEL_BUFFER_ADDRESS_ENTRY
        ),
        "dual_mapping_static": {
            "shared_descriptor_offsets": ["0x28", "0x40"],
            "user_map_offset": "0x48",
            "lazy_kernel_map_offset": "0x30",
            "kernel_map_method": "0xfffffff0086e0abc",
            "map_helper": "0xfffffff0086dfc84",
            "same_descriptor_statically": True,
            "runtime_byte_alias_unobserved": True,
            "runtime_write_permission_unobserved": True,
        },
        "registry_round_trip_static": {
            "registry_array_offset": "0x78",
            "array_vtable": f"{IOGPU_REGISTRY_ARRAY_VTABLE:#x}",
            "insert_target": "0xfffffff009f17ed4",
            "lookup_target": "0xfffffff009f17f10",
            "stored_and_loaded_pointer_compatible": True,
            "runtime_id_lifetime_unobserved": True,
            "runtime_parser_selection_unobserved": True,
        },
        "submission_boundary_static": {
            "queue_lookup": "0xfffffff009f1ae40",
            "missing_queue_exits_before_batch": True,
            "batch_entry": "0xfffffff009f1ae74",
            "queue_state_write_before_parser": "0xfffffff009f492a0",
            "backend_setup_before_parser": "0xfffffff009f4960c",
            "conditional_agx_preparser_object": "AGXBlockFence",
            "fence_pool_bitmap_write": "0xfffffff0087f5d34",
            "parser_dispatch": "0xfffffff009f49680",
            "buffer_id_lookup": "0xfffffff009f4bed0",
            "buffer_getter_call": "0xfffffff009f4bff8",
            "runtime_packet_consumption_unobserved": True,
            "selector25_parser_only_device_test_bounded": False,
        },
        "queue_creation_boundary_static": {
            "selector": 6,
            "queue_initializer": "0xfffffff0088041e8",
            "device_setup_virtual": "0xfffffff0088117a0",
            "resource_setup_virtual": "0xfffffff0087ff07c",
            "resource_call_argument": 0,
            "resource_allocation_before_return": True,
            "resource_ready_store": "0xfffffff0087ff390",
            "registry_insert": "0xfffffff009f1a6e0",
            "output_pair_store": "0xfffffff009f1a710",
            "runtime_queue_identity_unobserved": True,
            "queue_creation_is_read_only": False,
            "device_effects_fully_bounded": False,
        },
        "indirect_entries": validate_indirect_entries(agx.read_u64),
        "iogpu_indirect_entries": validate_indirect_entries(iogpu.read_u64, IOGPU_INDIRECT_ENTRIES),
        "constructor_indirect_entry": validate_constructor_entry(kernel_u64),
        "callback_candidates": validate_callback_entries(kernel_u64, kernel_cstring),
        "inference": [
            "The mode byte is populated from AGX state at object+0xdae0, bit 0.",
            "Mode bit set selects IOUAT; mode bit clear selects the AGXUAT map routine.",
            "Mode bit set also makes AGX call the IOUAT factory, store its result at state+0x10, and later pass that field to IOUAT map.",
            "The state+0x2e8 store is on the setup method's x0, whose AGXGartG14-class vtable reaches the setup wrapper. The validated AGXAcceleratorG14P registry-service vtable is different; the service object cannot be substituted for this GART object without a separate live pointer chain.",
            "The G14P service's +0x6f8 virtual factory allocates and sets up a GART object, and the service startup path stores the non-null return at service+0xee80. This is an exact-image pointer-chain candidate, not a live pointer or GART-vtable observation.",
            "The AGX-reachable factory passes a null provider in x3 to the authenticated IOUAT initializer.",
            "The second AGX map method forwards its incoming descriptor object in x1 to IOUAT map.",
            "An IOGPUFamily wrapper forwards its incoming x3 object to an AGX authenticated method compatible with a further map dispatch.",
            "An upstream IOGPUFamily resource routine receives an optional object in x2, checks the non-null object through a virtual method, then forwards it toward that wrapper.",
            "An upstream packet parser bounds offsets into a driver buffer, and a framing method checks an 8-byte minimum, 4-byte alignment, end overflow, and buffer limit before dispatching the command.",
            "The externalMethod dispatcher uses 0x18-stride tables with a 0x37 index bound and a client-state gate. In both tables index 6 targets s_new_command_queue and index 25 targets s_submit_command_buffers, which calls packet submission. Indices 12, 14, and 24 have argument layouts compatible with the historical shared-memory, notification-queue, and set-notification calls, respectively, but those names are inferred from contracts. All five historical Titan header values are one greater than the compatible exact-image indices. The older getTargetAndMethodForIndex-style tables also route index 0 to a packet method, but their runtime use is unobserved.",
            "The client table at +0x120 is assigned from an authenticated device +0x588 factory, with a client-initializer context stored at +0x128 forwarded to that factory. Compatible factory targets allocate a table and initialize its +0x78 registry. The packet object initializer receives this table and stores it at +0x490. External-method index 12 forwards the table to a shared-memory creator, which registers the returned object in table+0x78 and returns its ID plus an address from a mapping object at buffer+0x48. The buffer initializer creates a backing object at +0x40, stores that same pointer at +0x28, and constructs the +0x48 mapping against the client context. The mapping routine treats that context as a task pointer and reads task+0x28. The packet processor uses input IDs to resolve registered objects from table+0x78; the lookup rejects zero/out-of-range indices and retains a loaded object. Two PAC-compatible +0x80 getters can supply a kernel address, one through a separate buffer+0x30 mapping made from the same backing object. Runtime factory selection and effective byte alias are unobserved.",
            "The compatible IOGPU table +0xa8 buffer factory forces mapping options 1. The compatible AGX override branches on the second caller scalar: value 2 forces options 0x1001, otherwise its base-table +0xb8 dispatch resolves to the same IOGPU factory that forces 1. The buffer initializer forwards those fixed options to its mapping call. XNU 12377 defines 0x1000 as kIOMapReadOnly, so the AGX special branch requests a read-only mapping and the base branch omits that flag. The base factory installs a vtable whose +0x80 slot matches the authenticated packet-buffer address getter. These are static compatibility and option-level findings, not proof of resulting task permissions or a write reaching the kernel parser.",
            "The buffer backing call has the register/tag shape of XNU 12377 IOBufferMemoryDescriptor::inTaskWithOptions(task, options, capacity, alignment, kernTag, userTag). The initializer chooses the client task when mapping bit 0x1000 is clear and NULL when set, while fixing backing options at 0x10060, capacity at the first caller scalar, alignment at 1, kernel tag 0, and user tag 0x64. XNU names those option bits kIOMemoryKernelUserShared, kIOMemoryPageable, and kIOMemoryPurgeable. The exact runtime allocation and resulting bytes are unobserved.",
            "The exact-image kernel registers IOBufferMemoryDescriptor at the same zero-fill __common metaclass global loaded by the backing factory. Its metaclass allocation slot resolves to the constructor that installs an object vtable; that vtable's +0x128 initializer resolves to a kernel routine that selects non-null inTask. After descriptor setup, fixed backing options 0x10060 are masked into task-map option 1. The returned mapping object is retained, and its +0x78 address getter populates the descriptor buffer address. The task-map option lacks the known read-only bit 0x1000. These are static edges, not evidence of allocation success, effective write permission, or parser byte aliasing on the device.",
            "The exact-image IOBufferMemoryDescriptor vtable's +0xe8 entry resolves to a kernel map method. The IOGPU base getter lazily invokes that method on buffer+0x28 with option 0 and caches the mapping at buffer+0x30; the method adds kIOMapAnywhere and calls the same mapping helper used for buffer+0x48. Both calls start from the one descriptor stored at buffer+0x28 and +0x40. This establishes common descriptor identity and the conditional two-map route statically, not runtime byte aliasing or a controlled write.",
            "The exact-image registry-array constructor installs a vtable whose +0x78 insert slot resolves to a routine that stores the supplied object pointer into the selected slot and invokes its virtual +0x20 method. The shared-memory path passes its newly created object to this array and returns the resulting ID. The packet processor passes an input ID through the same table+0x78 lookup wrapper; the lookup checks nonzero/bounds, loads the indexed pointer, and applies an atomic reference-count operation. This closes a conditional static object round trip, not live ID stability, parser selection, or byte propagation.",
            "One IOGPUFamily command-16 path checks a 16-byte record count and passes records at request+0x14 to an object-selection loop; that loop supplies x2 from a kernel object array or null, not by passing record bytes directly.",
            "A class-compatible +0xe8 provider candidate accepts 4K/16K/64K granules, checks parent length alignment, and lazily builds an array of per-granule objects from a parent object at +0x88.",
            "IOUAT builds 0x28-byte segment records and invokes a PAC-authenticated virtual map callback.",
            "When the IOUAT constructor receives a null provider in x3, its default branch creates an object from the uat callback table and stores it at IOUAT+0x20.",
            "The uat callback candidate directly calls protected table ID 7 entry 4.",
        ],
        "unresolved": [
            "The mode bit's value on the target device was not observed.",
            "The exact-image externalMethod index 25 reaches packet processing in static control flow, but client-state gating and live invocation are unobserved. No user-controlled descriptor bytes were traced to the AGX map call.",
            "The array provider's runtime type, its parent object's origin, the packet buffer's user-writable provenance, and later virtual target types remain unresolved.",
            "A shared-memory object registration path, returned mapping address, common backing-object pointer, and divergent mapping options are traced statically. The runtime factory target, effective mapping permissions and byte alias, parser acceptance, and user-change propagation remain unresolved.",
            "Whether the mode-set AGX path is active and its IOUAT factory succeeds on the device is unobserved.",
            "No kernel, physical, or protected-memory write was observed by this offline audit.",
        ],
    }
    if devicetree is not None:
        result["devicetree"] = summarize_devicetree(devicetree)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernelcache", type=pathlib.Path)
    parser.add_argument("--devicetree", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    result = audit(args.kernelcache, args.devicetree)
    rendered = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
