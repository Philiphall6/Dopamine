#!/usr/bin/env python3
"""Check the exact-image selector-25 pre-parser control-flow boundary."""

from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
import pathlib

from analyze_sptm_txm import MachOImage
from audit_agx_uat_dispatch import (
    AGX_PREPARSER_FACTORY_ENTRIES,
    IOGPU_SELECTOR_0_ENTRIES,
    KERNEL_STATIC_BASE,
    validate_indirect_entries,
)
from triage_agx_metadata_probe import load_events, numbered
from triage_agx_owned_queue_probe import detail, triage


IMAGE_SHA256 = "8867208c59bfa426611c36fcfe570ffc41cc75ee293472fe7197860d0c5223f1"
IMAGE_NAME = "com.apple.iokit.IOGPUFamily"
AGX_IMAGE_NAME = "com.apple.AGXG14P"
KERNEL_IMAGE_NAME = "com.apple.kernel"
JOURNAL_SHA256 = "bf2154628ebf11b6a6d5681e832d1bac90b5e40c6db2848aa71886ca126a7664"
JOURNAL_RUN_ID = "73263D5E-22A4-4757-B24B-7DCCFE45B36E"
LIVE_QUEUE_VTABLE = 0xfffffff007b17550
LIVE_DEVICE_VTABLE = 0xfffffff007b1e0d0
DEVICE_FACTORY_SLOT = LIVE_DEVICE_VTABLE + 0x5c0
QUEUE_PACKET_SLOT = LIVE_QUEUE_VTABLE + 0x118
QUEUE_PACKET_ENCODING = 0x80119dcc017ff254
QUEUE_PACKET_OVERRIDE = 0xfffffff008803254
QUEUE_PRECHECK_SLOT = LIVE_QUEUE_VTABLE + 0x160
QUEUE_PRECHECK_ENCODING = 0x80415880017fb07c
QUEUE_PRECHECK = 0xfffffff0087ff07c
QUEUE_EMPTY_FINALIZER_SLOT = LIVE_QUEUE_VTABLE + 0xa8
QUEUE_EMPTY_FINALIZER_ENCODING = 0x801133b802f45d44
QUEUE_EMPTY_FINALIZER = 0xfffffff009f49d44
QUEUE_PACKET_BASE_GOT = 0xfffffff007b15d40
QUEUE_PACKET_BASE_GOT_ENCODING = 0x0010000000e42b28
QUEUE_PACKET_BASE_TABLE = 0xfffffff007e46b28
QUEUE_PACKET_BASE_SLOT = QUEUE_PACKET_BASE_TABLE + 0x128
QUEUE_PACKET_BASE_ENCODING = 0x80119dcc02f47e9c
QUEUE_PACKET_BASE = 0xfffffff009f4be9c
COMMAND_BUFFER_CLASS_NAME = 0xfffffff0070fab0d
COMMAND_BUFFER_VTABLE = 0xfffffff007b17410
COMMAND_BUFFER_INIT_SLOT = COMMAND_BUFFER_VTABLE + 0x78
COMMAND_BUFFER_INIT_ENCODING = 0x8011dc61017f9d84
COMMAND_BUFFER_INIT = 0xfffffff0087fdd84
COMMAND_BUFFER_CALLBACK_SLOT = COMMAND_BUFFER_VTABLE + 0x98
COMMAND_BUFFER_CALLBACK_ENCODING = 0x80419583017f9300
COMMAND_BUFFER_CALLBACK = 0xfffffff0087fd300
FIRMWARE_FACTORY_SLOT = LIVE_DEVICE_VTABLE + 0x880
FIRMWARE_FACTORY_ENCODING = 0x80116c7201853b14
FIRMWARE_FACTORY = 0xfffffff008857b14
FIRMWARE_POST_STORE_DEVICE_SLOT = LIVE_DEVICE_VTABLE + 0x858
FIRMWARE_POST_STORE_DEVICE_ENCODING = 0x801154270184c7f4
FIRMWARE_POST_STORE_DEVICE_TARGET = 0xfffffff0088507f4
FIRMWARE_CLASS_NAME = 0xfffffff0070ff371
FIRMWARE_PARENT_CLASS_NAME = 0xfffffff0070fded0
FIRMWARE_PARENT_META_GLOBAL = 0xfffffff00ab5df20
FIRMWARE_PARENT_META_VTABLE = 0xfffffff007b18dd0
FIRMWARE_PARENT_ALLOC_SLOT = FIRMWARE_PARENT_META_VTABLE + 0x68
FIRMWARE_PARENT_ALLOC_ENCODING = 0x8041160101845f38
FIRMWARE_PARENT_ALLOC = 0xfffffff008849f38
FIRMWARE_META_VTABLE = 0xfffffff007b1a4f8
FIRMWARE_ALLOC_SLOT = FIRMWARE_META_VTABLE + 0x68
FIRMWARE_ALLOC_ENCODING = 0x8041160101847540
FIRMWARE_ALLOC = 0xfffffff00884b540
FIRMWARE_INSTANCE_VTABLE = 0xfffffff007b18e58
FIRMWARE_BASE_CALLBACK_SLOT = FIRMWARE_INSTANCE_VTABLE + 0x210
FIRMWARE_BASE_CALLBACK_ENCODING = 0x8011925001630720
FIRMWARE_BASE_CALLBACK = 0xfffffff008634720
BLOCK_FENCE_METACLASS_GLOBAL = 0xfffffff00ab5d6d0
BLOCK_FENCE_NAME_ADDRESS = 0xfffffff0070fa75c
BLOCK_FENCE_META_VTABLE = 0xfffffff007b16de0
BLOCK_FENCE_INSTANCE_VTABLE = 0xfffffff007b16d20
BLOCK_FENCE_ALLOC_SLOT = BLOCK_FENCE_META_VTABLE + 0x68
BLOCK_FENCE_PREPARE_SLOT = BLOCK_FENCE_INSTANCE_VTABLE + 0x90
BLOCK_FENCE_RELEASE_SLOT = BLOCK_FENCE_INSTANCE_VTABLE + 0x28
BLOCK_FENCE_RELEASE_ENCODING = 0x80113a87015f70f0
BLOCK_FENCE_RELEASE = 0xfffffff0085fb0f0
BLOCK_FENCE_TAGGED_RELEASE_SLOT = BLOCK_FENCE_INSTANCE_VTABLE + 0x50
BLOCK_FENCE_TAGGED_RELEASE_ENCODING = 0x8011be60015f6e84
BLOCK_FENCE_TAGGED_RELEASE = 0xfffffff0085fae84
BLOCK_FENCE_RELEASE_CORE_SLOT = BLOCK_FENCE_INSTANCE_VTABLE + 0x58
BLOCK_FENCE_RELEASE_CORE_ENCODING = 0x801132e5015f6d24
BLOCK_FENCE_RELEASE_CORE = 0xfffffff0085fad24
BLOCK_FENCE_FREE_SLOT = BLOCK_FENCE_INSTANCE_VTABLE + 0x70
BLOCK_FENCE_FREE_ENCODING = 0x8011edc5017f20d8
BLOCK_FENCE_FREE = 0xfffffff0087f60d8

SUBMIT_WRAPPER_EXPECTED = {
    0xfffffff009f1ae3c: ("ldr", "x0, [x22, #0x120]"),
    0xfffffff009f1ae40: ("bl", "#0xfffffff009f38aa8"),
    0xfffffff009f1ae4c: ("ldr", "x8, [x0, #0x538]"),
    0xfffffff009f1ae74: ("bl", "#0xfffffff009f49254"),
    0xfffffff009f4927c: ("mov", "x19, x0"),
    0xfffffff009f4959c: ("ldr", "x0, [x19, #0x538]"),
    0xfffffff009f495b0: ("mov", "x17, #0x5c0"),
    0xfffffff009f495b4: ("add", "x16, x16, x17"),
    0xfffffff009f495c8: ("blraa", "x8, x17"),
    0xfffffff009f495cc: ("str", "x0, [x19, #0x520]"),
    0xfffffff009f495f4: ("ldr", "x8, [x16, #0x90]!"),
}

BATCH_START = 0xfffffff009f49254
BATCH_END = 0xfffffff009f494c0
QUEUE_STATE_WRITE = 0xfffffff009f492a0
PROCESS_CALL = 0xfffffff009f49398

PROCESS_START = 0xfffffff009f4956c
PROCESS_END = 0xfffffff009f49880
BACKEND_CALL = 0xfffffff009f4960c
BACKEND_SUCCESS_GATE = 0xfffffff009f49618
PARSER_CALL = 0xfffffff009f49680
BACKEND_OBJECT_READY = 0xfffffff009f495d4
BACKEND_FAILURE_NULL_CHECK = 0xfffffff009f497a8
BACKEND_FAILURE_RELEASE = 0xfffffff009f497cc
BACKEND_FAILURE_CLEAR = 0xfffffff009f497d0
BACKEND_COMMON_NULL_CHECK = 0xfffffff009f49840
BACKEND_COMMON_RELEASE = 0xfffffff009f49864
BACKEND_COMMON_CLEAR = 0xfffffff009f49868
PROCESS_RETURN = 0xfffffff009f4987c

PREPARE_START = 0xfffffff0087f5ca8
PREPARE_END = 0xfffffff0087f60d8
PREPARE_STATE_WRITE = 0xfffffff0087f5cc8
PREPARE_INDIRECT_CALL = 0xfffffff0087f5ce4
PREPARE_RETURN = 0xfffffff0087f60d4
PREPARE_POOL_WRITES = (
    0xfffffff0087f5d34,
    0xfffffff0087f5dc4,
    0xfffffff0087f5e44,
    0xfffffff0087f5edc,
)
PREPARE_RETENTION_PATH = (
    0xfffffff0087f5d34,
    0xfffffff0087f5d68,
    0xfffffff0087f5e44,
    0xfffffff0087f5e78,
    0xfffffff0087f5e84,
)
PREPARE_ROLLBACK_WRITES = (
    0xfffffff0087f5fac,
    0xfffffff0087f5fbc,
    0xfffffff0087f5ff4,
    0xfffffff0087f606c,
    0xfffffff0087f607c,
    0xfffffff0087f60b0,
)
PREPARE_BASE_GOT = 0xfffffff007b15d20
PREPARE_BASE_GOT_ENCODING = 0x0010000000e3f9e8
PREPARE_BASE_TABLE = 0xfffffff007e439e8
PREPARE_BASE_SLOT = PREPARE_BASE_TABLE + 0xa0
PREPARE_BASE_SLOT_ENCODING = 0x80115c7102f1df00
PREPARE_BASE_INITIALIZER = 0xfffffff009f21f00
BLOCK_FENCE_FREE_END = 0xfffffff0087f62b0
BLOCK_FENCE_FREE_GRAPH_END = 0xfffffff0087f62a8
BLOCK_FENCE_FIRST_RELEASE_PATH = 0xfffffff0087f60f8
BLOCK_FENCE_FIRST_CLEAR = 0xfffffff0087f61a8
BLOCK_FENCE_SECOND_STAGE = 0xfffffff0087f61ac
BLOCK_FENCE_SECOND_RELEASE_PATH = 0xfffffff0087f61b4
BLOCK_FENCE_SECOND_CLEAR = 0xfffffff0087f6264
BLOCK_FENCE_FINAL_STAGE = 0xfffffff0087f6268
BASE_INIT_END = 0xfffffff009f22008
BASE_INIT_HELPER_CALL = 0xfffffff009f21f30
BASE_INIT_RETURN = 0xfffffff009f22004
BASE_HELPER_START = 0xfffffff009f21bc0
BASE_HELPER_END = 0xfffffff009f21c38
BASE_HELPER_VIRTUAL_CALL = 0xfffffff009f21bf8
BASE_HELPER_RETURN = 0xfffffff009f21c34
BASE_HELPER_GOT = 0xfffffff007e40920
BASE_HELPER_GOT_ENCODING = 0x0010000000aeae60
BASE_HELPER_TABLE = 0xfffffff007aeee60
BASE_HELPER_SLOT = BASE_HELPER_TABLE + 0x78
BASE_HELPER_SLOT_ENCODING = 0x80114a6a015f6d18
BASE_HELPER_KERNEL_TARGET = 0xfffffff0085fad18

EXPECTED = {
    QUEUE_STATE_WRITE: ("strb", "w8, [x19, #0x52f]"),
    PROCESS_CALL: ("bl", "#0xfffffff009f4956c"),
    BACKEND_CALL: ("blraa", "x8, x17"),
    BACKEND_SUCCESS_GATE: ("tbz", "w8, #0, #0xfffffff009f497a8"),
    PARSER_CALL: ("blraa", "x9, x17"),
    0xfffffff009f497bc: ("ldr", "x8, [x16, #0x28]!"),
    BACKEND_FAILURE_RELEASE: ("blraa", "x8, x17"),
    0xfffffff009f49854: ("ldr", "x8, [x16, #0x28]!"),
    BACKEND_COMMON_RELEASE: ("blraa", "x8, x17"),
    0xfffffff009f49868: ("str", "xzr, [x24]"),
}
EXPECTED_AGX = {
    0xfffffff0087f5ccc: ("adrp", "x8, #0xfffffff007b15000"),
    0xfffffff0087f5cd0: ("ldr", "x8, [x8, #0xd20]"),
    0xfffffff0087f5cd4: ("add", "x9, x8, #0xa0"),
    0xfffffff0087f5cd8: ("ldr", "x8, [x8, #0xa0]"),
    PREPARE_STATE_WRITE: ("stp", "q0, q0, [x0, #0x130]"),
    PREPARE_INDIRECT_CALL: ("blraa", "x8, x17"),
    PREPARE_RETURN: ("retab", ""),
    **{address: ("str", "x10, [x9]") for address in PREPARE_POOL_WRITES},
}
EXPECTED_PREPARE_RETENTION = {
    0xfffffff0087f5d4c: ("str", "x8, [x21, #0xbf0]"),
    0xfffffff0087f5d68: ("str", "x8, [x19, #0x130]"),
    0xfffffff0087f5e5c: ("str", "x8, [x21, #0xbf0]"),
    0xfffffff0087f5e78: ("str", "x21, [x19, #0x138]"),
    0xfffffff0087f5e84: ("cbnz", "x8, #0xfffffff0087f60c0"),
    0xfffffff0087f5fac: ("str", "x9, [x11]"),
    0xfffffff0087f5fbc: ("str", "x9, [x22, #0xbf0]"),
    0xfffffff0087f5ff4: ("str", "xzr, [x9]"),
    0xfffffff0087f606c: ("str", "x10, [x9]"),
    0xfffffff0087f607c: ("str", "x9, [x22, #0xbf0]"),
    0xfffffff0087f60b0: ("str", "xzr, [x9]"),
}
EXPECTED_BLOCK_FENCE_FREE = {
    0xfffffff0087f60f0: ("ldr", "x21, [x0, #0x130]"),
    0xfffffff0087f6100: ("ldr", "x0, [x20, #0xc78]"),
    0xfffffff0087f6104: ("bl", "#0xfffffff007fe12ac"),
    0xfffffff0087f6158: ("str", "x10, [x9]"),
    0xfffffff0087f6168: ("str", "x9, [x20, #0xbf0]"),
    0xfffffff0087f619c: ("str", "xzr, [x9]"),
    0xfffffff0087f61a4: ("bl", "#0xfffffff007fe2080"),
    BLOCK_FENCE_FIRST_CLEAR: ("str", "xzr, [x19, #0x130]"),
    BLOCK_FENCE_SECOND_STAGE: ("ldr", "x21, [x19, #0x138]"),
    0xfffffff0087f61c0: ("bl", "#0xfffffff007fe12ac"),
    0xfffffff0087f6214: ("str", "x10, [x9]"),
    0xfffffff0087f6224: ("str", "x9, [x20, #0xbf0]"),
    0xfffffff0087f6258: ("str", "xzr, [x9]"),
    0xfffffff0087f6260: ("bl", "#0xfffffff007fe2080"),
    BLOCK_FENCE_SECOND_CLEAR: ("str", "xzr, [x19, #0x138]"),
    0xfffffff0087f626c: ("str", "xzr, [x19, #0x140]"),
    0xfffffff0087f6270: ("str", "xzr, [x8, #8]"),
    0xfffffff0087f627c: ("add", "x1, x8, #0x80"),
    0xfffffff0087f62ac: ("braa", "x16, x17"),
}
EXPECTED_RELEASE_CHAIN = {
    0xfffffff0085fb104: ("ldr", "x8, [x16, #0x50]!"),
    0xfffffff0085fb11c: ("braa", "x16, x17"),
    0xfffffff0085fae98: ("ldr", "x8, [x16, #0x58]!"),
    0xfffffff0085faeb0: ("braa", "x16, x17"),
    0xfffffff0085fad98: ("ldr", "x16, [x0]"),
    0xfffffff0085fada8: ("ldr", "x8, [x16, #0x70]!"),
    0xfffffff0085fadcc: ("braa", "x16, x17"),
}
EXPECTED_BASE_INIT = {
    BASE_INIT_HELPER_CALL: ("bl", "#0xfffffff009f21bc0"),
    0xfffffff009f21f38: ("str", "x23, [x19, #0xe0]"),
    0xfffffff009f21f60: ("blraa", "x8, x17"),
    0xfffffff009f21f6c: ("bl", "#0xfffffff00866a168"),
    0xfffffff009f21f70: ("str", "x0, [x19, #0xf8]"),
    0xfffffff009f21fd0: ("blraa", "x9, x17"),
    0xfffffff009f21fe0: ("bl", "#0xfffffff009f47efc"),
    BASE_INIT_RETURN: ("retab", ""),
}
EXPECTED_BASE_HELPER = {
    0xfffffff009f21be0: ("adrp", "x8, #0xfffffff007e40000"),
    0xfffffff009f21be4: ("ldr", "x8, [x8, #0x920]"),
    0xfffffff009f21be8: ("add", "x9, x8, #0x78"),
    0xfffffff009f21bec: ("ldr", "x8, [x8, #0x78]"),
    BASE_HELPER_VIRTUAL_CALL: ("blraa", "x8, x17"),
    0xfffffff009f21c04: ("str", "x22, [x19, #0x10]"),
    0xfffffff009f21c0c: ("bl", "#0xfffffff009f1e11c"),
    0xfffffff009f21c14: ("bl", "#0xfffffff009f1e11c"),
    0xfffffff009f21c18: ("str", "x20, [x19, #0xc0]"),
    0xfffffff009f21c20: ("str", "x0, [x19, #0x18]"),
    BASE_HELPER_RETURN: ("retab", ""),
}
EXPECTED_KERNEL_TARGET = {
    BASE_HELPER_KERNEL_TARGET: ("bti", "c"),
    BASE_HELPER_KERNEL_TARGET + 4: ("mov", "w0, #1"),
    BASE_HELPER_KERNEL_TARGET + 8: ("ret", ""),
}
EXPECTED_PACKET_OVERRIDE = {
    QUEUE_PRECHECK: ("bti", "c"),
    0xfffffff0087ff080: ("str", "xzr, [x0, #0x5f0]"),
    0xfffffff0087ff084: ("ldrb", "w8, [x0, #0x5e8]"),
    0xfffffff0087ff088: ("tbz", "w8, #0, #0xfffffff0087ff094"),
    0xfffffff0087ff08c: ("mov", "w0, #1"),
    0xfffffff008803280: ("mov", "x17, #0x160"),
    0xfffffff00880329c: ("blraa", "x8, x17"),
    0xfffffff0088032a0: ("tbz", "w0, #0, #0xfffffff008803330"),
    0xfffffff0088032d0: ("blraa", "x8, x17"),
    0xfffffff0088032d4: ("strh", "wzr, [x19, #0x800]"),
    0xfffffff0088032d8: ("strb", "wzr, [x19, #0x802]"),
    0xfffffff0088032ec: ("strb", "w8, [x19, #0x5d8]"),
    0xfffffff0088032f4: ("ldr", "x8, [x8, #0xd40]"),
    0xfffffff0088032fc: ("ldr", "x16, [x8, #0x128]"),
    0xfffffff00880332c: ("braa", "x16, x17"),
    0xfffffff008803368: ("str", "w8, [x19, #0x528]"),
    0xfffffff008803388: ("str", "x0, [x21, #0x140]"),
}
EXPECTED_EMPTY_PACKET_PATH = {
    0xfffffff009f1add8: ("ldr", "w0, [x21, #0x38]"),
    0xfffffff009f1addc: ("ldr", "x23, [x21, #0x30]"),
    0xfffffff009f1ade0: ("ldr", "x8, [x21, #0x20]"),
    0xfffffff009f1ade4: ("ldp", "x25, x24, [x8, #0x10]"),
    0xfffffff009f1ae2c: ("mul", "x9, x24, x25"),
    0xfffffff009f1ae30: ("cmp", "x0, x9"),
    0xfffffff009f1ae38: ("ldr", "w1, [x8]"),
    0xfffffff009f1ae3c: ("ldr", "x0, [x22, #0x120]"),
    0xfffffff009f1ae74: ("bl", "#0xfffffff009f49254"),
    0xfffffff009f4c150: ("cmp", "x26, #0x10"),
    0xfffffff009f4c178: ("ldr", "w8, [x24, #0xc]"),
    0xfffffff009f4c17c: ("lsr", "w23, w8, #0x1f"),
    0xfffffff009f4c184: ("and", "w10, w8, #0x3fffffff"),
    0xfffffff009f4c18c: ("csel", "w27, w10, wzr, eq"),
    0xfffffff009f4c190: ("and", "w8, w10, w9, asr #31"),
    0xfffffff009f4c1a4: ("cbnz", "w8, #0xfffffff009f4c298"),
    0xfffffff009f4c1a8: ("cbz", "w27, #0xfffffff009f4c294"),
    0xfffffff009f4c294: ("cbz", "x20, #0xfffffff009f4c2a4"),
    0xfffffff009f4c2a4: ("mov", "x1, #0"),
    0xfffffff009f4c2a8: ("mov", "x27, #0"),
    0xfffffff009f4c2ac: ("str", "xzr, [sp, #0x28]"),
    0xfffffff009f4c2b0: ("mov", "w23, #1"),
    0xfffffff009f4c2b4: ("mov", "x0, x21"),
    0xfffffff009f4c2b8: ("mov", "x2, x26"),
    0xfffffff009f4c2bc: ("bl", "#0xfffffff009f2515c"),
    0xfffffff009f4c2d0: ("ldr", "x8, [x16, #0xa8]!"),
    0xfffffff009f4c2e8: ("blraa", "x8, x17"),
}
EXPECTED_SUBMIT_RECORD_CONTRACT = {
    0xfffffff009f43aa4: ("mov", "w8, #0x30"),
    0xfffffff009f43aa8: ("str", "w8, [x0, #0x268]"),
    0xfffffff009f1ae4c: ("ldr", "x8, [x0, #0x538]"),
    0xfffffff009f1ae50: ("ldr", "w8, [x8, #0x268]"),
    0xfffffff009f1ae54: ("cmp", "x24, x8"),
    0xfffffff009f1ae58: ("b.ne", "#0xfffffff009f1af44"),
}
EXPECTED_OLD_SELECTOR_0 = {
    0xfffffff009f1c6f8: ("bl", "#0xfffffff009f38aa8"),
    0xfffffff009f1c718: ("bl", "#0xfffffff009f49254"),
}
EXPECTED_COMMAND_BUFFER = {
    0xfffffff0087febf4: ("add", "x0, x0, #0x918"),
    0xfffffff0087febfc: ("add", "x1, x1, #0xb0d"),
    0xfffffff0087fec08: ("mov", "w3, #0x17c0"),
    0xfffffff0087fec0c: ("bl", "#0xfffffff0085f7d6c"),
    0xfffffff0087fec94: ("add", "x16, x16, #0x400"),
    0xfffffff0087fec98: ("add", "x16, x16, #0x10"),
    0xfffffff0087feca8: ("str", "x16, [x0]"),
    0xfffffff0087fecb4: ("mov", "x0, x19"),
    0xfffffff0087ff2a0: ("mov", "w1, #0x17c0"),
    0xfffffff0087ff2a4: ("bl", "#0xfffffff0085fb7bc"),
    0xfffffff0087ff2a8: ("bl", "#0xfffffff0087fec6c"),
    0xfffffff0087ff2ac: ("str", "x0, [x19, #0x670]"),
    0xfffffff0087ff2b8: ("ldr", "x1, [x19, #0x538]"),
    0xfffffff0087ff2bc: ("ldr", "x2, [x19, #0x490]"),
    0xfffffff0087ff2e0: ("blraa", "x8, x17"),
    0xfffffff0087fdda8: ("mov", "x22, x1"),
    0xfffffff0087fddd4: ("stp", "x21, x22, [x19, #0x10]"),
    0xfffffff0087fddd8: ("str", "x20, [x19, #0x20]"),
    0xfffffff0087fd33c: ("str", "w8, [x0, #0x28]"),
    0xfffffff0087fd390: ("stp", "q0, q0, [x21, #0xb0]"),
    0xfffffff0087fd3d0: ("str", "wzr, [x8]"),
    0xfffffff0087fd43c: ("str", "w22, [x20, #0x180]"),
    0xfffffff0087fd450: ("str", "w8, [x20, #0x180]"),
    0xfffffff0087fd4c4: ("blraa", "x9, x17"),
    0xfffffff0087fd4cc: ("str", "x0, [x21]"),
}
EXPECTED_FIRMWARE_FACTORY = {
    0xfffffff00884a004: ("add", "x0, x0, #0xf20"),
    0xfffffff00884a00c: ("add", "x1, x1, #0xed0"),
    0xfffffff00884a018: ("mov", "w3, #0x1be0"),
    0xfffffff00884a024: ("add", "x16, x16, #0xdc0"),
    0xfffffff00884a028: ("add", "x16, x16, #0x10"),
    FIRMWARE_PARENT_ALLOC: ("bti", "c"),
    0xfffffff008849f3c: ("mov", "x0, #0"),
    0xfffffff008849f40: ("ret", ""),
    0xfffffff0087e6a20: ("add", "x8, x16, #0x880"),
    0xfffffff0087e6a24: ("ldr", "x9, [x16, #0x880]"),
    0xfffffff0087e6a34: ("blraa", "x9, x17"),
    0xfffffff0087e6a3c: ("str", "x0, [x19, #0x4a0]"),
    0xfffffff0087e6a40: ("ldr", "x16, [x19]"),
    0xfffffff0087e6a50: ("mov", "x17, #0x858"),
    0xfffffff0087e6a60: ("mov", "x0, x19"),
    0xfffffff0087e6a6c: ("blraa", "x8, x17"),
    FIRMWARE_POST_STORE_DEVICE_TARGET: ("bti", "c"),
    0xfffffff008857b1c: ("add", "x0, x0, #0xef8"),
    0xfffffff008857b30: ("ldr", "x8, [x16, #0x68]!"),
    0xfffffff008857b44: ("braa", "x16, x17"),
    0xfffffff00884bedc: ("add", "x0, x0, #0xef8"),
    0xfffffff00884bee4: ("add", "x1, x1, #0x371"),
    0xfffffff00884beec: ("add", "x2, x2, #0xf20"),
    0xfffffff00884bef0: ("mov", "w3, #0x1be0"),
    0xfffffff00884bef4: ("bl", "#0xfffffff0085f7d6c"),
    0xfffffff00884befc: ("add", "x16, x16, #0x4e8"),
    0xfffffff00884bf00: ("add", "x16, x16, #0x10"),
    0xfffffff00884b580: ("add", "x16, x16, #0xe48"),
    0xfffffff00884b584: ("add", "x16, x16, #0x10"),
    0xfffffff00884b594: ("str", "x16, [x0]"),
    0xfffffff0087fd460: ("ldr", "x8, [x19, #0x18]"),
    0xfffffff0087fd464: ("ldr", "x0, [x8, #0x4a0]"),
    0xfffffff0087fd4b4: ("ldr", "x9, [x16, #0x210]"),
    0xfffffff0087fd4c4: ("blraa", "x9, x17"),
}
EXPECTED_PURE_VIRTUAL = {
    FIRMWARE_BASE_CALLBACK: ("pacibsp", ""),
    0xfffffff008634750: ("add", "x0, x0, #0xff8"),
    0xfffffff008634754: ("bl", "#0xfffffff0087ba0ec"),
}
EXPECTED_METACLASS_CHAIN = {
    0xfffffff0087e4284: ("adrp", "x0, #0xfffffff00ab5d000"),
    0xfffffff0087e4288: ("add", "x0, x0, #0x6d0"),
    0xfffffff0087e428c: ("ldr", "x16, [x0]"),
    0xfffffff0087e429c: ("ldr", "x8, [x16, #0x68]!"),
    0xfffffff0087e42b0: ("braa", "x16, x17"),
    0xfffffff0087f631c: ("adrp", "x0, #0xfffffff007b23000"),
    0xfffffff0087f6320: ("add", "x0, x0, #0x7c0"),
    0xfffffff0087f6340: ("adrp", "x16, #0xfffffff007b16000"),
    0xfffffff0087f6344: ("add", "x16, x16, #0xd10"),
    0xfffffff0087f6348: ("add", "x16, x16, #0x10"),
    0xfffffff0087f6358: ("str", "x16, [x0]"),
    0xfffffff0087f6430: ("adrp", "x0, #0xfffffff00ab5d000"),
    0xfffffff0087f6434: ("add", "x0, x0, #0x6d0"),
    0xfffffff0087f6438: ("adrp", "x1, #0xfffffff0070fa000"),
    0xfffffff0087f643c: ("add", "x1, x1, #0x75c"),
    0xfffffff0087f6448: ("mov", "w3, #0x158"),
    0xfffffff0087f644c: ("bl", "#0xfffffff0085f7d6c"),
    0xfffffff0087f6450: ("adrp", "x16, #0xfffffff007b16000"),
    0xfffffff0087f6454: ("add", "x16, x16, #0xdd0"),
    0xfffffff0087f6458: ("add", "x16, x16, #0x10"),
    0xfffffff0087f6468: ("str", "x16, [x0]"),
}


def branch_target(operands: str) -> int:
    try:
        return int(operands.rsplit("#", 1)[1], 0)
    except (IndexError, ValueError) as exc:
        raise ValueError(f"unresolved branch target: {operands}") from exc


def build_graph(instructions: list) -> dict[int, tuple[int, ...]]:
    addresses = {instruction.address for instruction in instructions}
    graph = {}
    for instruction in instructions:
        address = instruction.address
        mnemonic = instruction.mnemonic
        following = address + 4
        if mnemonic in {"ret", "retab", "brk"}:
            successors = ()
        elif mnemonic == "b":
            successors = (branch_target(instruction.op_str),)
        elif mnemonic.startswith("b.") or mnemonic in {"cbz", "cbnz", "tbz", "tbnz"}:
            successors = (following, branch_target(instruction.op_str))
        elif mnemonic in {"br", "braa", "brab"}:
            raise ValueError(f"unresolved computed branch at {address:#x}")
        elif mnemonic.startswith(".") or mnemonic in {"udf", "eret"}:
            raise ValueError(f"unsupported instruction at {address:#x}: {mnemonic}")
        else:
            # Calls are modeled as returning normally. A non-returning call
            # can remove a path, but cannot create a parser bypass.
            successors = (following,)
        graph[address] = tuple(target for target in successors if target in addresses)
    return graph


def reachable(graph: dict[int, tuple[int, ...]], entry: int, excluded: int | None = None) -> set[int]:
    seen = set()
    pending = [entry]
    while pending:
        current = pending.pop()
        if current == excluded or current in seen or current not in graph:
            continue
        seen.add(current)
        pending.extend(graph[current])
    return seen


def reachable_avoiding(graph: dict[int, tuple[int, ...]], entry: int,
                       excluded: set[int]) -> set[int]:
    seen = set()
    pending = [entry]
    while pending:
        current = pending.pop()
        if current in excluded or current in seen or current not in graph:
            continue
        seen.add(current)
        pending.extend(graph[current])
    return seen


def backend_return_without_release(graph: dict[int, tuple[int, ...]]) -> bool:
    pending = [(BACKEND_OBJECT_READY, True, False)]
    seen = set()
    while pending:
        node, live, released = pending.pop()
        state = (node, live, released)
        if state in seen or node not in graph:
            continue
        seen.add(state)
        if node in {BACKEND_FAILURE_RELEASE, BACKEND_COMMON_RELEASE}:
            released = True
        if node in {BACKEND_FAILURE_CLEAR, BACKEND_COMMON_CLEAR}:
            live = False
        if node == PROCESS_RETURN:
            if not released:
                return True
            continue

        successors = graph[node]
        if node == BACKEND_FAILURE_NULL_CHECK:
            # cbz x0, failure-clear; x0 was reloaded from queue+0x520.
            successors = (node + 4,) if live else (BACKEND_FAILURE_CLEAR,)
        elif node == BACKEND_COMMON_NULL_CHECK:
            # cbz x0, common-clear; x0 was reloaded from queue+0x520.
            successors = (node + 4,) if live else (BACKEND_COMMON_CLEAR,)
        pending.extend((successor, live, released) for successor in successors)
    return False


def dominates(graph: dict[int, tuple[int, ...]], entry: int, required: int, target: int) -> bool:
    if target not in reachable(graph, entry):
        raise ValueError(f"target is unreachable: {target:#x}")
    if required not in reachable(graph, entry):
        raise ValueError(f"required instruction is unreachable: {required:#x}")
    return target not in reachable(graph, entry, excluded=required)


def path_through(graph: dict[int, tuple[int, ...]], entry: int, target: int,
                 required: tuple[int, ...], forbidden: tuple[int, ...]) -> list[int] | None:
    required_set = set(required)
    forbidden_set = set(forbidden)
    pending = deque([(entry, frozenset(), [entry])])
    visited = set()
    while pending:
        node, seen, path = pending.popleft()
        if node in forbidden_set or node not in graph:
            continue
        seen = seen | ({node} if node in required_set else set())
        key = (node, seen)
        if key in visited:
            continue
        visited.add(key)
        if node == target and required_set <= seen:
            return path
        pending.extend((successor, seen, path + [successor]) for successor in graph[node])
    return None


def function_graph(image: MachOImage, start: int, end: int) -> dict[int, tuple[int, ...]]:
    instructions = [instruction for instruction in image.instructions
                    if start <= instruction.address < end]
    expected_addresses = set(range(start, end, 4))
    if {instruction.address for instruction in instructions} != expected_addresses:
        raise ValueError(f"incomplete function disassembly: {start:#x}-{end:#x}")
    return build_graph(instructions)


def verify_instructions(image: MachOImage, expected: dict[int, tuple[str, str]]) -> None:
    for address, contract in expected.items():
        instruction = image.instruction_at(address)
        actual = None if instruction is None else (instruction.mnemonic, instruction.op_str)
        if actual != contract:
            raise ValueError(f"instruction mismatch at {address:#x}: {actual} != {contract}")


def verify_prepare_base_slot(agx: MachOImage, iogpu: MachOImage) -> dict:
    got = agx.read_u64(PREPARE_BASE_GOT)
    slot = iogpu.read_u64(PREPARE_BASE_SLOT)
    table = None if got is None else KERNEL_STATIC_BASE + (got & 0xffffffff)
    target = None if slot is None else KERNEL_STATIC_BASE + (slot & 0xffffffff)
    if (got, table, slot, target) != (
        PREPARE_BASE_GOT_ENCODING,
        PREPARE_BASE_TABLE,
        PREPARE_BASE_SLOT_ENCODING,
        PREPARE_BASE_INITIALIZER,
    ):
        raise ValueError("AGX prepare base-initializer pointer chain changed")
    if iogpu.mapped_bytes(table, 0xa8) is None:
        raise ValueError("IOGPU base table is not mapped")
    verify_instructions(iogpu, EXPECTED_BASE_INIT)
    graph = function_graph(iogpu, PREPARE_BASE_INITIALIZER, BASE_INIT_END)
    if not dominates(graph, PREPARE_BASE_INITIALIZER, BASE_INIT_HELPER_CALL, BASE_INIT_RETURN):
        raise ValueError("IOGPU base initializer helper is no longer required")
    return {
        "agx_got": f"{PREPARE_BASE_GOT:#x}",
        "static_table": f"{table:#x}",
        "table_slot": f"{PREPARE_BASE_SLOT:#x}",
        "static_target": f"{target:#x}",
        "instruction_count": len(graph),
        "helper_call_dominates_return": True,
        "conditional_state_allocation_and_callback_sites": [
            f"{address:#x}" for address in (
                0xfffffff009f21f38,
                0xfffffff009f21f60,
                0xfffffff009f21f6c,
                0xfffffff009f21f70,
                0xfffffff009f21fd0,
                0xfffffff009f21fe0,
            )
        ],
    }


def verify_base_init_helper(iogpu: MachOImage, kernel: MachOImage) -> dict:
    got = iogpu.read_u64(BASE_HELPER_GOT)
    slot = kernel.read_u64(BASE_HELPER_SLOT)
    table = None if got is None else KERNEL_STATIC_BASE + (got & 0xffffffff)
    target = None if slot is None else KERNEL_STATIC_BASE + (slot & 0xffffffff)
    if (got, table, slot, target) != (
        BASE_HELPER_GOT_ENCODING,
        BASE_HELPER_TABLE,
        BASE_HELPER_SLOT_ENCODING,
        BASE_HELPER_KERNEL_TARGET,
    ):
        raise ValueError("IOGPU base-helper pointer chain changed")
    if kernel.mapped_bytes(table, 0x80) is None:
        raise ValueError("kernel base-helper table is not mapped")
    verify_instructions(iogpu, EXPECTED_BASE_HELPER)
    verify_instructions(kernel, EXPECTED_KERNEL_TARGET)
    graph = function_graph(iogpu, BASE_HELPER_START, BASE_HELPER_END)
    if not dominates(graph, BASE_HELPER_START, BASE_HELPER_VIRTUAL_CALL, BASE_HELPER_RETURN):
        raise ValueError("IOGPU helper virtual call is no longer required")
    return {
        "iogpu_got": f"{BASE_HELPER_GOT:#x}",
        "static_table": f"{table:#x}",
        "table_slot": f"{BASE_HELPER_SLOT:#x}",
        "static_kernel_target": f"{target:#x}",
        "kernel_target_returns_one": True,
        "virtual_call_dominates_helper_return": True,
        "stateful_success_path_sites": [
            f"{address:#x}" for address in (
                0xfffffff009f21c04,
                0xfffffff009f21c0c,
                0xfffffff009f21c14,
                0xfffffff009f21c18,
                0xfffffff009f21c20,
            )
        ],
    }


def verify_queue_packet_route(agx: MachOImage, iogpu: MachOImage) -> dict:
    entries = validate_indirect_entries(agx.read_u64, (
        ("observed-queue-packet-override", QUEUE_PACKET_SLOT,
         QUEUE_PACKET_ENCODING, QUEUE_PACKET_OVERRIDE),
        ("observed-queue-precheck", QUEUE_PRECHECK_SLOT,
         QUEUE_PRECHECK_ENCODING, QUEUE_PRECHECK),
        ("observed-queue-empty-finalizer", QUEUE_EMPTY_FINALIZER_SLOT,
         QUEUE_EMPTY_FINALIZER_ENCODING, QUEUE_EMPTY_FINALIZER),
    ))
    got = agx.read_u64(QUEUE_PACKET_BASE_GOT)
    slot = iogpu.read_u64(QUEUE_PACKET_BASE_SLOT)
    table = None if got is None else KERNEL_STATIC_BASE + (got & 0xffffffff)
    target = None if slot is None else KERNEL_STATIC_BASE + (slot & 0xffffffff)
    if (got, table, slot, target) != (
        QUEUE_PACKET_BASE_GOT_ENCODING,
        QUEUE_PACKET_BASE_TABLE,
        QUEUE_PACKET_BASE_ENCODING,
        QUEUE_PACKET_BASE,
    ):
        raise ValueError("queue packet base-method pointer chain changed")
    verify_instructions(agx, EXPECTED_PACKET_OVERRIDE)
    verify_instructions(iogpu, EXPECTED_EMPTY_PACKET_PATH)
    verify_instructions(iogpu, EXPECTED_SUBMIT_RECORD_CONTRACT)
    verify_instructions(iogpu, EXPECTED_OLD_SELECTOR_0)
    old_entries = validate_indirect_entries(iogpu.read_u64, IOGPU_SELECTOR_0_ENTRIES)
    return {
        "observed_queue_entries": entries,
        "base_table": f"{table:#x}",
        "base_packet_slot": f"{QUEUE_PACKET_BASE_SLOT:#x}",
        "base_packet_target": f"{target:#x}",
        "old_selector_0_entries": old_entries,
        "old_selector_0_batch_target": f"{BATCH_START:#x}",
        "override_pre_base_sites": [f"{address:#x}" for address in (
            0xfffffff00880329c,
            0xfffffff0088032d0,
            0xfffffff0088032d4,
            0xfffffff0088032d8,
            0xfffffff0088032ec,
        )],
        "old_selector_runtime_reachability_observed": False,
        "parser_only_alternate_route_established": False,
        "all_zero_header_uses_empty_record_path": True,
        "all_zero_header_command_dispatch_skipped": True,
        "all_zero_header_finalizer_target": f"{QUEUE_EMPTY_FINALIZER:#x}",
        "all_zero_header_complete_effects_bounded": False,
        "submit_record_size": "0x30",
        "submit_record_size_field": "device+0x268",
    }


def verify_command_buffer_callback(agx: MachOImage) -> dict:
    name = agx.read_cstring(COMMAND_BUFFER_CLASS_NAME)
    if name != "AGXCommandBuffer":
        raise ValueError(f"queue command-buffer class name changed: {name}")
    entries = validate_indirect_entries(agx.read_u64, (
        ("queue-command-buffer-initializer", COMMAND_BUFFER_INIT_SLOT,
         COMMAND_BUFFER_INIT_ENCODING, COMMAND_BUFFER_INIT),
        ("queue-command-buffer-callback", COMMAND_BUFFER_CALLBACK_SLOT,
         COMMAND_BUFFER_CALLBACK_ENCODING, COMMAND_BUFFER_CALLBACK),
    ))
    verify_instructions(agx, EXPECTED_COMMAND_BUFFER)
    return {
        "static_class_name": name,
        "class_size": "0x17c0",
        "queue_field": "+0x670",
        "vtable_entries": entries,
        "initializer_device_field": "+0x18",
        "callback_state_write_sites": [f"{address:#x}" for address in (
            0xfffffff0087fd33c,
            0xfffffff0087fd390,
            0xfffffff0087fd3d0,
            0xfffffff0087fd43c,
            0xfffffff0087fd450,
            0xfffffff0087fd4cc,
        )],
        "callback_downstream_virtual_call": "0xfffffff0087fd4c4",
        "runtime_object_identity_observed": False,
        "complete_effects_bounded": False,
    }


def verify_firmware_callback_candidate(agx: MachOImage, kernel: MachOImage) -> dict:
    name = agx.read_cstring(FIRMWARE_CLASS_NAME)
    parent_name = agx.read_cstring(FIRMWARE_PARENT_CLASS_NAME)
    pure_virtual = kernel.read_cstring(0xfffffff0070a0a72)
    if (name, parent_name, pure_virtual) != (
        "AGXArmFirmwareASC", "AGXArmFirmware", "__cxa_pure_virtual"
    ):
        raise ValueError("firmware class or pure-virtual marker changed")
    entries = validate_indirect_entries(agx.read_u64, (
        ("device-firmware-factory", FIRMWARE_FACTORY_SLOT,
         FIRMWARE_FACTORY_ENCODING, FIRMWARE_FACTORY),
        ("post-store-device-method", FIRMWARE_POST_STORE_DEVICE_SLOT,
         FIRMWARE_POST_STORE_DEVICE_ENCODING, FIRMWARE_POST_STORE_DEVICE_TARGET),
        ("abstract-firmware-parent-allocator", FIRMWARE_PARENT_ALLOC_SLOT,
         FIRMWARE_PARENT_ALLOC_ENCODING, FIRMWARE_PARENT_ALLOC),
        ("firmware-metaclass-allocator", FIRMWARE_ALLOC_SLOT,
         FIRMWARE_ALLOC_ENCODING, FIRMWARE_ALLOC),
        ("firmware-base-callback", FIRMWARE_BASE_CALLBACK_SLOT,
         FIRMWARE_BASE_CALLBACK_ENCODING, FIRMWARE_BASE_CALLBACK),
    ))
    verify_instructions(agx, EXPECTED_FIRMWARE_FACTORY)
    verify_instructions(kernel, EXPECTED_PURE_VIRTUAL)
    return {
        "static_class_name": name,
        "static_parent_class_name": parent_name,
        "static_parent_metaclass_global": f"{FIRMWARE_PARENT_META_GLOBAL:#x}",
        "abstract_parent_allocator_returns_null": True,
        "class_size": "0x1be0",
        "device_field": "+0x4a0",
        "base_vtable_entries": entries,
        "base_callback_symbol": pure_virtual,
        "immediate_post_store_call_receives_device": True,
        "runtime_field_object_and_final_vtable_observed": False,
        "effective_callback_target_resolved": False,
    }


def verify_live_queue_link(raw: bytes) -> dict:
    digest = hashlib.sha256(raw).hexdigest()
    if digest != JOURNAL_SHA256:
        raise ValueError(f"queue journal SHA-256 mismatch: {digest}")
    events = load_events(raw)
    verdict = triage(events, JOURNAL_RUN_ID)
    if verdict["verdict"] != "owned_queue_and_buffer_observed":
        raise ValueError("queue journal does not pass owned-queue triage")
    run = [event for event in events if event["run_id"] == JOURNAL_RUN_ID]
    queue_vtable = numbered(detail(run, "titan.own-queue.object-vtable-identity"), "unslid")
    device_vtable = numbered(detail(run, "titan.own-queue.device-vtable-identity"), "unslid")
    queue = numbered(detail(run, "titan.own-queue.object"), "value")
    device = numbered(detail(run, "titan.own-queue.device-backref"), "value")
    if (queue_vtable, device_vtable) != (LIVE_QUEUE_VTABLE, LIVE_DEVICE_VTABLE):
        raise ValueError("live queue/device vtable identity changed")
    if not queue or not device or numbered(detail(run, "titan.own-queue.device"), "value") != device:
        raise ValueError("live queue/device backreference changed")
    return {
        "journal_sha256": digest,
        "run_id": JOURNAL_RUN_ID,
        "queue": f"{queue:#x}",
        "queue_vtable_unslid": f"{queue_vtable:#x}",
        "device": f"{device:#x}",
        "device_vtable_unslid": f"{device_vtable:#x}",
        "device_factory_slot": f"{DEVICE_FACTORY_SLOT:#x}",
        "submit_lookup_checkpoint_observed": any(
            event["stage"].startswith("titan.command-buffers") for event in run
        ),
    }


def verify_block_fence_metaclass(agx: MachOImage) -> dict:
    verify_instructions(agx, EXPECTED_METACLASS_CHAIN)
    name = agx.read_cstring(BLOCK_FENCE_NAME_ADDRESS)
    if name != "AGXBlockFence":
        raise ValueError(f"backend metaclass name changed: {name}")
    if BLOCK_FENCE_ALLOC_SLOT != 0xfffffff007b16e48 or \
       BLOCK_FENCE_PREPARE_SLOT != 0xfffffff007b16db0:
        raise ValueError("backend metaclass/instance vtable geometry changed")
    return {
        "class_name": name,
        "metaclass_global": f"{BLOCK_FENCE_METACLASS_GLOBAL:#x}",
        "class_size": "0x158",
        "metaclass_vtable": f"{BLOCK_FENCE_META_VTABLE:#x}",
        "allocate_slot": f"{BLOCK_FENCE_ALLOC_SLOT:#x}",
        "instance_vtable": f"{BLOCK_FENCE_INSTANCE_VTABLE:#x}",
        "prepare_slot": f"{BLOCK_FENCE_PREPARE_SLOT:#x}",
        "runtime_object_identity_observed": False,
    }


def verify_block_fence_cleanup(agx: MachOImage, kernel: MachOImage,
                               process: dict[int, tuple[int, ...]]) -> dict:
    entries = validate_indirect_entries(agx.read_u64, (
        ("agx-block-fence-release", BLOCK_FENCE_RELEASE_SLOT,
         BLOCK_FENCE_RELEASE_ENCODING, BLOCK_FENCE_RELEASE),
        ("agx-block-fence-tagged-release", BLOCK_FENCE_TAGGED_RELEASE_SLOT,
         BLOCK_FENCE_TAGGED_RELEASE_ENCODING, BLOCK_FENCE_TAGGED_RELEASE),
        ("agx-block-fence-release-core", BLOCK_FENCE_RELEASE_CORE_SLOT,
         BLOCK_FENCE_RELEASE_CORE_ENCODING, BLOCK_FENCE_RELEASE_CORE),
        ("agx-block-fence-free", BLOCK_FENCE_FREE_SLOT,
         BLOCK_FENCE_FREE_ENCODING, BLOCK_FENCE_FREE),
    ))
    verify_instructions(agx, EXPECTED_BLOCK_FENCE_FREE)
    verify_instructions(kernel, EXPECTED_RELEASE_CHAIN)

    release_sites = {BACKEND_FAILURE_RELEASE, BACKEND_COMMON_RELEASE}
    normal_return_release_covered = not backend_return_without_release(process)
    if not normal_return_release_covered or not release_sites <= reachable(
        process, BACKEND_OBJECT_READY
    ):
        raise ValueError("backend object normal-return release coverage changed")

    free_graph = function_graph(agx, BLOCK_FENCE_FREE, BLOCK_FENCE_FREE_GRAPH_END)
    first_clear_required = dominates(
        free_graph, BLOCK_FENCE_FIRST_RELEASE_PATH,
        BLOCK_FENCE_FIRST_CLEAR, BLOCK_FENCE_SECOND_STAGE
    )
    second_clear_required = dominates(
        free_graph, BLOCK_FENCE_SECOND_RELEASE_PATH,
        BLOCK_FENCE_SECOND_CLEAR, BLOCK_FENCE_FINAL_STAGE
    )
    if not first_clear_required or not second_clear_required:
        raise ValueError("backend pool-pointer clearing path changed")

    return {
        "vtable_entries": entries,
        "normal_return_release_sites": [f"{address:#x}" for address in sorted(release_sites)],
        "normal_return_local_release_covered": True,
        "release_core_dispatches_virtual_free": True,
        "free_override": f"{BLOCK_FENCE_FREE:#x}",
        "first_pool_pointer_clear_dominates_second_stage": True,
        "second_pool_pointer_clear_dominates_final_stage": True,
        "pool_bitmap_restore_sites": [
            "0xfffffff0087f6158", "0xfffffff0087f6168",
            "0xfffffff0087f6214", "0xfffffff0087f6224",
        ],
        "pool_backing_clear_sites": [
            "0xfffffff0087f619c", "0xfffffff0087f6258",
        ],
        "final_release_before_selector_return_proven": False,
    }


def audit(path: pathlib.Path, journal: pathlib.Path | None = None) -> dict:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != IMAGE_SHA256:
        raise ValueError(f"kernelcache SHA-256 mismatch: {digest}")
    image = MachOImage(path, IMAGE_NAME)
    agx = MachOImage(path, AGX_IMAGE_NAME)
    verify_instructions(image, EXPECTED)
    verify_instructions(image, SUBMIT_WRAPPER_EXPECTED)
    verify_instructions(agx, EXPECTED_AGX)
    verify_instructions(agx, EXPECTED_PREPARE_RETENTION)

    backend_entries = tuple(entry for entry in AGX_PREPARSER_FACTORY_ENTRIES
                            if entry[0] in {"agx-block-fence-factory", "agx-block-fence-allocate",
                                            "agx-block-fence-prepare"})
    decoded_backend = validate_indirect_entries(agx.read_u64, backend_entries)
    if backend_entries[0][1] != DEVICE_FACTORY_SLOT:
        raise ValueError("live device factory slot no longer matches exact-image vtable")
    metaclass_chain = verify_block_fence_metaclass(agx)

    batch = function_graph(image, BATCH_START, BATCH_END)
    process = function_graph(image, PROCESS_START, PROCESS_END)
    queue_state_required = dominates(batch, BATCH_START, QUEUE_STATE_WRITE, PROCESS_CALL)
    backend_required = dominates(process, PROCESS_START, BACKEND_CALL, PARSER_CALL)
    success_gate_required = dominates(process, PROCESS_START, BACKEND_SUCCESS_GATE, PARSER_CALL)
    failure_skips_parser = PARSER_CALL not in reachable(process, 0xfffffff009f497a8)
    if not (queue_state_required and backend_required and success_gate_required and failure_skips_parser):
        raise ValueError("pre-parser dominance changed")

    prepare = function_graph(agx, PREPARE_START, PREPARE_END)
    state_write_required = dominates(prepare, PREPARE_START, PREPARE_STATE_WRITE, PREPARE_RETURN)
    indirect_call_required = dominates(prepare, PREPARE_START, PREPARE_INDIRECT_CALL, PREPARE_RETURN)
    reachable_pool_writes = all(address in reachable(prepare, PREPARE_START)
                                for address in PREPARE_POOL_WRITES)
    if not (state_write_required and indirect_call_required and reachable_pool_writes):
        raise ValueError("candidate AGX backend effects changed")
    retention_path = path_through(prepare, PREPARE_START, PREPARE_RETURN,
                                  PREPARE_RETENTION_PATH, PREPARE_ROLLBACK_WRITES)
    if retention_path is None:
        raise ValueError("candidate pool-retention control-flow path changed")
    base_initializer = verify_prepare_base_slot(agx, image)
    kernel = MachOImage(path, KERNEL_IMAGE_NAME)
    backend_cleanup = verify_block_fence_cleanup(agx, kernel, process)
    base_helper = verify_base_init_helper(image, kernel)
    queue_packet_route = verify_queue_packet_route(agx, image)
    command_buffer_callback = verify_command_buffer_callback(agx)
    firmware_callback_candidate = verify_firmware_callback_candidate(agx, kernel)

    result = {
        "build": "23A355",
        "image_sha256": digest,
        "mode": "offline-static-normal-return-paths",
        "batch_instruction_count": len(batch),
        "process_instruction_count": len(process),
        "queue_state_write_dominates_process_call": queue_state_required,
        "backend_call_dominates_parser_call": backend_required,
        "backend_success_gate_dominates_parser_call": success_gate_required,
        "backend_failure_branch_skips_parser": failure_skips_parser,
        "candidate_agx_backend": {
            "static_vtable_entries": decoded_backend,
            "static_metaclass_chain": metaclass_chain,
            "prepare_instruction_count": len(prepare),
            "object_state_write_dominates_return": state_write_required,
            "indirect_call_dominates_return": indirect_call_required,
            "statically_resolved_base_initializer": base_initializer,
            "statically_resolved_base_helper": base_helper,
            "reachable_conditional_pool_write_sites": [f"{address:#x}" for address in PREPARE_POOL_WRITES],
            "possible_pool_reservation_return_without_local_rollback": True,
            "retention_path_sites": [f"{address:#x}" for address in PREPARE_RETENTION_PATH],
            "excluded_local_rollback_writes": [f"{address:#x}" for address in PREPARE_ROLLBACK_WRITES],
            "runtime_object_identity_observed": False,
            "cleanup_contract": backend_cleanup,
            "complete_effects_bounded": False,
        },
        "observed_queue_packet_route": queue_packet_route,
        "static_command_buffer_callback": command_buffer_callback,
        "static_firmware_callback_candidate": firmware_callback_candidate,
        "parser_only_selector25_device_test_bounded": False,
        "limits": "Static submit route plus observed queue/device identity only; local release and the final free routine are pinned, but final deallocation timing and complete packet effects are not observed.",
    }
    if journal is not None:
        result["observed_queue_static_submit_link"] = verify_live_queue_link(journal.read_bytes())
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernelcache", type=pathlib.Path)
    parser.add_argument("--journal", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    result = audit(args.kernelcache, args.journal)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
