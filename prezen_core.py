#####################################################################################################
#####################################################################################################
#####################################################################################################
# Author: Kaya Ercihan
# Version: 2.2.0
# Description: Parse and decode pre-Zen AMD microcode updates (K8/K10 cores, families 0x0F-0x12)
# Self-containment: header, match registers, triad de-obfuscation, micro-op and sequence-word decoding
# License: GPL-3.0-only
#
# The triad de-obfuscation (deobfuscate_triad / obfuscate_triad) is a port of
# amd-ucode-patch src/amd_ucode_patch/utils/triad_obfuscation.py
# (https://github.com/amd-zenith/amd-ucode-patch, SPDX-License-Identifier: GPL-2.0-or-later).
# The field layout, register names, condition codes and mnemonics follow the GhidraAmdMicrocode
# SLEIGH specification AMDuCodePreZen.sinc so both tools render the same text.
#####################################################################################################
#####################################################################################################
#####################################################################################################
"""Pre-Zen (K8/K10) AMD microcode patch decoding without any Binary Ninja dependency.

Patch layout (file offsets):
    0x00  u32 date (BCD 0xMMDDYYYY)
    0x04  u32 patch_level          family = 0xF + (patch_level >> 24), two K8 anomalies corrected
    0x08  u16 loader_id            0x8000 (K8/K10), 0x8003 (family 0x12)
    0x0A  u8  op_triad_count
    0x0B  u8  init_flag
    0x0C  u32 op_triad_checksum    little-endian u32 word sum of the triad array
    0x10  u32 nb_dev_id
    0x14  4 bytes unknown
    0x18  u16 cpuid                equivalence id (family/model/stepping nibbles)
    0x1A  6 bytes unknown
    0x20  u32 match_register[8]    low 16 bits = ROM triad address, 0xFFFF = unused
    0x40  triad[op_triad_count]    28 bytes each: 3 x u64 micro-op + u32 sequence word (obfuscated)

Patch RAM starts at triad address 0xC00; triad T lives at byte offset T * 28 and match register i
redirects ROM triad match_register[i] to patch triad 0xC00 + 2 * i.
"""
from __future__ import annotations

import hashlib
import struct
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

CORE_VERSION = "2.2.0"

#####################################################################################################
# Geometry
#####################################################################################################

PREZEN_HEADER_SIZE = 32
PREZEN_MATCH_OFFSET = 32
PREZEN_MATCH_COUNT = 8
PREZEN_MATCH_SIZE = PREZEN_MATCH_COUNT * 4
PREZEN_TRIADS_OFFSET = PREZEN_MATCH_OFFSET + PREZEN_MATCH_SIZE
PREZEN_TRIAD_SIZE = 28
PREZEN_WORDS_PER_TRIAD = 7
PREZEN_OPS_PER_TRIAD = 3
PREZEN_OP_SIZE = 8
PREZEN_SEQ_SIZE = 4
PREZEN_SEQ_OFFSET = PREZEN_OPS_PER_TRIAD * PREZEN_OP_SIZE
PREZEN_MAX_TRIADS = 255
PREZEN_PATCH_RAM_TRIAD = 0xC00
PREZEN_PATCH_RAM_BYTE_OFFSET = PREZEN_PATCH_RAM_TRIAD * PREZEN_TRIAD_SIZE
PREZEN_ROM_TRIADS = 0x1000
PREZEN_MATCH_UNUSED = 0xFFFF
PREZEN_MAX_PATCH_SIZE = PREZEN_TRIADS_OFFSET + PREZEN_MAX_TRIADS * PREZEN_TRIAD_SIZE

PREZEN_LOADER_IDS: Dict[int, str] = {0x8000: "K8/K10", 0x8003: "family 0x12"}
PREZEN_FAMILIES: Tuple[int, ...] = (0x0F, 0x10, 0x11, 0x12)
PREZEN_MICROARCH: Dict[int, str] = {0x0F: "K8", 0x10: "K10", 0x11: "K8", 0x12: "K10"}
PREZEN_FAMILY_NAMES: Dict[int, str] = {0x0F: "K8", 0x10: "K10", 0x11: "Turion/Griffin", 0x12: "Fusion/Llano"}
# Two malformed K8 patch levels whose extended family nibble is wrong (would read as 0x11 / 0xCF)
PREZEN_PATCH_LEVEL_ANOMALIES: Dict[int, int] = {0x02000008: 0x00, 0xC0012102: 0x00}

_MASK32 = 0xFFFFFFFF
_MASK64 = 0xFFFFFFFFFFFFFFFF

#####################################################################################################
# ISA tables (AMDuCodePreZen.sinc)
#####################################################################################################

PREZEN_REGISTERS: Tuple[str, ...] = tuple(
    ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
    + [f"t{i}d" for i in range(1, 33)]
    + ["regmd4", "regmd5", "t35d", "regmd7", "regmd6", "t38d", "t39d", "t40d"]
    + [f"t{i}d" for i in range(41, 49)]
    + ["pcd"]
    + [f"t{i}d" for i in range(50, 57)]
)

PREZEN_CONDITION_CODES: Tuple[str, ...] = (
    "ccF", "ccT", "ECF", "nECF", "EZF", "nEZF", "SZnZF", "nSZnZF",
    "MSTRZ", "nMSTRZ", "STRZ", "nSTRZ", "MSTRC", "nMSTRC", "STRZnZF", "nSTRZnZF",
    "OF", "nOF", "CF", "nCF", "ZF", "nZF", "CvZF", "nCvZF",
    "SF", "nSF", "PF", "nPF", "SxOF", "nSxOF", "SxOvZF", "nSxOvZF",
)

PREZEN_OPERATION_NAMES: Dict[int, str] = {
    0x000: "add", 0x001: "or", 0x002: "adc", 0x003: "sbb", 0x004: "and", 0x005: "sub",
    0x006: "xor", 0x007: "cmp", 0x008: "test",
    0x010: "rll", 0x011: "rrl", 0x014: "sll", 0x015: "srl",
    0x040: "writepc", 0x060: "mov",
    0x070: "mul", 0x071: "imul", 0x072: "muleh", 0x073: "mulel", 0x07A: "div1", 0x07C: "div2",
    0x07F: "ld", 0x150: "st", 0x18D: "lea", 0x1C0: "bswap", 0x1F5: "not", 0x1FF: "crash",
}

PREZEN_SIZE_SUFFIX: Dict[int, str] = {0: "b", 1: "w", 2: "d", 3: "q"}
PREZEN_SIZE_BYTES: Dict[int, int] = {0: 1, 1: 2, 2: 4, 3: 8}
PREZEN_JCC_HI4 = 5

PREZEN_SEQ_ACTIONS: Dict[int, str] = {0: "next", 1: "complete", 2: "branch"}


#####################################################################################################
# Bit helpers and triad (de)obfuscation
#####################################################################################################


def _bits(value: int, low: int, high: int) -> int:
    width = high - low + 1
    return (value >> low) & ((1 << width) - 1)


def _ror32(value: int, count: int) -> int:
    count &= 31
    value &= _MASK32
    if count == 0:
        return value
    return ((value >> count) | (value << (32 - count))) & _MASK32


def _rol32(value: int, count: int) -> int:
    return _ror32(value, -count)


def _deobfuscate_word(raw_le_bytes: bytes, position: int) -> int:
    """Logical 32-bit word for on-disk word number ``position`` (triad_index * 7 + word)."""
    return _ror32(int.from_bytes(raw_le_bytes, "little"), position) ^ _MASK32


def deobfuscate_triad(data: bytes, index: int) -> Tuple[List[int], int]:
    """Return ``(ops, sequence_word)`` for the 28-byte triad at array position ``index``."""
    if len(data) < PREZEN_TRIAD_SIZE:
        raise ValueError(f"a triad is {PREZEN_TRIAD_SIZE} bytes, got {len(data)}")
    base = index * PREZEN_WORDS_PER_TRIAD
    words = [_deobfuscate_word(data[4 * p:4 * p + 4], base + p) for p in range(PREZEN_WORDS_PER_TRIAD)]
    for k in range(0, 6, 2):
        words[k], words[k + 1] = words[k + 1], words[k]
    ops = [(words[2 * i] << 32) | words[2 * i + 1] for i in range(PREZEN_OPS_PER_TRIAD)]
    return ops, words[6]


def obfuscate_triad(ops: Sequence[int], sequence_word: int, index: int) -> bytes:
    """Inverse of :func:`deobfuscate_triad`."""
    if len(ops) != PREZEN_OPS_PER_TRIAD:
        raise ValueError(f"a triad holds three micro-ops, got {len(ops)}")
    words: List[int] = []
    for op in ops:
        words.append(((op >> 32) & _MASK32) ^ _MASK32)
        words.append((op & _MASK32) ^ _MASK32)
    words.append((sequence_word & _MASK32) ^ _MASK32)
    for k in range(0, 6, 2):
        words[k], words[k + 1] = words[k + 1], words[k]
    base = index * PREZEN_WORDS_PER_TRIAD
    out = bytearray()
    for p in range(PREZEN_WORDS_PER_TRIAD):
        out += _rol32(words[p], base + p).to_bytes(4, "little")
    return bytes(out)


def deobfuscate_op_word(data: bytes, triad_index: int, slot: int) -> int:
    """Logical 64-bit micro-op ``slot`` (0..2) from its own 8 on-disk bytes.

    Op ``slot`` only depends on on-disk words ``2*slot`` and ``2*slot+1`` of its triad, so a
    disassembler can decode one micro-op from the bytes at its own address.
    """
    if len(data) < PREZEN_OP_SIZE:
        raise ValueError(f"a micro-op is {PREZEN_OP_SIZE} bytes, got {len(data)}")
    if not 0 <= slot < PREZEN_OPS_PER_TRIAD:
        raise ValueError(f"slot must be 0..2, got {slot}")
    base = triad_index * PREZEN_WORDS_PER_TRIAD + 2 * slot
    low = _deobfuscate_word(data[0:4], base)
    high = _deobfuscate_word(data[4:8], base + 1)
    return (high << 32) | low


def deobfuscate_sequence_word(data: bytes, triad_index: int) -> int:
    if len(data) < PREZEN_SEQ_SIZE:
        raise ValueError(f"a sequence word is {PREZEN_SEQ_SIZE} bytes, got {len(data)}")
    return _deobfuscate_word(data[0:4], triad_index * PREZEN_WORDS_PER_TRIAD + 6)


def pack_triad(ops: Sequence[int], sequence_word: int) -> bytes:
    """Little-endian logical triad bytes (3 x u64 + u32), the form hashed by the golden corpus."""
    return struct.pack("<3QI", *(op & _MASK64 for op in ops), sequence_word & _MASK32)


#####################################################################################################
# Header and match registers
#####################################################################################################


def prezen_family_from_patch_level(patch_level: int) -> Tuple[int, bool]:
    """Return ``(family, corrected)`` for a patch level; corrected marks a known K8 anomaly."""
    patch_level &= _MASK32
    if patch_level in PREZEN_PATCH_LEVEL_ANOMALIES:
        return 0xF + PREZEN_PATCH_LEVEL_ANOMALIES[patch_level], True
    return 0xF + (patch_level >> 24), False


def _bcd_byte(value: int) -> Optional[int]:
    high, low = value >> 4, value & 0xF
    if high > 9 or low > 9:
        return None
    return high * 10 + low


def prezen_date_iso(date: int) -> Optional[str]:
    """Decode the BCD date word 0xMMDDYYYY; ``None`` when any field is out of range."""
    month = _bcd_byte((date >> 24) & 0xFF)
    day = _bcd_byte((date >> 16) & 0xFF)
    year_hi = _bcd_byte((date >> 8) & 0xFF)
    year_lo = _bcd_byte(date & 0xFF)
    if None in (month, day, year_hi, year_lo):
        return None
    year = year_hi * 100 + year_lo
    if not (1990 <= year <= 2099 and 1 <= month <= 12 and 1 <= day <= 31):
        return None
    return f"{year:04d}-{month:02d}-{day:02d}"


@dataclass(frozen=True)
class PreZenHeader:
    date: int
    patch_level: int
    loader_id: int
    op_triad_count: int
    init_flag: int
    op_triad_checksum: int
    nb_dev_id: int
    unknown0: bytes
    cpuid: int
    unknown1: bytes

    @property
    def family(self) -> int:
        return prezen_family_from_patch_level(self.patch_level)[0]

    @property
    def patch_level_corrected(self) -> bool:
        return prezen_family_from_patch_level(self.patch_level)[1]

    @property
    def microarch(self) -> str:
        return PREZEN_MICROARCH.get(self.family, "unknown")

    @property
    def family_name(self) -> str:
        return PREZEN_FAMILY_NAMES.get(self.family, f"family 0x{self.family:02x}")

    @property
    def loader_name(self) -> str:
        return PREZEN_LOADER_IDS.get(self.loader_id, "unknown")

    @property
    def cpuid_family_model_stepping(self) -> Tuple[int, int, int]:
        value = self.cpuid & 0xFFFF
        stepping = value & 0xF
        model = (((value >> 8) & 0xF) << 4) | ((value >> 4) & 0xF)
        family = 0xF + ((value >> 12) & 0xF)
        return family, model, stepping

    @property
    def expected_size(self) -> int:
        return PREZEN_TRIADS_OFFSET + PREZEN_TRIAD_SIZE * self.op_triad_count

    @property
    def date_iso(self) -> Optional[str]:
        return prezen_date_iso(self.date)


def parse_prezen_header(data: bytes, base: int = 0) -> PreZenHeader:
    if base < 0:
        raise ValueError("base must be non-negative")
    if len(data) < base + PREZEN_HEADER_SIZE:
        raise ValueError(
            f"Need at least 0x{PREZEN_HEADER_SIZE:x} header bytes at base 0x{base:x}; "
            f"only 0x{max(0, len(data) - base):x} available"
        )
    (date, patch_level, loader_id, count, init_flag, checksum, nb_dev_id,
     unknown0, cpuid, unknown1) = struct.unpack_from("<IIHBBII4sH6s", data, base)
    return PreZenHeader(
        date=date,
        patch_level=patch_level,
        loader_id=loader_id,
        op_triad_count=count,
        init_flag=init_flag,
        op_triad_checksum=checksum,
        nb_dev_id=nb_dev_id,
        unknown0=unknown0,
        cpuid=cpuid,
        unknown1=unknown1,
    )


@dataclass(frozen=True)
class PreZenMatchRegister:
    index: int
    raw: int

    @property
    def rom_address(self) -> int:
        return self.raw & 0xFFFF

    @property
    def upper(self) -> int:
        return (self.raw >> 16) & 0xFFFF

    @property
    def used(self) -> bool:
        return self.rom_address != PREZEN_MATCH_UNUSED

    @property
    def handler_triad(self) -> int:
        return PREZEN_PATCH_RAM_TRIAD + 2 * self.index

    @property
    def text(self) -> str:
        if not self.used:
            return f".match_reg {self.index} unused"
        line = f".match_reg {self.index} 0x{self.rom_address:04x} -> uc_{self.handler_triad:04x}"
        if self.upper:
            line += f" ; raw=0x{self.raw:08x}"
        return line


def parse_prezen_match_registers(data: bytes, base: int = 0) -> Tuple[PreZenMatchRegister, ...]:
    offset = base + PREZEN_MATCH_OFFSET
    if len(data) < offset + PREZEN_MATCH_SIZE:
        raise ValueError("Need the 8 match registers at patch +0x20")
    values = struct.unpack_from(f"<{PREZEN_MATCH_COUNT}I", data, offset)
    return tuple(PreZenMatchRegister(index, value) for index, value in enumerate(values))


def prezen_checksum(triad_bytes: bytes) -> int:
    """Little-endian u32 word sum of the triad array, truncated to 32 bits."""
    usable = len(triad_bytes) - (len(triad_bytes) % 4)
    words = struct.unpack_from(f"<{usable // 4}I", triad_bytes, 0)
    return sum(words) & _MASK32


#####################################################################################################
# Micro-op and sequence word decoding
#####################################################################################################


def prezen_triad_byte_offset(triad_address: int) -> int:
    return triad_address * PREZEN_TRIAD_SIZE


def prezen_branch_target(triad_address: int, triad_count: int) -> Optional[int]:
    """Byte offset (relative to the microcode address space) of a patch-RAM triad, else ``None``."""
    if PREZEN_PATCH_RAM_TRIAD <= triad_address < PREZEN_PATCH_RAM_TRIAD + triad_count:
        return prezen_triad_byte_offset(triad_address)
    return None


@dataclass(frozen=True)
class DecodedPreZenOp:
    word: int
    operation: int
    hi4: int
    cc: int
    swap: int
    three_op: int
    dst: int
    pzs: int
    cflag: int
    op_class: int
    seg: int
    sizezx: int
    size: int
    src1: int
    regmode: int
    src2reg: int
    imm: int
    braddr: int

    @property
    def is_jcc(self) -> bool:
        return self.hi4 == PREZEN_JCC_HI4

    @property
    def known(self) -> bool:
        return not self.is_jcc and self.operation in PREZEN_OPERATION_NAMES

    @property
    def mnemonic(self) -> str:
        if self.is_jcc:
            return "jcc"
        return PREZEN_OPERATION_NAMES.get(self.operation, "unk_op")

    @property
    def size_suffix(self) -> str:
        return PREZEN_SIZE_SUFFIX[self.size]

    @property
    def size_bytes(self) -> int:
        return PREZEN_SIZE_BYTES[self.size]

    @property
    def display_mnemonic(self) -> str:
        if self.is_jcc:
            return "jcc"
        return f"{self.mnemonic}.{self.size_suffix}"

    @property
    def dst_name(self) -> str:
        return PREZEN_REGISTERS[self.dst]

    @property
    def src1_name(self) -> str:
        return PREZEN_REGISTERS[self.src1]

    @property
    def src2_name(self) -> str:
        return PREZEN_REGISTERS[self.src2reg]

    @property
    def src_is_register(self) -> bool:
        return self.regmode == 1

    @property
    def src_text(self) -> str:
        return self.src2_name if self.src_is_register else f"0x{self.imm:x}"

    @property
    def cc_name(self) -> str:
        return PREZEN_CONDITION_CODES[self.cc]

    @property
    def branch_byte_offset(self) -> int:
        return prezen_triad_byte_offset(self.braddr)

    def operand_texts(self) -> List[str]:
        if self.is_jcc:
            return [self.cc_name, f"0x{self.branch_byte_offset:x}"]
        operands: List[str] = []
        if not self.known:
            operands.append(f"0x{self.operation:x}")
        operands.append(self.dst_name)
        if self.three_op:
            operands.append(self.src1_name)
        operands.append(self.src_text)
        return operands

    def text(self) -> str:
        return f"{self.display_mnemonic} " + ", ".join(self.operand_texts())


def decode_prezen_op(word: int) -> DecodedPreZenOp:
    word &= _MASK64
    return DecodedPreZenOp(
        word=word,
        operation=_bits(word, 54, 62),
        hi4=_bits(word, 59, 62),
        cc=_bits(word, 54, 58),
        swap=_bits(word, 53, 53),
        three_op=_bits(word, 52, 52),
        dst=_bits(word, 46, 51),
        pzs=_bits(word, 42, 42),
        cflag=_bits(word, 41, 41),
        op_class=_bits(word, 37, 39),
        seg=_bits(word, 33, 36),
        sizezx=_bits(word, 32, 32),
        size=_bits(word, 30, 31),
        src1=_bits(word, 24, 29),
        regmode=_bits(word, 23, 23),
        src2reg=_bits(word, 9, 14),
        imm=_bits(word, 0, 15),
        braddr=_bits(word, 0, 11),
    )


@dataclass(frozen=True)
class DecodedPreZenSequence:
    word: int
    action_code: int
    action: str
    target: Optional[int]

    @property
    def target_byte_offset(self) -> Optional[int]:
        if self.target is None:
            return None
        return prezen_triad_byte_offset(self.target)

    @property
    def text(self) -> str:
        if self.action == "branch":
            return f"sw_branch 0x{self.target_byte_offset:x}"
        if self.action == "complete":
            return "sw_complete"
        if self.action == "next":
            return "sw_next"
        return f"sw_raw 0x{self.word:08x}"


def decode_prezen_sequence(word: int) -> DecodedPreZenSequence:
    word &= _MASK32
    action_code = _bits(word, 14, 16)
    action = PREZEN_SEQ_ACTIONS.get(action_code, "raw")
    target = _bits(word, 0, 11) if action == "branch" else None
    return DecodedPreZenSequence(word=word, action_code=action_code, action=action, target=target)


@dataclass(frozen=True)
class DecodedPreZenTriad:
    index: int
    raw: bytes
    ops: Tuple[DecodedPreZenOp, ...]
    sequence: DecodedPreZenSequence

    @property
    def address(self) -> int:
        return PREZEN_PATCH_RAM_TRIAD + self.index

    @property
    def label(self) -> str:
        return f"uc_{self.address:04x}"

    @property
    def decoded_bytes(self) -> bytes:
        return pack_triad([op.word for op in self.ops], self.sequence.word)

    @property
    def raw_words(self) -> Tuple[int, ...]:
        return struct.unpack(f"<{PREZEN_WORDS_PER_TRIAD}I", self.raw)


def decode_prezen_triad(raw: bytes, index: int) -> DecodedPreZenTriad:
    ops, sequence_word = deobfuscate_triad(raw, index)
    return DecodedPreZenTriad(
        index=index,
        raw=bytes(raw[:PREZEN_TRIAD_SIZE]),
        ops=tuple(decode_prezen_op(op) for op in ops),
        sequence=decode_prezen_sequence(sequence_word),
    )


#####################################################################################################
# Whole-patch parsing and detection
#####################################################################################################


@dataclass(frozen=True)
class ParsedPreZenPatch:
    header: PreZenHeader
    match_registers: Tuple[PreZenMatchRegister, ...]
    triads: Tuple[DecodedPreZenTriad, ...]
    computed_checksum: int
    available: int
    warnings: Tuple[str, ...]

    @property
    def complete(self) -> bool:
        return len(self.triads) == self.header.op_triad_count

    @property
    def checksum_ok(self) -> bool:
        return self.complete and self.computed_checksum == self.header.op_triad_checksum

    @property
    def triad_count(self) -> int:
        return len(self.triads)

    @property
    def mapped_size(self) -> int:
        return self.triad_count * PREZEN_TRIAD_SIZE

    @property
    def decoded_bytes(self) -> bytes:
        return b"".join(triad.decoded_bytes for triad in self.triads)

    @property
    def decoded_sha256(self) -> str:
        return hashlib.sha256(self.decoded_bytes).hexdigest()

    def branch_target(self, triad_address: int) -> Optional[int]:
        return prezen_branch_target(triad_address, self.triad_count)


def parse_prezen_patch(data: bytes, base: int = 0) -> ParsedPreZenPatch:
    header = parse_prezen_header(data, base)
    if header.op_triad_count == 0:
        raise ValueError("The header announces zero micro-op triads")
    registers = parse_prezen_match_registers(data, base)
    available = len(data) - base
    warnings: List[str] = []

    triad_region = data[base + PREZEN_TRIADS_OFFSET:base + header.expected_size]
    complete_count = min(header.op_triad_count, len(triad_region) // PREZEN_TRIAD_SIZE)
    if complete_count < header.op_triad_count:
        warnings.append(
            f"truncated: {complete_count}/{header.op_triad_count} triads available "
            f"(0x{available:x} of 0x{header.expected_size:x} bytes)"
        )
    triads = tuple(
        decode_prezen_triad(triad_region[t * PREZEN_TRIAD_SIZE:(t + 1) * PREZEN_TRIAD_SIZE], t)
        for t in range(complete_count)
    )
    computed = prezen_checksum(triad_region[:complete_count * PREZEN_TRIAD_SIZE])
    if complete_count == header.op_triad_count and computed != header.op_triad_checksum:
        warnings.append(
            f"checksum mismatch: header 0x{header.op_triad_checksum:08x}, computed 0x{computed:08x}"
        )
    if header.loader_id not in PREZEN_LOADER_IDS:
        warnings.append(f"unexpected loader id 0x{header.loader_id:04x}")
    if header.family not in PREZEN_FAMILIES:
        warnings.append(f"family 0x{header.family:02x} is outside the K8/K10 range")
    for register in registers:
        if register.used and register.handler_triad >= PREZEN_PATCH_RAM_TRIAD + header.op_triad_count:
            warnings.append(
                f"match register {register.index} handler uc_{register.handler_triad:04x} lies beyond "
                f"the last triad"
            )
    return ParsedPreZenPatch(
        header=header,
        match_registers=registers,
        triads=triads,
        computed_checksum=computed,
        available=available,
        warnings=tuple(warnings),
    )


@dataclass(frozen=True)
class PreZenDetection:
    matched: bool
    header: Optional[PreZenHeader]
    confidence: str
    reason: str


def detect_prezen(data: bytes, base: int = 0) -> PreZenDetection:
    try:
        header = parse_prezen_header(data, base)
    except ValueError as exc:
        return PreZenDetection(False, None, "none", str(exc))
    if header.loader_id not in PREZEN_LOADER_IDS:
        return PreZenDetection(
            False, header, "none",
            f"loader id 0x{header.loader_id:04x} is not a pre-Zen loader (0x8000/0x8003)",
        )
    family = header.family
    if family not in PREZEN_FAMILIES:
        cpuid_family = header.cpuid_family_model_stepping[0]
        if cpuid_family not in PREZEN_FAMILIES:
            return PreZenDetection(
                False, header, "none",
                f"patch level family 0x{family:02x} and cpuid family 0x{cpuid_family:02x} are not K8/K10",
            )
        family = cpuid_family
    if header.op_triad_count == 0:
        return PreZenDetection(False, header, "none", "header announces zero triads")
    available = len(data) - base
    description = (
        f"loader 0x{header.loader_id:04x}, family 0x{family:02x} ({PREZEN_MICROARCH.get(family, '?')}), "
        f"{header.op_triad_count} triads"
    )
    if available < header.expected_size:
        return PreZenDetection(
            True, header, "medium",
            f"{description}; only 0x{available:x}/0x{header.expected_size:x} bytes are available",
        )
    return PreZenDetection(True, header, "high", description)


#####################################################################################################
# Text listing
#####################################################################################################


def render_prezen_header_lines(header: PreZenHeader) -> List[str]:
    family, model, stepping = header.cpuid_family_model_stepping
    corrected = " (corrected K8 anomaly)" if header.patch_level_corrected else ""
    return [
        "; Header",
        f".date 0x{header.date:08x}" + (f" ; {header.date_iso}" if header.date_iso else " ; invalid BCD date"),
        f".patch_level 0x{header.patch_level:08x} ; family 0x{header.family:02x} {header.microarch}{corrected}",
        f".loader_id 0x{header.loader_id:04x} ; {header.loader_name}",
        f".op_triad_count {header.op_triad_count}",
        f".init_flag 0x{header.init_flag:02x}",
        f".op_triad_checksum 0x{header.op_triad_checksum:08x}",
        f".nb_dev_id 0x{header.nb_dev_id:08x}",
        f".cpuid 0x{header.cpuid:04x} ; family 0x{family:02x} model 0x{model:02x} stepping {stepping}",
    ]


def render_prezen_listing(parsed: ParsedPreZenPatch) -> List[str]:
    header = parsed.header
    lines = [
        f"; Zenella {CORE_VERSION} / pre-Zen {header.microarch} (family 0x{header.family:02x}) triad listing",
        "",
    ]
    lines.extend(render_prezen_header_lines(header))
    checksum_text = "OK" if parsed.checksum_ok else f"MISMATCH (computed 0x{parsed.computed_checksum:08x})"
    lines.append(f"; checksum {checksum_text}; {parsed.triad_count}/{header.op_triad_count} triads decoded")
    for warning in parsed.warnings:
        lines.append(f"; warning: {warning}")
    lines.extend(["", "; Match Registers"])
    lines.extend(register.text for register in parsed.match_registers)
    lines.extend(["", "; Triads (patch RAM from uc_0c00; byte address = triad * 28)"])
    for triad in parsed.triads:
        raw_words = " ".join(f"{word:08x}" for word in triad.raw_words)
        lines.append("")
        lines.append(f"{triad.label}: ; byte 0x{prezen_triad_byte_offset(triad.address):x} raw {raw_words}")
        for slot, op in enumerate(triad.ops):
            lines.append(f"    {op.text():<40} ; op{slot} 0x{op.word:016x}")
        lines.append(f"    {triad.sequence.text:<40} ; seq 0x{triad.sequence.word:08x}")
    return lines


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1 or args[0] in ("-h", "--help"):
        print("usage: python3 prezen_core.py <patch.bin>", file=sys.stderr)
        return 2
    with open(args[0], "rb") as handle:
        blob = handle.read()
    detection = detect_prezen(blob)
    if not detection.matched:
        print(f"not a pre-Zen K8/K10 patch: {detection.reason}", file=sys.stderr)
        return 1
    print("\n".join(render_prezen_listing(parse_prezen_patch(blob))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
