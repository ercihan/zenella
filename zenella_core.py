#####################################################################################################
#####################################################################################################
#####################################################################################################
# Author: Kaya Ercihan
# Version: 2.2.0
# Description: Decode Zen1 and Zen2 microcode and provide shared AMD update format helpers
# Self-containment: pure Python decoder with no Binary Ninja dependency
# License: GPL-3.0-only
#####################################################################################################
#####################################################################################################
#####################################################################################################
"""Pure-Python decoder and format helpers for Zenella.

The Zen 1 / Zen 2 instruction layout implemented here is derived from the
ZenUtils architecture specification. This module deliberately has no Binary
Ninja dependency so its decoder can be regression-tested outside Binary Ninja.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import ast
from functools import lru_cache
from pathlib import Path
from collections import Counter
from datetime import date
import hashlib
import math
import struct
from typing import Dict, Iterable, Optional, Sequence, Tuple


#####################################################################################################
# Shared update container offsets
#####################################################################################################
CORE_VERSION = "2.2.0"

HEADER_OFFSET = 0x0000
HEADER_SIZE = 0x0020
SIGNATURE_OFFSET = 0x0020
SIGNATURE_SIZE = 0x0100
MODULUS_OFFSET = 0x0120
MODULUS_SIZE = 0x0100
CHECK_OFFSET = 0x0220
CHECK_SIZE = 0x0100
OPTIONS_OFFSET = 0x0320
OPTIONS_SIZE = 0x0004
SECONDARY_LOADER_OFFSET = OPTIONS_OFFSET + 2  # LE16 research-profile selector
REVISION_COPY_OFFSET = 0x0324
REVISION_COPY_SIZE = 0x0004

#####################################################################################################
# Zen1 and Zen2 update layout from ZenUtils
#####################################################################################################
ZEN12_MATCH_OFFSET = 0x0328
ZEN12_MATCH_ENTRY_COUNT = 22
ZEN12_MATCH_ENTRY_SIZE = 4
ZEN12_MATCH_SIZE = ZEN12_MATCH_ENTRY_COUNT * ZEN12_MATCH_ENTRY_SIZE  # 0x58
ZEN12_PAYLOAD_OFFSET = 0x0380
ZEN12_PACKAGE_COUNT = 64
ZEN12_INSTRUCTIONS_PER_PACKAGE = 4
ZEN12_INSTRUCTION_SIZE = 8
ZEN12_SEQUENCE_SIZE = 4
ZEN12_PACKAGE_SIZE = (
    ZEN12_INSTRUCTIONS_PER_PACKAGE * ZEN12_INSTRUCTION_SIZE
    + ZEN12_SEQUENCE_SIZE
)  # 0x24
ZEN12_PAYLOAD_SIZE = ZEN12_PACKAGE_COUNT * ZEN12_PACKAGE_SIZE  # 0x900
ZEN12_PATCH_SIZE = ZEN12_PAYLOAD_OFFSET + ZEN12_PAYLOAD_SIZE  # 0xc80
ZEN12_ROM_START = 0x1FC0

#####################################################################################################
# Zen5: upstream container geometry and separately identified sample geometry.
# Source: google/security-research, pocs/cpus/entrysign/zentool/ucode.{c,h},
# reviewed 2026-09-13. Upstream reads 60 dwords, then 370 packed 36-byte records
# for 0x8010/0x8015. This is NOT proof that all 370 records are instructions.
#####################################################################################################
EXTENDED_HEADER_SIZE = REVISION_COPY_OFFSET + REVISION_COPY_SIZE  # 0x328
ZEN5_MATCH_OFFSET = EXTENDED_HEADER_SIZE
ZEN5_MATCH_ENTRY_COUNT = 60             # upstream serialized DWORD count
ZEN5_MATCH_SIZE = ZEN5_MATCH_ENTRY_COUNT * 4  # 0xf0; no invented mask split
ZEN5_PATCH_SIZE = 0x3820
ZEN5_RECORD_SIZE = 8
ZEN5_UOPS_PER_QUAD = 4
ZEN5_SEQUENCE_SIZE = 4
ZEN5_OPQUAD_SIZE = 36
ZENTOOL_ZEN5_OPQUAD_OFFSET = ZEN5_MATCH_OFFSET + ZEN5_MATCH_SIZE  # 0x418
ZENTOOL_ZEN5_OPQUAD_COUNT = 370
ZENTOOL_ZEN5_OPQUAD_REGION_SIZE = 370 * ZEN5_OPQUAD_SIZE

# Confirmed Zen5c / loader 0x8015 register geometry: the register area at 0x328
# holds exactly 31 match DWORDs followed by 31 mask DWORDs (62 DWORDs, 0xF8
# bytes), so the op-quad body starts at 0x328 + 4*62 = 0x420. This is the
# default geometry applied by parse_zen5_patch for loader 0x8015; the body runs
# from 0x420 up to the trailing zero padding (zen5_manual_fit).
ZEN5_8015_REGISTER_SPLIT = (31, 31)

# Empirical 0x8015 / processor-revision 0xB110 profile checked against both
# supplied revisions 0x0B10104E and 0x0B101054. It is separate from the
# upstream loader table: 0x420 holds the first nonzero, in-phase quad, and
# 0x2820 begins an identical 4 KiB table-like region in both samples.
# The loader selects geometry; content checks below are diagnostics only.
# Figure 3 of Google's "Zen and the Art of Microcode Hacking" shows a
# 0x8004 example with 8 option/revision bytes, 10 match DWORDs and 12 mask
# DWORDs in 0x320..0x380. The first half INCLUDES those eight header bytes.
# For 0x8015 the 0x328..0x420 register area is confirmed as 31 match DWORDs
# then 31 mask DWORDs (ZEN5_8015_REGISTER_SPLIT); the earlier 30/32 reading
# of the diagram scaling was a research hypothesis and is superseded.
# PREFIX constants remain deprecated API aliases, never separate display fields.
ZEN5_PREFIX_OFFSET = ZENTOOL_ZEN5_OPQUAD_OFFSET
ZEN5_PREFIX_SIZE = 8
ZEN5_OPQUAD_OFFSET = 0x420
ZEN5_OPQUAD_COUNT = 256
ZEN5_OPQUAD_REGION_SIZE = ZEN5_OPQUAD_COUNT * ZEN5_OPQUAD_SIZE  # 0x2400
ZEN5_AUX_OFFSET = ZEN5_OPQUAD_OFFSET + ZEN5_OPQUAD_REGION_SIZE  # 0x2820
ZEN5_AUX_SIZE = ZEN5_PATCH_SIZE - ZEN5_AUX_OFFSET  # 0x1000
ZEN5_PAYLOAD_OFFSET = ZEN5_OPQUAD_OFFSET
ZEN5_PAYLOAD_SIZE = ZEN5_OPQUAD_REGION_SIZE
ZEN5_RECORD_COUNT = ZEN5_OPQUAD_COUNT * ZEN5_UOPS_PER_QUAD
ZENTOOL_NOP_WORD = 0x007F9C0000000000
ZEN5_REFERENCE_SHA256 = "fcb651b436acd4a45f1a410680e28f8ecbb6cae2830861cf1e26177184fa93a6"
ZEN5_REFERENCE_SHA256S = (
    ZEN5_REFERENCE_SHA256,
    "ba789f262c5a47b27f4d34efceeaecf825445aba35e048077f9fc2ea53126367",
)
ZEN5_PRECODE_OFFSET = ZEN5_MATCH_OFFSET
ZEN5_PRECODE_SIZE = ZEN5_OPQUAD_OFFSET - ZEN5_PRECODE_OFFSET  # 0xf8


assert EXTENDED_HEADER_SIZE == 0x328
assert ZENTOOL_ZEN5_OPQUAD_OFFSET == 0x418
assert ZENTOOL_ZEN5_OPQUAD_OFFSET + ZENTOOL_ZEN5_OPQUAD_REGION_SIZE == ZEN5_PATCH_SIZE
assert ZEN5_PREFIX_OFFSET + ZEN5_PREFIX_SIZE == ZEN5_OPQUAD_OFFSET
assert ZEN5_AUX_OFFSET == 0x2820
assert ZEN5_AUX_OFFSET + ZEN5_AUX_SIZE == ZEN5_PATCH_SIZE

REGISTERS: Tuple[str, ...] = (
    "reg0", "reg1", "reg2", "reg3", "reg4", "reg5", "reg6", "reg7",
    "reg8", "reg9", "reg10", "reg11", "reg12", "reg13", "reg14", "reg15",
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)

SEGMENTS: Dict[int, str] = {
    0: "vs",
    1: "cpuid",
    5: "msr1",
    6: "ls",
    9: "ucode",
    12: "msr2",
}

SIZE_CODE_TO_SUFFIX: Dict[int, str] = {
    0b000: "b",
    0b001: "w",
    0b011: "d",
    0b111: "q",
}
SIZE_CODE_TO_BYTES: Dict[int, int] = {
    0b000: 1,
    0b001: 2,
    0b011: 4,
    0b111: 8,
}

REGOP_NAMES: Dict[int, str] = {
    0xFF: "nop",
    0xA0: "mov",
    0x5F: "add",
    0x5D: "adc",
    0x50: "sub",
    0x52: "sbb",
    0x60: "mul",
    0xB0: "and",
    0xB5: "xor",
    0xBE: "or",
    0x40: "shl",
    0x41: "scl",
    0x42: "rol",
    0x44: "rcl",
    0x48: "shr",
    0x49: "scr",
    0x4A: "ror",
    0x4C: "rcr",
    0x4E: "sar",
    0x90: "movxy_x",
    0x91: "movxy_y",
    0x92: "movxy_b",
    0x93: "movxy_nb",
    0x94: "movxy_z",
    0x95: "movxy_nz",
    0x96: "movxy_be",
    0x97: "movxy_a",
    0x98: "movxy_l",
    0x99: "movxy_ge",
    0x9A: "movxy_le",
    0x9B: "movxy_g",
    0x9C: "movxy_s",
    0x9E: "movxy_ns",
}

BRANCH_NAMES: Dict[int, str] = {
    1: "jmp",
    2: "jb",
    3: "jnb",
    4: "jz",
    5: "jnz",
    6: "jbe",
    7: "ja",
    8: "jl",
    9: "jge",
    10: "jle",
    11: "jg",
    12: "js",
    13: "jns",
}


@dataclass(frozen=True)
class ZenProfile:
    name: str
    generation: int
    cpuid_part: int
    patch_size: int
    payload_offset: int
    payload_size: int
    executable: bool


ZEN1 = ZenProfile("Zen1", 1, 0x80, ZEN12_PATCH_SIZE, ZEN12_PAYLOAD_OFFSET, ZEN12_PAYLOAD_SIZE, True)
ZEN2 = ZenProfile("Zen2", 2, 0x87, ZEN12_PATCH_SIZE, ZEN12_PAYLOAD_OFFSET, ZEN12_PAYLOAD_SIZE, True)
ZEN5 = ZenProfile("Zen5", 5, 0xB4, ZEN5_PATCH_SIZE, ZEN5_PAYLOAD_OFFSET, ZEN5_PAYLOAD_SIZE, False)
PROFILES: Dict[str, ZenProfile] = {p.name.lower(): p for p in (ZEN1, ZEN2, ZEN5)}

# The compact processor revision value does not identify a generation by itself
# ZenUtils originally recognized one sample value for Zen1 and one for Zen2
# Public Family 17h updates cover several model groups
# Keep the accepted parts explicit so the detection remains auditable
# This also accepts valid updates such as 0x8840 with CPUID 00880F40
#
# The Zen1 profile also covers Zen+ and other Family 17h parts using the same ZenUtils ISA profile
# Zen5 remains a structural profile in Zenella
ZEN1_PROC_REV_PARTS: Tuple[int, ...] = (0x80, 0x81, 0x82, 0x85)
ZEN2_PROC_REV_PARTS: Tuple[int, ...] = (0x83, 0x84, 0x86, 0x87, 0x88, 0x89, 0x8A)
ZEN5_PROC_REV_PARTS: Tuple[int, ...] = (0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB6, 0xB7, 0xBD)

CPUID_PART_TO_PROFILE: Dict[int, ZenProfile] = {
    **{part: ZEN1 for part in ZEN1_PROC_REV_PARTS},
    **{part: ZEN2 for part in ZEN2_PROC_REV_PARTS},
    **{part: ZEN5 for part in ZEN5_PROC_REV_PARTS},
}


@dataclass(frozen=True)
class PatchHeader:
    date: int
    revision: int
    loader_id: int
    patch_length: int
    init_flag: int
    checksum: int
    northbridge_vendor: int
    northbridge_device: int
    southbridge_vendor: int
    southbridge_device: int
    processor_signature: int
    bios_revision: int
    flags: int

    @property
    def cpuid_part(self) -> int:
        return (self.processor_signature >> 8) & 0xFF

    @property
    def expanded_cpuid(self) -> int:
        return expanded_cpuid_from_processor_signature(self.processor_signature)

    @property
    def effective_family_model(self) -> Tuple[int, int, int]:
        return family_model_stepping_from_processor_signature(self.processor_signature)


@dataclass(frozen=True)
class DetectionResult:
    profile: Optional[ZenProfile]
    header: Optional[PatchHeader]
    confidence: str
    reason: str


@dataclass(frozen=True)
class DecodedMatchEntry:
    raw: int
    m1: int
    u1: bool
    m2: int
    u2: bool
    padding: int


@dataclass(frozen=True)
class DecodedUop:
    word: int
    instruction_class: str
    mnemonic: Optional[str]
    operation: int
    rd: int
    rs: int
    rt: int
    rmod: bool
    read_zf: bool
    read_cf: bool
    write_zf: bool
    write_cf: bool
    native_flags: bool
    size_code: int
    load: bool
    store: bool
    exec_unit: int
    imm16: int = 0
    imm_signed: bool = False
    imm32_mode: bool = False
    imm_mode: bool = False
    immediate: int = 0
    condition: int = 0
    target: Optional[int] = None
    segment: Optional[int] = None
    offset: int = 0
    qwsz: bool = False
    unknown_reason: Optional[str] = None

    @property
    def valid(self) -> bool:
        return self.mnemonic is not None

    @property
    def size_bytes(self) -> int:
        return SIZE_CODE_TO_BYTES.get(self.size_code, 8)

    @property
    def rd_name(self) -> str:
        return REGISTERS[self.rd]

    @property
    def rs_name(self) -> str:
        return REGISTERS[self.rs]

    @property
    def rt_name(self) -> str:
        return REGISTERS[self.rt]

    @property
    def segment_name(self) -> str:
        if self.segment is None:
            return "?"
        return SEGMENTS.get(self.segment, hex(self.segment))

    @property
    def flag_suffix(self) -> str:
        flags = []
        if self.read_zf:
            flags.append("z")
        if self.read_cf:
            flags.append("c")
        if self.write_zf:
            flags.append("Z")
        if self.write_cf:
            flags.append("C")
        if self.native_flags:
            flags.append("n")
        size_suffix = SIZE_CODE_TO_SUFFIX.get(self.size_code)
        # ZenUtils normally omits the q suffix in disassembly
        if size_suffix and size_suffix != "q":
            flags.append(size_suffix)
        return "".join(flags)

    @property
    def display_mnemonic(self) -> str:
        mnemonic = self.mnemonic or ".insn"
        suffix = self.flag_suffix
        return f"{mnemonic}.{suffix}" if suffix else mnemonic

    @property
    def signed_immediate(self) -> int:
        bits = 32 if self.imm32_mode else 16
        value = self.immediate & ((1 << bits) - 1)
        if self.imm_signed and value & (1 << (bits - 1)):
            value -= 1 << bits
        return value

    @property
    def scaled_offset(self) -> int:
        return self.offset << 3 if self.qwsz else self.offset

    def _memory_text(self) -> str:
        terms = [self.rs_name]
        if self.rt != 0:
            terms.append(self.rt_name)
        if self.offset != 0:
            terms.append(hex(self.offset))
        return f"{self.segment_name}:[{' + '.join(terms)}]"

    def text(self) -> str:
        if not self.valid:
            return f".insn 0x{self.word:016x}"

        mnemonic = self.display_mnemonic
        if self.instruction_class == "regop":
            if self.mnemonic == "nop":
                assembly = mnemonic
            elif self.mnemonic == "mov":
                rhs = hex(self.imm16) if self.imm_mode else self.rt_name
                assembly = f"{mnemonic} {self.rd_name}, {rhs}"
            else:
                rhs = hex(self.imm16) if self.imm_mode else self.rt_name
                assembly = f"{mnemonic} {self.rd_name}, {self.rs_name}, {rhs}"
            if self.imm32_mode:
                assembly += f", imm32:0x{self.immediate:x}"
            return assembly

        if self.instruction_class == "ldop":
            return f"{mnemonic} {self.rd_name}, {self._memory_text()}"
        if self.instruction_class == "stop":
            return f"{mnemonic} {self._memory_text()}, {self.rd_name}"
        if self.instruction_class == "brop":
            return f"{mnemonic} 0x{(self.target or 0):x}"
        return f".insn 0x{self.word:016x}"


@dataclass(frozen=True)
class DecodedSequenceWord:
    word: int
    action: str
    target: Optional[int] = None
    immediate: bool = False

    @property
    def text(self) -> str:
        suffix = " ; (immediately)" if self.immediate else ""
        if self.action == "branch":
            return f".sw_branch 0x{(self.target or 0):x}{suffix}"
        if self.action == "continue":
            return ".sw_continue"
        if self.action == "complete":
            return f".sw_complete{suffix}"
        return f".sw 0x{self.word:08x}"


def _bits(value: int, low: int, high: int) -> int:
    width = high - low + 1
    return (value >> low) & ((1 << width) - 1)


def expanded_cpuid_from_processor_signature(signature: int) -> int:
    """Expand AMD's compact patch processor revision to CPUID EAX form.

    AMD Zen update headers carry the packed 16-bit processor revision used by
    the Linux microcode loader, not a literal CPUID EAX value.  The packed
    nibbles are ExtFamily, ExtModel, BaseModel and Stepping; BaseFamily 0xF is
    implicit for these updates.
    """

    signature &= 0xFFFF
    ext_family = (signature >> 12) & 0xF
    ext_model = (signature >> 8) & 0xF
    base_model = (signature >> 4) & 0xF
    stepping = signature & 0xF
    return (
        (ext_family << 20)
        | (ext_model << 16)
        | (0xF << 8)
        | (base_model << 4)
        | stepping
    )


def family_model_stepping_from_processor_signature(signature: int) -> Tuple[int, int, int]:
    """Return effective AMD family, model and stepping for a patch signature."""

    signature &= 0xFFFF
    ext_family = (signature >> 12) & 0xF
    ext_model = (signature >> 8) & 0xF
    base_model = (signature >> 4) & 0xF
    stepping = signature & 0xF
    family = 0xF + ext_family
    model = (ext_model << 4) | base_model
    return family, model, stepping


def profile_from_processor_signature(signature: int) -> Tuple[Optional[ZenProfile], str]:
    """Resolve a supported Zenella profile from a compact processor revision.

    The explicit part table is authoritative for known public model groups.
    A Family 17h model-range fallback handles additional steppings within the
    same established Zen1/Zen2 groups without treating every 0x8x value as the
    same architecture.
    """

    part = (signature >> 8) & 0xFF
    profile = CPUID_PART_TO_PROFILE.get(part)
    if profile is not None:
        return profile, f"known processor-revision part 0x{part:02x}"

    family, model, _stepping = family_model_stepping_from_processor_signature(signature)
    if family == 0x17:
        # Public Family 17h model groups using the Zen1 and Zen+ profile
        if 0x00 <= model <= 0x2F or 0x50 <= model <= 0x5F:
            return ZEN1, f"Family 17h model 0x{model:02x} falls in the Zen1/Zen+ model groups"
        # Public Family 17h model groups using the Zen2 profile
        if 0x30 <= model <= 0x4F or 0x60 <= model <= 0xAF:
            return ZEN2, f"Family 17h model 0x{model:02x} falls in the Zen2 model groups"
    return None, f"no supported profile for processor-revision part 0x{part:02x}"


def parse_patch_header(data: bytes, base: int = 0) -> PatchHeader:
    if base < 0:
        raise ValueError("base must be non-negative")
    if len(data) < base + HEADER_SIZE:
        raise ValueError(
            f"Need at least 0x{HEADER_SIZE:x} bytes at base 0x{base:x}; "
            f"only 0x{max(0, len(data) - base):x} available"
        )

    def u8(offset: int) -> int:
        return data[base + offset]

    def u16(offset: int) -> int:
        return int.from_bytes(data[base + offset:base + offset + 2], "little")

    def u32(offset: int) -> int:
        return int.from_bytes(data[base + offset:base + offset + 4], "little")

    return PatchHeader(
        date=u32(0x00),
        revision=u32(0x04),
        loader_id=u16(0x08),
        patch_length=u8(0x0A),
        init_flag=u8(0x0B),
        checksum=u32(0x0C),
        northbridge_vendor=u16(0x10),
        northbridge_device=u16(0x12),
        southbridge_vendor=u16(0x14),
        southbridge_device=u16(0x16),
        processor_signature=u32(0x18),
        bios_revision=u8(0x1C),
        flags=u8(0x1D),
    )



@dataclass(frozen=True)
class PatchOptions:
    """Zenella's second-header view. The two original bytes are not modified.

    loaderid is LE16 at +0x322. It selects Zenella's research profiles; this is
    deliberately distinct from native zentool, which switches on +0x08.
    """
    autorun: int
    encrypted: int
    loaderid: int


def parse_patch_options(data: bytes, base: int = 0) -> PatchOptions:
    if base < 0 or base + OPTIONS_OFFSET + OPTIONS_SIZE > len(data):
        raise ValueError("Incomplete second header: need four option bytes at patch +0x320")
    return PatchOptions(*struct.unpack_from("<BBH", data, base + OPTIONS_OFFSET))


def detect_profile(data: bytes, base: int = 0) -> DetectionResult:
    try:
        header = parse_patch_header(data, base)
    except ValueError as exc:
        return DetectionResult(None, None, "none", str(exc))

    available = len(data) - base
    by_cpuid, identification = profile_from_processor_signature(header.processor_signature)
    if by_cpuid is not None:
        if available < by_cpuid.patch_size:
            return DetectionResult(
                by_cpuid,
                header,
                "medium",
                f"{identification} identifies {by_cpuid.name}, "
                f"but only 0x{available:x}/0x{by_cpuid.patch_size:x} bytes are available",
            )
        trailing = available - by_cpuid.patch_size
        trailing_text = f"; ignoring 0x{trailing:x} trailing bytes" if trailing else ""
        return DetectionResult(
            by_cpuid,
            header,
            "high",
            f"{identification} identifies {by_cpuid.name}{trailing_text}"
            + ("; generation only, not proof of ISA or payload geometry" if by_cpuid == ZEN5 else ""),
        )

    # Patch size separates Zen5 from the Zen1 and Zen2 family but cannot separate Zen1 from Zen2
    if available == ZEN5_PATCH_SIZE:
        return DetectionResult(
            ZEN5,
            header,
            "low",
            "Patch size matches the current Zen5 structural profile; CPUID part is unknown",
        )
    if available == ZEN12_PATCH_SIZE:
        return DetectionResult(
            None,
            header,
            "none",
            "Patch size matches Zen1/Zen2, but the CPUID part does not distinguish a supported profile",
        )

    if ZEN12_PATCH_SIZE < available < ZEN5_PATCH_SIZE:
        return DetectionResult(
            None,
            header,
            "none",
            f"At least one 0x{ZEN12_PATCH_SIZE:x}-byte Zen1/Zen2 patch is present, "
            f"but {identification}; 0x{available - ZEN12_PATCH_SIZE:x} trailing bytes remain",
        )

    return DetectionResult(
        None,
        header,
        "none",
        f"Unsupported CPUID part 0x{header.cpuid_part:02x} and size 0x{available:x}",
    )


def get_profile(name: str) -> ZenProfile:
    try:
        return PROFILES[name.strip().lower()]
    except KeyError as exc:
        raise ValueError(f"Unsupported profile {name!r}; expected Zen1, Zen2, or Zen5") from exc


def decode_match_entry(word: int) -> DecodedMatchEntry:
    word &= 0xFFFFFFFF
    return DecodedMatchEntry(
        raw=word,
        m1=_bits(word, 0, 12),
        u1=bool(_bits(word, 13, 13)),
        m2=_bits(word, 14, 26),
        u2=bool(_bits(word, 27, 27)),
        padding=_bits(word, 28, 31),
    )


def decode_match_entries(data: bytes, offset: int = 0, count: int = ZEN12_MATCH_ENTRY_COUNT) -> Tuple[DecodedMatchEntry, ...]:
    required = offset + count * 4
    if offset < 0 or len(data) < required:
        raise ValueError(f"Need 0x{required:x} bytes to decode {count} match entries")
    return tuple(
        decode_match_entry(int.from_bytes(data[offset + i * 4:offset + i * 4 + 4], "little"))
        for i in range(count)
    )


def decode_uop(word: int, prev_word: int = 0) -> DecodedUop:
    word &= 0xFFFFFFFFFFFFFFFF
    rt = _bits(word, 21, 25)
    rs = _bits(word, 26, 30)
    rd = _bits(word, 31, 35)
    rmod = bool(_bits(word, 36, 36))
    read_zf = bool(_bits(word, 37, 37))
    read_cf = bool(_bits(word, 38, 38))
    write_zf = bool(_bits(word, 39, 39))
    write_cf = bool(_bits(word, 40, 40))
    native_flags = bool(_bits(word, 41, 41))
    size_code = _bits(word, 42, 44)
    load = bool(_bits(word, 45, 45))
    store = bool(_bits(word, 46, 46))
    operation = _bits(word, 47, 54)
    exec_unit = _bits(word, 59, 61)

    common = dict(
        word=word,
        operation=operation,
        rd=rd,
        rs=rs,
        rt=rt,
        rmod=rmod,
        read_zf=read_zf,
        read_cf=read_cf,
        write_zf=write_zf,
        write_cf=write_cf,
        native_flags=native_flags,
        size_code=size_code,
        load=load,
        store=store,
        exec_unit=exec_unit,
    )

    if operation >= 0x20 and not load and not store:
        imm16 = _bits(word, 0, 15)
        imm_signed = bool(_bits(word, 16, 16))
        imm32_mode = bool(_bits(word, 17, 17))
        imm_mode = bool(_bits(word, 19, 19))
        condition = _bits(word, 47, 50)
        mnemonic = REGOP_NAMES.get(operation)
        if mnemonic is None and 0x20 <= operation <= 0x2F:
            mnemonic = "sub2"
        immediate = (((prev_word & 0xFFFF) << 16) | imm16) if imm32_mode else imm16
        return DecodedUop(
            instruction_class="regop",
            mnemonic=mnemonic,
            imm16=imm16,
            imm_signed=imm_signed,
            imm32_mode=imm32_mode,
            imm_mode=imm_mode,
            immediate=immediate,
            condition=condition,
            unknown_reason=None if mnemonic else f"unknown RegOp opcode 0x{operation:02x}",
            **common,
        )

    if load and operation == 0xDE and not store:
        return DecodedUop(
            instruction_class="ldop",
            mnemonic="mov",
            segment=_bits(word, 10, 13),
            offset=_bits(word, 0, 9),
            qwsz=bool(_bits(word, 19, 19)),
            **common,
        )

    if store and operation == 0xA0 and not load:
        return DecodedUop(
            instruction_class="stop",
            mnemonic="mov",
            segment=_bits(word, 10, 13),
            offset=_bits(word, 0, 9),
            qwsz=bool(_bits(word, 19, 19)),
            **common,
        )

    if operation < 0x10 and not load and not store:
        condition = _bits(word, 47, 50)
        target = _bits(word, 0, 12)
        mnemonic = BRANCH_NAMES.get(condition)
        return DecodedUop(
            instruction_class="brop",
            mnemonic=mnemonic,
            condition=condition,
            target=target,
            unknown_reason=None if mnemonic else f"unknown branch condition {condition}",
            **common,
        )

    return DecodedUop(
        instruction_class="unknown",
        mnemonic=None,
        unknown_reason=(
            f"unclassified encoding: operation=0x{operation:02x}, "
            f"load={int(load)}, store={int(store)}"
        ),
        **common,
    )


def disassemble_uop(word: int, prev_word: int = 0) -> Optional[str]:
    decoded = decode_uop(word, prev_word)
    return decoded.text() if decoded.valid else None


def decode_sequence_word(word: int) -> DecodedSequenceWord:
    word &= 0xFFFFFFFF
    if word & 0x00020000:
        return DecodedSequenceWord(
            word=word,
            action="branch",
            target=word & 0x1FFF,
            immediate=bool(word & 0x00100000),
        )
    if word & 1:
        return DecodedSequenceWord(word=word, action="continue")
    if word & 2:
        return DecodedSequenceWord(
            word=word,
            action="complete",
            immediate=bool(word & 0x00100000),
        )
    return DecodedSequenceWord(word=word, action="raw")


def package_offset(slot: int) -> int:
    if not 0 <= slot < ZEN12_PACKAGE_COUNT:
        raise ValueError(f"slot must be in [0, {ZEN12_PACKAGE_COUNT - 1}]")
    return ZEN12_PAYLOAD_OFFSET + slot * ZEN12_PACKAGE_SIZE


def rom_address_to_slot(address: int) -> Optional[int]:
    slot = address - ZEN12_ROM_START
    return slot if 0 <= slot < ZEN12_PACKAGE_COUNT else None


def rom_address_to_payload_offset(address: int) -> Optional[int]:
    slot = rom_address_to_slot(address)
    return None if slot is None else slot * ZEN12_PACKAGE_SIZE


def slot_to_rom_address(slot: int) -> int:
    if not 0 <= slot < ZEN12_PACKAGE_COUNT:
        raise ValueError(f"slot must be in [0, {ZEN12_PACKAGE_COUNT - 1}]")
    return ZEN12_ROM_START + slot


def iter_package_words(payload: bytes) -> Iterable[Tuple[int, Tuple[int, int, int, int], int]]:
    if len(payload) != ZEN12_PAYLOAD_SIZE:
        raise ValueError(
            f"Zen1/Zen2 payload must be exactly 0x{ZEN12_PAYLOAD_SIZE:x} bytes; "
            f"got 0x{len(payload):x}"
        )
    for slot in range(ZEN12_PACKAGE_COUNT):
        offset = slot * ZEN12_PACKAGE_SIZE
        words = tuple(
            int.from_bytes(
                payload[offset + i * ZEN12_INSTRUCTION_SIZE:
                        offset + (i + 1) * ZEN12_INSTRUCTION_SIZE],
                "little",
            )
            for i in range(ZEN12_INSTRUCTIONS_PER_PACKAGE)
        )
        sequence_offset = offset + ZEN12_INSTRUCTIONS_PER_PACKAGE * ZEN12_INSTRUCTION_SIZE
        sequence = int.from_bytes(payload[sequence_offset:sequence_offset + 4], "little")
        yield slot, words, sequence


#####################################################################################################
# Zen5 opcode tags and bitfields. Keep the user's mappings separate from layout selection.
#####################################################################################################

# RISC86 opclass analog of zentool zen_opclass_t. The authoritative bit layout is in zentool
# ucode.h, whose per-class structs (RegOp/SpecOp/BrOp vs LdStOp) all place `.class` at bits
# [59:62]. In this codebase that field is the 3-bit slice decode_zen5_tag() names `exec_unit`.
# The class, not opcode/type, decides a word is a LdStOp: OP_LD and OP_ST are both 0x00, and a
# LdStOp's `type` is a *different* field (bits [55:59], this codebase's `mid`), so matching the
# [47:55] opcode slice is meaningless for LdStOps. Verified against both EPYC 9965 updates:
# RegOps (add/shl) -> class REG(111), nop -> class SPEC(000), class {LD,STN,ST} -> real LdStOps.
OPCLASS_SPEC = 0b000
OPCLASS_BR   = 0b001
OPCLASS_LD   = 0b010   # LdOp (issued to the load unit)
OPCLASS_STN  = 0b100   # StOp, no memory reference
OPCLASS_ST   = 0b101   # StOp, memory / fault-capable
OPCLASS_REGX = 0b110
OPCLASS_REG  = 0b111
LDSTOP_CLASSES = frozenset({OPCLASS_LD, OPCLASS_STN, OPCLASS_ST})
OPCLASS_NAMES = {
    OPCLASS_SPEC: "spec", OPCLASS_BR: "br", OPCLASS_LD: "ld", OPCLASS_STN: "stn",
    OPCLASS_ST: "st", OPCLASS_REGX: "regx", OPCLASS_REG: "reg",
}
OP_LD = 0x00   # zen_ld_opcode_t OP_LD
OP_ST = 0x00   # zen_st_opcode_t OP_ST
@dataclass(frozen=True)
class DecodedZen5Tag:
    """Zenella's original 64-bit micro-op field view.

    The names and bit slices are retained from the user's plugin. Opcode tags
    label bits 47..54 using the complete user table, without a class whitelist.
    Tag lookup is not a claim to implement complete Zen5 execution semantics.
    """
    offset: int
    raw: bytes
    word: int
    opcode: int
    imm16: int
    imm_flags: int
    rt: int
    rs: int
    rd: int
    flags: int
    size: int
    load: int
    store: int
    mid: int
    exec_unit: int
    hi: int


def _bitfield(word: int, lo: int, width: int) -> int:
    return (word >> lo) & ((1 << width) - 1)


def decode_zen5_tag(record: bytes, offset: int = 0) -> DecodedZen5Tag:
    """Extract the original opcode, register, immediate and control-bit fields."""
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if len(record) != ZEN5_RECORD_SIZE:
        raise ValueError(f"Zen5 word must be exactly 8 bytes; got {len(record)}")
    word = int.from_bytes(record, "little")
    return DecodedZen5Tag(
        offset=offset, raw=bytes(record), word=word,
        opcode=_bitfield(word, 47, 8), imm16=_bitfield(word, 0, 16),
        imm_flags=_bitfield(word, 16, 5), rt=_bitfield(word, 21, 5),
        rs=_bitfield(word, 26, 5), rd=_bitfield(word, 31, 5),
        flags=_bitfield(word, 36, 6), size=_bitfield(word, 42, 3),
        load=_bitfield(word, 45, 1), store=_bitfield(word, 46, 1),
        mid=_bitfield(word, 55, 4), exec_unit=_bitfield(word, 59, 3),
        hi=_bitfield(word, 62, 2),
    )


def zen5_opclass(tag: "DecodedZen5Tag") -> int:
    """RISC86 opclass (zentool ucode.h .class, bits [59:62]). It is the field
    decode_zen5_tag() names `exec_unit`; see the OPCLASS_* constants above."""
    return tag.exec_unit


def zen5_is_ldstop(tag: "DecodedZen5Tag") -> bool:
    """True when this word is a LdStOp. The class alone decides this the [47:55]
    opcode slice is not a LdStOp's type (that lives at bits [55:59])."""
    return zen5_opclass(tag) in LDSTOP_CLASSES


def zen5_detect_body_sections(quads, quad_offset: int, min_nop_run: int = 8):
    """Overlay sections within the op-quad body. Purely descriptive this does NOT change
    op-quad parsing; it only names ranges of already-decoded op-quads.

    Detection works on the raw body BYTES (scanning for ZENTOOL_NOP_WORD at every 4-byte
    position), so it does not depend on the op-quad grid the caller chose; the resulting
    byte boundaries are then snapped to the nearest op-quad boundary of that grid so the
    sections can be framed as whole op-quads in whatever layout is applied.

    - NOP section: the longest dense run of NOP words (consecutive NOP words at most 12 bytes
      apart, i.e. adjacent or separated by one 4-byte sequence word), at least
      4 * `min_nop_run` words long.
    - Finalization sequence: starts after the sparse continuation of that run (NOP words that
      keep appearing at most one op-quad, 36 bytes, apart) and ends where the trailing
      all-zero bytes of the body begin (or at the body end when there are none).

    Returns a list of dicts {name, label, offset, end, first_quad, quad_count, raw_offset,
    raw_end, interpretation, aligned} with absolute, quad-aligned offsets (raw_* are the
    unsnapped byte boundaries), or [] when no qualifying NOP run exists. `aligned` tells
    whether the NOP words sit on the uop slots of the caller's grid (False means the grid is
    shifted relative to the microcode and the NOP words do not decode as NOP).
    """
    n = len(quads)
    if n == 0:
        return []
    body = b"".join(q.raw for q in quads)
    body_end = quad_offset + len(body)
    nop_bytes = ZENTOOL_NOP_WORD.to_bytes(ZEN5_RECORD_SIZE, "little")
    nops = [quad_offset + i for i in range(0, len(body) - ZEN5_RECORD_SIZE + 1, 4)
            if body[i:i + ZEN5_RECORD_SIZE] == nop_bytes]
    if not nops:
        return []

    # Longest dense run: NOP words adjacent or with exactly one sequence word between them.
    dense_gap = ZEN5_RECORD_SIZE + ZEN5_SEQUENCE_SIZE
    runs = []
    for off in nops:
        if runs and off - runs[-1][-1] <= dense_gap:
            runs[-1].append(off)
        else:
            runs.append([off])
    best = max(runs, key=len)
    if len(best) < ZEN5_UOPS_PER_QUAD * min_nop_run:
        return []
    raw_nop_start = best[0]
    raw_nop_end = best[-1] + ZEN5_RECORD_SIZE

    # Sparse continuation: single real ops interleaved with NOPs right after the dense run.
    last = best[-1]
    for off in nops:
        if off <= last:
            continue
        if off - last <= ZEN5_OPQUAD_SIZE:
            last = off
        else:
            break
    raw_fin_start = last + ZEN5_RECORD_SIZE

    # Finalization ends where the body's trailing zero bytes begin.
    raw_fin_end = zen5_body_padding_start(body, 0, len(body)) + quad_offset
    if raw_fin_end <= raw_fin_start:
        raw_fin_end = body_end

    def snap(raw):
        qi = int(round((raw - quad_offset) / ZEN5_OPQUAD_SIZE))
        return max(0, min(n, qi))

    q_nop_start = snap(raw_nop_start)
    q_nop_end = max(q_nop_start + 1, snap(raw_nop_end))
    q_fin_start = max(q_nop_end, snap(raw_fin_start))
    q_fin_end = max(q_fin_start, snap(raw_fin_end))
    if q_nop_end > n:
        return []
    slots = (0, ZEN5_RECORD_SIZE, 2 * ZEN5_RECORD_SIZE, 3 * ZEN5_RECORD_SIZE)
    aligned = all(((off - quad_offset) % ZEN5_OPQUAD_SIZE) in slots for off in best)

    def span(name, label, qs, qe, raw_s, raw_e, interpretation):
        return {
            "name": name, "label": label,
            "offset": quad_offset + qs * ZEN5_OPQUAD_SIZE,
            "end": quad_offset + qe * ZEN5_OPQUAD_SIZE,
            "first_quad": qs, "quad_count": qe - qs,
            "raw_offset": raw_s, "raw_end": raw_e,
            "interpretation": interpretation,
            "aligned": aligned,
        }

    sections = [span(
        "nop_section", "NOP section", q_nop_start, q_nop_end, raw_nop_start, raw_nop_end,
        "dense run of NOP words (opcode 0xFF) before the finalization sequence; op-quads still decoded",
    )]
    if q_fin_end > q_fin_start:
        sections.append(span(
            "finalization_section", "Finalization sequence", q_fin_start, q_fin_end,
            raw_fin_start, raw_fin_end,
            "op-quads after the last NOP of the NOP section's sparse tail, up to the trailing "
            "zero padding; op-quads still decoded",
        ))
    return sections


def zen5_nop_alignment_hint(data: bytes, quad_offset: int, patch_size: int = None):
    """If the NOP section found at `quad_offset` does not sit on the uop slots of that grid
    (the NOP words are shifted by a DWORD or two relative to the op-quads) but a nearby
    4/8-byte shift puts them on the slots, return a hint dict {delta, suggested_quad_offset,
    nop_quads, register_total_delta} so callers can warn that the register boundary is
    misaligned. Returns None when the current offset is aligned (or no NOP run is found at
    any nearby shift)."""
    size = len(data) if patch_size is None else min(patch_size, len(data))

    def nop_section(off):
        if off < 0 or off + ZEN5_OPQUAD_SIZE > size:
            return None
        avail = size - off
        count = avail // ZEN5_OPQUAD_SIZE
        if count <= 0:
            return None
        quads = list(iter_zen5_opquads(data[off:off + count * ZEN5_OPQUAD_SIZE], off, strict=False))
        secs = zen5_detect_body_sections(quads, off)
        return next((s for s in secs if s["name"] == "nop_section"), None)

    here = nop_section(quad_offset)
    if here is not None and here["aligned"]:
        return None
    best = None
    for delta in (-8, -4, 4, 8):
        sec = nop_section(quad_offset + delta)
        if sec is not None and sec["aligned"] and (best is None or sec["quad_count"] > best[1]):
            best = (delta, sec["quad_count"])
    if best is None:
        return None
    delta, run = best
    return {
        "delta": delta,
        "suggested_quad_offset": quad_offset + delta,
        "nop_quads": run,
        "register_total_delta": delta // 4,  # +N/-N DWORDs to add to match+mask
    }


def zen5_is_alignment_artifact(tag: "DecodedZen5Tag") -> bool:
    """A word whose entire top 32 bits are zero (no opcode/class/size/flags/ld/st) but whose
    low 32 bits are nonzero is not a real micro-op: it is an op-quad framing/alignment artifact
    (e.g. a zero dword concatenated with a sequence word). Real ops always set bits in the top
    half (opcode 47..54, class 59..61, size 42..44), so this never flags a genuine op. A truly
    all-zero word is excluded (low 32 bits are zero)."""
    return (tag.word >> 32) == 0 and (tag.word & 0xFFFFFFFF) != 0


def zen5_opcode_label(tag: "DecodedZen5Tag",
                      names: Optional[Dict[int, str]] = None) -> str:
    """Opcode name for display. A LdStOp -> 'LD'/'ST' by the ldst bit; a non-LdStOp whose
    8-bit opcode slice is 0x00 -> '<CLASS>.0x00' (the legacy AMD_ZEN_UOP_LD_ST_00 name implied
    load/store, which these are not; all-zero words are class=0 -> 'SPEC.0x00'); otherwise the
    enum tag name or a raw hex opcode. No 'padding' interpretation is made."""
    if zen5_is_ldstop(tag):
        return "LD" if tag.load else "ST"
    if tag.opcode == 0x00:
        class_name = OPCLASS_NAMES.get(tag.exec_unit, f"0b{tag.exec_unit:03b}")
        return f"{class_name.upper()}.0x00"
    names = load_zen5_opcode_names() if names is None else names
    return names.get(tag.opcode, f"0x{tag.opcode:02x}")


def zen5_ldstop_fields(tag: "DecodedZen5Tag") -> Dict[str, int]:
    """LdStOp-specific fields, per zentool ucode.h `struct LdStOp`. Valid only when
    zen5_is_ldstop(tag). reg0/reg1/reg2 are tag.rt/tag.rs/tag.rd (bits 21/26/31)."""
    w = tag.word
    return {
        "opclass": tag.exec_unit,          # bits[59:62]
        "ldst": tag.load,                  # bit 45  (1 -> load, 0 -> store)
        "type": tag.mid,                   # bits[55:59]  (0 == OP_LD / OP_ST)
        "imm": (w >> 0) & 0x3FF,           # bits[0:10]  displacement
        "segment": (w >> 10) & 0xF,        # bits[10:14]
        "mode": (w >> 17) & 0x3,           # bits[17:19]
        "wordsz": (w >> 19) & 0x1,         # bit 19  (qword-scaled displacement)
    }


# Per-opcode operand form for the tagged Zen5 opcodes. Keyed by the 8-bit opcode
# value (bits 47..54), so the duplicate 0x47 spelling in ZEN_OPCODE_ENUM is a
# non-issue. Each entry is (mnemonic, form). The forms are decoded by
# decode_zen5_operands() below. This is principled INFERENCE grounded in the
# Zen1/Zen2 operand model in decode_uop()/DecodedUop.text() (identical 64-bit bit
# layout) and validated against the two supplied EPYC 9965 updates; it is NOT a
# claim to implement complete Zen5 execution semantics. Opcodes absent from this
# table decode to form "unknown" and render "?", leaving the raw fields as the
# authoritative display rather than inventing a mnemonic.
ZEN5_OPERAND_SPECS: Dict[int, Tuple[str, str]] = {
    # alu3: dst, src, (src2 reg or immediate)
    0x19: ("nsub", "alu3"), 0x30: ("and", "alu3"), 0x50: ("sub", "alu3"),
    0x52: ("sbb", "alu3"), 0x55: ("nadd", "alu3"), 0x5C: ("add2", "alu3"),
    0x5D: ("adc", "alu3"), 0x5E: ("add3", "alu3"), 0x5F: ("add", "alu3"),
    0x72: ("sbit", "alu3"), 0xB5: ("xor", "alu3"), 0xBE: ("or", "alu3"),
    # shift/rotate: dst, src, (immediate count or register count)
    0x40: ("shl", "shift"), 0x41: ("bll", "shift"), 0x42: ("rol", "shift"),
    0x44: ("rlc", "shift"), 0x46: ("rrd", "shift"), 0x47: ("src", "shift"),
    0x48: ("shr", "shift"), 0x4A: ("ror", "shift"), 0x4C: ("rrc", "shift"),
    0x4F: ("srd", "shift"),
    # unary: dst, src
    0x70: ("popcnt", "unary"), 0xA9: ("bswap", "unary"),
    # register move: dst, (register or immediate)
    0x93: ("mov2", "mov"),
    # segment move: store form writes memory, else register move
    0xA0: ("mov", "movsreg"),
    # load from segment:[base(+index)+disp]
    0xDE: ("mov", "load"),
    # LD_ST_00: opcode-slice 0 in a non-LdStOp class (e.g. SPEC padding). Real LdStOps are
    # dispatched by class *before* this table is consulted (see decode_zen5_operands), so this
    # entry only ever sees non-LdStOp words with a zero opcode slice -> rendered as unmodeled.
    0x00: ("ldst", "ldst00"),
    # branch
    0x05: ("jmp", "branch"),
    # no-op tag (applied broadly; only all-clear words render "nop")
    0xFF: ("nop", "nop"),
    # zero-operand
    0x6F: ("vzeroupper64", "noargs"), 0x7F: ("vzeroupper32", "noargs"),
}


@dataclass(frozen=True)
class DecodedZen5Operands:
    """Inferred per-opcode operand rendering for one Zen5 micro-op.

    `asm` is a human instruction string (numeric registers r0..r31, hex
    immediates) or None when the opcode's operand-form preconditions are not met;
    `detail` is a JSON-safe structured view. `confidence` is always "inferred":
    this operand model is reverse-engineered, not documented ISA.
    """
    form: str
    mnemonic: Optional[str]
    asm: Optional[str]
    confidence: str
    detail: Dict[str, object]
    note: Optional[str] = None


def _zen5_reg(index: int) -> str:
    """Numeric register name matching the existing rd=rN field display."""
    return f"r{index}"


def _zen5_size_suffix(size: int) -> str:
    """'.b'/'.w'/'.d' for known size codes; '' for qword/unknown (as in Zen1/2)."""
    suffix = SIZE_CODE_TO_SUFFIX.get(size)
    return "" if not suffix or suffix == "q" else "." + suffix


def _zen5_mem_text(seg_name: str, rs: int, rt: int, offset: int, qwsz: bool) -> str:
    """seg:[base(+index)(+disp)], mirroring DecodedUop._memory_text (:386)."""
    terms = [_zen5_reg(rs)]
    if rt:
        terms.append(_zen5_reg(rt))
    disp = offset << 3 if qwsz else offset
    if disp:
        terms.append(f"0x{disp:x}")
    return f"{seg_name}:[{' + '.join(terms)}]"


def _decode_zen5_ldstop(tag: DecodedZen5Tag) -> "DecodedZen5Operands":
    """Operand rendering for a LdStOp (opclass in {LD, STN, ST}), per zentool ucode.h
    `struct LdStOp`. Direction is the ldst bit (bit 45): 1 -> load, 0 -> store. The
    memory operand is segment:[reg1(+reg2)(+disp)] with the data register reg2==tag.rd.
    """
    f = zen5_ldstop_fields(tag)
    opclass = f["opclass"]
    class_name = OPCLASS_NAMES.get(opclass, f"0b{opclass:03b}")
    sz = _zen5_size_suffix(tag.size)
    dst = _zen5_reg(tag.rd)                       # reg2: data register
    seg_name = SEGMENTS.get(f["segment"], hex(f["segment"]))
    mem = _zen5_mem_text(seg_name, tag.rs, tag.rt, f["imm"], bool(f["wordsz"]))
    is_load = bool(f["ldst"])
    mnemonic = "ld" if is_load else "st"
    mem_ref = {OPCLASS_LD: "load unit",
               OPCLASS_STN: "non-memory",
               OPCLASS_ST: "memory/fault-capable"}.get(opclass, "?")
    asm = f"{mnemonic}{sz} {dst}, {mem}" if is_load else f"{mnemonic}{sz} {mem}, {dst}"

    notes = []
    if opclass == OPCLASS_STN:
        # "StOp without memory reference" the segment:[...] operand is the codebase's
        # inferred form; the class says this store does not reference memory.
        notes.append("class STN: StOp without memory reference; operand shown is inferred")
    if f["type"] != 0:
        notes.append(f"non-zero LdStOp type 0x{f['type']:x}; only OP_LD/OP_ST=0x0 is modeled")
    note = "; ".join(notes) or None

    detail = {
        "direction": "load" if is_load else "store",
        "rd": dst, "mem": mem, "segment": seg_name, "segment_raw": f["segment"],
        "disp": f["imm"], "class": opclass, "class_name": class_name,
        "mem_ref": mem_ref, "ldst": f["ldst"], "type": f["type"], "mode": f["mode"],
    }
    return DecodedZen5Operands("ldstop", mnemonic, asm, "inferred", detail, note)


def decode_zen5_operands(tag: DecodedZen5Tag,
                         prev_word: Optional[int] = None) -> DecodedZen5Operands:
    """Infer the operands of a tagged Zen5 micro-op from its DecodedZen5Tag.

    The immediate-operand indicator is empirically word bit 20 (imm_flags bit 4):
    across both the shift and ALU families in the two supplied EPYC 9965 updates,
    bit 20 set correlates exactly with rt==0 and a small in-range imm16 (a real
    immediate), while bit 20 clear (imm_flags 0) uses the rt register and leaves
    imm16 as don't-care bits. Word bit 16 (imm_flags bit 0) is the sign bit, and
    word bit 17 (imm_flags bit 1) selects a 32-bit immediate whose upper half is in
    the previous word (as in decode_uop :693) only resolvable with quad context;
    without it the low half is reported explicitly rather than guessed. Preconditions
    that fail leave asm=None so the caller renders "?" and the raw fields remain
    authoritative.
    """
    # Class-first dispatch: a LdStOp is identified by its opclass (bits 59..61), NOT by the
    # [47:55] opcode slice, and it uses an entirely different field layout (zentool ucode.h
    # struct LdStOp). Handle it before the opcode-keyed table, which only models RegOp/SpecOp/
    # BrOp words whose type does live at [47:55].
    if zen5_is_ldstop(tag):
        return _decode_zen5_ldstop(tag)

    spec = ZEN5_OPERAND_SPECS.get(tag.opcode)
    use_imm = bool(tag.imm_flags & 0x10)      # word bit 20: immediate-operand mode
    imm_signed = bool(tag.imm_flags & 0x01)   # word bit 16: sign
    imm32_mode = use_imm and bool(tag.imm_flags & 0x02)  # word bit 17: 32-bit imm
    qwsz = bool(tag.imm_flags & 0x08)         # word bit 19: qword-scaled offset
    sz = _zen5_size_suffix(tag.size)
    note: Optional[str] = None

    if imm32_mode and prev_word is not None:
        value, width = (((prev_word & 0xFFFF) << 16) | tag.imm16), 32
    elif imm32_mode:
        value, width = tag.imm16, 16
        note = "imm32 upper half in previous word (unavailable)"
    else:
        value, width = tag.imm16, 16
    if imm_signed and value & (1 << (width - 1)):
        imm_text = f"-0x{(1 << width) - value:x}"
    else:
        imm_text = f"0x{value:x}"

    if spec is None:
        return DecodedZen5Operands(
            form="unknown", mnemonic=None, asm=None, confidence="inferred",
            detail={"opcode": tag.opcode}, note="opcode not in ZEN5_OPERAND_SPECS")

    mnemonic, form = spec
    dst, src = _zen5_reg(tag.rd), _zen5_reg(tag.rs)

    if form == "alu3":
        if use_imm:
            src2, kind = imm_text, "imm"
        else:
            src2, kind = _zen5_reg(tag.rt), "reg"
        asm = f"{mnemonic}{sz} {dst}, {src}, {src2}"
        detail = {"rd": dst, "rs": src, "src2_kind": kind, "src2": src2}
        return DecodedZen5Operands(form, mnemonic, asm, "inferred", detail, note)

    if form == "shift":
        if use_imm:
            asm = f"{mnemonic}{sz} {dst}, {src}, {imm_text}"
            detail = {"rd": dst, "rs": src, "count_kind": "imm", "count": imm_text}
            if tag.imm16 > 63:
                note = "immediate shift count exceeds 63; unusual"
        else:
            cnt = _zen5_reg(tag.rt)
            asm = f"{mnemonic}{sz} {dst}, {src}, {cnt}"
            detail = {"rd": dst, "rs": src, "count_kind": "reg", "count": cnt}
        return DecodedZen5Operands(form, mnemonic, asm, "inferred", detail, note)

    if form == "unary":
        asm = f"{mnemonic}{sz} {dst}, {src}"
        return DecodedZen5Operands(form, mnemonic, asm, "inferred",
                                   {"rd": dst, "rs": src}, note)

    if form == "mov":
        rhs, kind = (imm_text, "imm") if use_imm else (_zen5_reg(tag.rt), "reg")
        asm = f"{mnemonic}{sz} {dst}, {rhs}"
        return DecodedZen5Operands(form, mnemonic, asm, "inferred",
                                   {"rd": dst, "src_kind": kind, "src": rhs}, note)

    if form == "movsreg":
        seg = (tag.imm16 >> 10) & 0xF
        off = tag.imm16 & 0x3FF
        seg_name = SEGMENTS.get(seg, hex(seg))
        if tag.store:
            mem = _zen5_mem_text(seg_name, tag.rs, tag.rt, off, qwsz)
            asm = f"{mnemonic}{sz} {mem}, {dst}"
            detail = {"direction": "store", "mem": mem, "rd": dst,
                      "segment": seg_name, "segment_raw": seg}
        else:
            rhs, kind = (imm_text, "imm") if use_imm else (_zen5_reg(tag.rt), "reg")
            asm = f"{mnemonic}{sz} {dst}, {rhs}"
            detail = {"direction": "reg", "rd": dst, "src_kind": kind, "src": rhs}
        return DecodedZen5Operands(form, mnemonic, asm, "inferred", detail, note)

    if form == "load":
        if not tag.load:
            return DecodedZen5Operands(form, mnemonic, None, "inferred",
                                       {"rd": dst}, "load form without load bit set")
        seg = (tag.imm16 >> 10) & 0xF
        off = tag.imm16 & 0x3FF
        seg_name = SEGMENTS.get(seg, hex(seg))
        mem = _zen5_mem_text(seg_name, tag.rs, tag.rt, off, qwsz)
        asm = f"{mnemonic}{sz} {dst}, {mem}"
        detail = {"rd": dst, "mem": mem, "segment": seg_name, "segment_raw": seg}
        return DecodedZen5Operands(form, mnemonic, asm, "inferred", detail, note)

    if form == "ldst00":
        # Real LdStOps (class LD/STN/ST) are handled by the class-first dispatch at the top of
        # decode_zen5_operands and never reach here. A word arriving here has a zero opcode
        # slice but a non-LdStOp class SPEC(000) padding (the all-zero filler) or some other
        # class whose type is not modeled so it is left unmodeled.
        opclass = zen5_opclass(tag)
        class_name = OPCLASS_NAMES.get(opclass, f"0b{opclass:03b}")
        reason = ("opcode-slice 0x00, class spec: empty/padding slot, not a LdStOp"
                  if opclass == OPCLASS_SPEC
                  else f"opcode-slice 0x00 with non-LdStOp class {class_name}; not a LdStOp")
        return DecodedZen5Operands(form, mnemonic, None, "inferred",
                                   {"imm16": tag.imm16, "class": opclass,
                                    "class_name": class_name}, reason)

    if form == "branch":
        if not tag.load and not tag.store and not tag.rd and not tag.rs and not tag.rt:
            asm = f"{mnemonic} 0x{tag.imm16:x}"
            return DecodedZen5Operands(form, mnemonic, asm, "inferred",
                                       {"target": f"0x{tag.imm16:x}"}, note)
        return DecodedZen5Operands(form, mnemonic, None, "inferred",
                                   {"imm16": tag.imm16},
                                   "branch tag with non-branch fields set; unmodeled")

    if form == "nop":
        clean = not (tag.imm16 or tag.rd or tag.rs or tag.rt or tag.load or tag.store)
        if clean:
            return DecodedZen5Operands(form, mnemonic, "nop", "inferred", {}, note)
        return DecodedZen5Operands(form, mnemonic, None, "inferred",
                                   {"rd": dst, "rs": src, "rt": _zen5_reg(tag.rt),
                                    "load": tag.load, "store": tag.store},
                                   "NOP tag but non-nop fields present")

    if form == "noargs":
        return DecodedZen5Operands(form, mnemonic, mnemonic, "inferred", {}, note)

    return DecodedZen5Operands("unknown", None, None, "inferred",
                               {"opcode": tag.opcode}, "unhandled operand form")


def zen5_uop_operand_text(tag: DecodedZen5Tag,
                          prev_word: Optional[int] = None) -> str:
    """Rendered operand string for one micro-op, or '?' when unmodeled."""
    return decode_zen5_operands(tag, prev_word).asm or "?"


@dataclass(frozen=True)
class DecodedZen5OpQuad:
    offset: int
    raw: bytes
    uops: Tuple[DecodedZen5Tag, ...]
    sequence_word: int


def decode_zen5_opquad(record: bytes, offset: int = 0) -> DecodedZen5OpQuad:
    """Decode a 36-byte op-quad: four 8-byte micro-ops + a 4-byte raw sequence word."""
    if len(record) != ZEN5_OPQUAD_SIZE:
        raise ValueError(
            f"Zen5 op-quad must be exactly {ZEN5_OPQUAD_SIZE} bytes; got {len(record)}"
        )
    uops = tuple(
        decode_zen5_tag(
            record[i * ZEN5_RECORD_SIZE:(i + 1) * ZEN5_RECORD_SIZE],
            offset + i * ZEN5_RECORD_SIZE,
        )
        for i in range(ZEN5_UOPS_PER_QUAD)
    )
    seq_off = ZEN5_UOPS_PER_QUAD * ZEN5_RECORD_SIZE
    sequence_word = int.from_bytes(record[seq_off:seq_off + ZEN5_SEQUENCE_SIZE], "little")
    return DecodedZen5OpQuad(
        offset=offset,
        raw=bytes(record),
        uops=uops,
        sequence_word=sequence_word,
    )


def iter_zen5_opquads(
    payload: bytes,
    base_offset: int = ZEN5_OPQUAD_OFFSET,
    strict: bool = True,
) -> Iterable[DecodedZen5OpQuad]:
    """Yield decoded op-quads from the payload starting at base_offset.

    strict=True requires the full op-quad region (ZEN5_OPQUAD_COUNT records);
    strict=False accepts any whole number of 36-byte records.
    """
    if strict and len(payload) != ZEN5_OPQUAD_COUNT * ZEN5_OPQUAD_SIZE:
        raise ValueError(
            f"Zen5 op-quad region must be exactly "
            f"0x{ZEN5_OPQUAD_COUNT * ZEN5_OPQUAD_SIZE:x} bytes; got 0x{len(payload):x}"
        )
    if base_offset < 0:
        raise ValueError("base_offset must be non-negative")
    if len(payload) % ZEN5_OPQUAD_SIZE:
        raise ValueError("Incomplete 36-byte record; retain the remainder as raw bytes")
    count = len(payload) // ZEN5_OPQUAD_SIZE
    for index in range(count):
        start = index * ZEN5_OPQUAD_SIZE
        yield decode_zen5_opquad(
            payload[start:start + ZEN5_OPQUAD_SIZE],
            base_offset + start,
        )


@lru_cache(maxsize=1)
def load_zen5_opcode_names() -> Dict[int, str]:
    """Read the *same* literal ZEN_OPCODE_ENUM used by the BN plugin.

    The CLI must not import Binary Ninja merely to obtain the opcode names, and
    a second copied opcode table would drift away from the user's additions.
    Parse the sibling source as data (ast.literal_eval), never execute it.
    The first spelling of a duplicate value is canonical; all aliases remain
    present in the BN enumeration. Pass an explicit map to render helpers to
    override the table. Clear this cache after editing it in a live session.
    """
    path = Path(__file__).with_name("amd_zen_ucode.py")
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "ZEN_OPCODE_ENUM"
                for target in node.targets
            ):
                values = ast.literal_eval(node.value)
                if not isinstance(values, dict) or not values:
                    raise ValueError("ZEN_OPCODE_ENUM must be a nonempty literal dictionary")
                names: Dict[int, str] = {}
                for name, value in values.items():
                    if not isinstance(name, str) or type(value) is not int or value < 0:
                        raise ValueError("Opcode tags require string names and non-negative integer values")
                    # Only 8-bit values name a word by its [47:55] opcode slice. Values > 0xFF are
                    # synthetic members (e.g. LdStOp LD/ST resolved by class + the ldst bit) that
                    # no 8-bit opcode ever addresses; they live only in the BN enumeration.
                    if value <= 0xFF:
                        names.setdefault(value, name)
                return names
        raise ValueError("ZEN_OPCODE_ENUM was not found")
    except (OSError, SyntaxError, ValueError, TypeError) as exc:
        raise ValueError(f"Cannot load opcode names from {path}: {exc}") from exc


def zen5_uop_field_text(tag: DecodedZen5Tag, tag_names: Optional[Dict[int, str]] = None,
                        prev_word: Optional[int] = None,
                        sequence_words: Optional[frozenset] = None) -> str:
    """Restore the original enum tag and field display; no per-word warning spam.

    Every mapping supplied by the caller is honored. In particular the NOP
    pattern resolves to AMD_ZEN_SPEC_NOP and TYPE5_READ is not filtered out.
    Unknown values stay numeric rather than acquiring an invented mnemonic.

    The original field display is preserved verbatim. For nonzero words an
    additional ` asm=<operands>` segment is appended (a strict line suffix) with
    the inferred per-opcode operand decode; zero words keep the exact prior line.
    """
    names = load_zen5_opcode_names() if tag_names is None else tag_names
    class_name = OPCLASS_NAMES.get(tag.exec_unit, f"0b{tag.exec_unit:03b}")
    name = zen5_opcode_label(tag, names)
    text = (
        f"opcode={name} "
        f"rd=r{tag.rd} rs=r{tag.rs} rt=r{tag.rt} imm16=0x{tag.imm16:04x} "
        f"size={tag.size} ld={tag.load} st={tag.store} class={tag.exec_unit} ({class_name})"
    )
    if tag.word == 0:
        return text + " (zero word)"
    if zen5_is_alignment_artifact(tag):
        low32 = tag.word & 0xFFFFFFFF
        seq_note = ", low32=seq word" if sequence_words and low32 in sequence_words else ""
        return text + f" (align-artifact?: top32=0{seq_note})"
    return text + " asm=" + zen5_uop_operand_text(tag, prev_word)


def render_zen5_opquad_lines(
    payload: bytes,
    tag_names: Optional[Dict[int, str]] = None,
    base_offset: int = ZEN5_OPQUAD_OFFSET,
) -> Sequence[str]:
    """List every complete record; do not hide zeros or discard incomplete data."""
    quads = list(iter_zen5_opquads(payload, base_offset, strict=False))
    # Patch-wide sequence words: used to corroborate alignment artifacts (a "uop" whose top 32
    # bits are zero and whose low 32 bits equal a sequence word is a framing artifact).
    sequence_words = frozenset(q.sequence_word for q in quads)
    # Overlay sections (NOP / finalization) keyed by their starting op-quad offset. Descriptive
    # only op-quad parsing above is unchanged.
    section_banner = {
        s["offset"]: f"--- {s['label']}: 0x{s['offset']:04x}..0x{s['end']:04x} "
                     f"({s['quad_count']} op-quads) ---"
        for s in zen5_detect_body_sections(quads, base_offset)
    }
    lines = []
    for index, quad in enumerate(quads):
        if quad.offset in section_banner:
            lines.append(section_banner[quad.offset])
        lines.append(f"0x{quad.offset:04x}: opquad[{index:03d}]")
        for slot, tag in enumerate(quad.uops):
            prev_word = quad.uops[slot - 1].word if slot else None
            lines.append(f"    uop{slot} 0x{tag.offset:04x}: "
                         f"{zen5_uop_field_text(tag, tag_names, prev_word, sequence_words)}")
        lines.append(f"    sequence_word 0x{quad.offset + 32:04x}: 0x{quad.sequence_word:08x} ; "
                     + decode_zentool_sequence_word(quad.sequence_word).text)
    return lines


@dataclass(frozen=True)
class ContainerGeometry:
    format_id: int
    match_dwords: int
    quad_count: int

    @property
    def quad_offset(self) -> int:
        return EXTENDED_HEADER_SIZE + 4 * self.match_dwords

    @property
    def patch_size(self) -> int:
        return self.quad_offset + self.quad_count * 36


# Exact upstream loader table, independent of CPU marketing names.
ZENTOOL_FORMATS = {
    0x8004: ContainerGeometry(0x8004, 22, 64),
    0x8005: ContainerGeometry(0x8005, 38, 128),
    0x8010: ContainerGeometry(0x8010, 60, 370),
    0x8015: ContainerGeometry(0x8015, 60, 370),
}


@dataclass(frozen=True)
class LoaderLayout:
    """File geometry, not a claim about the hardware's register allocation.

    register_dwords covers the entire area after the extended header.
    register_split is a named display interpretation, not hardware validation.
    register_split_basis preserves its provenance in reports and serialized JSON.
    """
    format_id: int
    quad_offset: int
    quad_count: int
    patch_size: int
    provenance: str
    register_split: Optional[Tuple[int, int]] = None
    register_split_basis: str = "unsplit upstream table"

    def __post_init__(self) -> None:
        if self.quad_offset < EXTENDED_HEADER_SIZE or self.register_size % 4:
            raise ValueError("Register area must consist of whole DWORDs after the header")
        if self.quad_count <= 0 or self.code_end > self.patch_size:
            raise ValueError("Operation records exceed the selected patch extent")
        if self.register_split is not None:
            if (len(self.register_split) != 2
                    or any(type(n) is not int or n <= 0 for n in self.register_split)
                    or sum(self.register_split) != self.register_dwords):
                raise ValueError(
                    f"Explicit match/mask counts must be positive and sum to "
                    f"{self.register_dwords} DWORDs for loader 0x{self.format_id:04x}")

    @property
    def register_offset(self) -> int:
        return EXTENDED_HEADER_SIZE

    @property
    def register_size(self) -> int:
        return self.quad_offset - EXTENDED_HEADER_SIZE

    @property
    def register_dwords(self) -> int:
        return self.register_size // 4

    @property
    def code_end(self) -> int:
        return self.quad_offset + self.quad_count * ZEN5_OPQUAD_SIZE

    @property
    def auxiliary_size(self) -> int:
        return self.patch_size - self.code_end


# ONE source for parser, BN types, and CLI boundaries. Every default layout is
# the exact-fit zentool geometry, where nquad is chosen so the body closes on
# the patch with no trailing bytes: header(0x328) + nmatch*4 + nquad*36 == size.
# For every supported format this holds by construction (auxiliary_size == 0),
# so the default path never emits an "auxiliary_raw" tail. The former 0x420/256
# research profile (which left a 0x1000 aux tail) is retained separately below
# and is reachable ONLY through mode="sample-420", never as a default.
ZENELLA_LOADER_LAYOUTS = {
    fmt: LoaderLayout(fmt, g.quad_offset, g.quad_count, g.patch_size, "zentool")
    for fmt, g in ZENTOOL_FORMATS.items()
}

# Experimental, non-default: Zenella's two-sample B110 research profile. It puts
# 256 quads at 0x420 and leaves 0x1000 of unexplained trailing data (aux), so it
# is NOT exact-fit. Kept only for the "(Experimental)" menu item / --layout.
SAMPLE_420_LAYOUT = LoaderLayout(
    0x8015, 0x420, 256, 0x3820, "Zenella 0x420 profile; two supplied B110 samples")

# Source for the *example* organization, not the later-loader extrapolations:
# https://bughunters.google.com/blog/zen-and-the-art-of-microcode-hacking
# Fig. 3: 0x320 options/revision, 0x328 match, 0x350 mask, 0x380 microcode.
# Its arrays are 10 and 12 DWORDs. "Half and half" only holds when the
# 8-byte options/revision header is included in the first half.
def diagram_register_split(quad_offset: int) -> Tuple[int, int]:
    """Scale the Fig. 3 organization; geometry inference, NOT hardware proof.

    Divide [OPTIONS_OFFSET, quad_offset) into two equal byte spans. The first
    contains OPTIONS_SIZE + REVISION_COPY_SIZE bytes followed by match words;
    the second contains mask words. Never infer counts from nonzero contents.
    """
    header_bytes = OPTIONS_SIZE + REVISION_COPY_SIZE
    if type(quad_offset) is not int:
        raise ValueError("Body offset must be an integer")
    span = quad_offset - OPTIONS_OFFSET
    if span <= header_bytes * 2 or span % 8:
        raise ValueError("Diagram-scaled metadata requires two whole-DWORD halves")
    half = span // 2
    return (half - header_bytes) // 4, half // 4


# Equal match/mask display partition per exact-fit profile. zentool models only
# match registers (each match_t holds two 13-bit compares); the mask half is a
# Zenella extension. The register area is split into two equal DWORD halves, so
# match_count == mask_count. Every register_dwords value below is even, so the
# equal split is exact: 0x8004 -> 11/11, 0x8005 -> 19/19, 0x8010/0x8015 -> 30/30.
# Passing --register-split (register_split=) overrides these. Non-default profiles
# with an odd register_dword count fall back to the unsplit register_table.
ZENELLA_REGISTER_SPLITS: Dict[Tuple[int, int], Tuple[int, int]] = {
    (0x8004, 0x380): (11, 11),
    (0x8005, 0x3C0): (19, 19),
    (0x8010, 0x418): (30, 30),
    (0x8015, 0x418): (30, 30),
}


def get_loader_layout(format_id: int, mode: str = "loader",
                      register_split: Optional[Tuple[int, int]] = None) -> LoaderLayout:
    """Select loader geometry and a separately attributed display interpretation.

    The zentool comparison is left UNSPLIT unless the caller explicitly requests
    a split; it continues to read 60 DWORDs and 370 quads for 0x8010/0x8015.
    """
    if format_id not in ZENTOOL_FORMATS:
        raise ValueError(f"Unsupported loader format 0x{format_id:04x}")
    if mode == "zentool":
        g = ZENTOOL_FORMATS[format_id]
        result = LoaderLayout(format_id, g.quad_offset, g.quad_count, g.patch_size, "zentool")
    elif mode == "sample-420":
        if format_id not in (0x8010, 0x8015):
            raise ValueError("The explicit 0x420 profile requires loader 0x8010 or 0x8015")
        result = replace(SAMPLE_420_LAYOUT, format_id=format_id)
    elif mode in ("auto", "loader", "raw", "exact"):
        # "exact" forces the exact-fit geometry with an equal split and skips the
        # content auto-detection that auto/loader apply in parse_zen5_patch; it is
        # the explicit no-trailing-bytes view for 0x8010/0x8015.
        result = ZENELLA_LOADER_LAYOUTS[format_id]
        # Exact-fit: the loader id sets the body boundary so that header +
        # registers + opquads consumes every byte, with no trailing tail.
        assert result.auxiliary_size == 0, (
            f"Loader 0x{format_id:04x} default layout is not exact-fit "
            f"(auxiliary_size=0x{result.auxiliary_size:x}); body would leave trailing bytes")
    else:
        raise ValueError(f"Unsupported layout {mode!r}")
    if register_split is not None:
        return replace(result, register_split=tuple(register_split),
                       register_split_basis="explicit researcher-supplied interpretation")
    if mode == "zentool":
        return result
    # Default and sample-420: split the register area into two equal DWORD halves
    # so the match and mask registers are equal in width. An explicit table entry
    # wins; otherwise fall back to computed equal halves when the count is even.
    split = ZENELLA_REGISTER_SPLITS.get((format_id, result.quad_offset))
    if split is None and result.register_dwords % 2 == 0:
        split = (result.register_dwords // 2,) * 2
    if split is None:
        return result
    basis = ("equal match/mask partition (Zenella extension; zentool models only match "
             "registers, so the mask half is inferred and hardware capacities are unverified)"
             if split[0] == split[1] else "configured researcher-supplied interpretation")
    return replace(result, register_split=tuple(split), register_split_basis=basis)


@dataclass(frozen=True)
class ZentoolSequenceFields:
    """The exact ucode.h seqword_t bit projection; not a Zen5 control-flow lift."""
    word: int
    action: int
    target: int
    nodelay: bool
    other_bits: int

    @property
    def action_name(self) -> str:
        return {0: "RELATIVE", 2: "ABSOLUTE"}.get(self.action, f"ACTION_0x{self.action:x}")

    @property
    def text(self) -> str:
        # Do not apply ZenUtils' bit-0 shortcut to arbitrary Zen5 sequence words.
        # In zentool action is bits 16..19, not just the low two bits.
        if self.word == 1:
            return "zentool: RELATIVE +1 (next quad)"
        text = f"zentool fields: action={self.action_name} target=0x{self.target:x}"
        if self.nodelay:
            text += " nodelay=1"
        if self.other_bits:
            text += f" other_bits=0x{self.other_bits:08x}"
        return text


def decode_zentool_sequence_word(word: int) -> ZentoolSequenceFields:
    """Project ucode.h: target[0:12], action[16:19], nodelay[20].

    Sources: google/security-research/.../zentool/ucode.h (seqword_t),
    disas.c (dump_sequence_word), docs/intro.md (Sequence Words).
    All remaining bits are retained. This does not change the original
    Zen1/Zen2 decode_sequence_word() or any LLIL control flow.
    """
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        raise ValueError("Sequence word must be an unsigned 32-bit integer")
    known = 0x1FFF | (0xF << 16) | (1 << 20)
    return ZentoolSequenceFields(word, (word >> 16) & 0xF, word & 0x1FFF,
                                bool(word & (1 << 20)), word & ~known)


def zen5_sequence_statistics(quads: Sequence[DecodedZen5OpQuad]) -> dict:
    """Count stored DWORD values without normalizing or replacing any sequence."""
    ones = [q for q in quads if q.sequence_word == 1]
    return {
        "count": len(quads),
        "exact_one_count": len(ones),
        "exact_one_offsets": [q.offset + 32 for q in ones],
        "exact_one_all_nop_quads": sum(
            all(u.word == ZENTOOL_NOP_WORD for u in q.uops) for q in ones),
        "histogram": {f"0x{k:08x}": v for k, v in
                      sorted(Counter(q.sequence_word for q in quads).items())},
        "interpretation": "1 is relative +1 in zentool; the full Zen5 control word is not established",
    }


@dataclass(frozen=True)
class PatchRegion:
    name: str
    offset: int
    raw: bytes
    interpretation: str

    @property
    def end(self) -> int:
        return self.offset + len(self.raw)


@dataclass(frozen=True)
class ParsedZen5Patch:
    header: PatchHeader
    sha256: str
    layout: str
    confidence: str
    warnings: Tuple[str, ...]
    regions: Tuple[PatchRegion, ...]
    quads: Tuple[DecodedZen5OpQuad, ...]
    base: int = 0
    geometry: Optional[LoaderLayout] = None
    options: Optional[PatchOptions] = None
    selector_offset: Optional[int] = None  # relative to patch, not containing file

    @property
    def patch_bytes(self) -> bytes:
        """Lossless in-memory reconstruction including opaque and appended bytes."""
        return b"".join(region.raw for region in self.regions)


def _bounded(data: bytes, start: int, size: int) -> bytes:
    if start < 0 or size < 0 or start + size > len(data):
        raise ValueError(f"Out-of-bounds region: offset=0x{start:x}, size=0x{size:x}")
    return bytes(data[start:start + size])


def header_date_iso(header: PatchHeader) -> str:
    """BCD date is MMDDYYYY as a little-endian dword; reject invalid BCD/date."""
    digits = f"{header.date:08x}"
    if any(c not in "0123456789" for c in digits):
        raise ValueError(f"Invalid BCD patch date 0x{header.date:08x}")
    return date(int(digits[4:8]), int(digits[:2]), int(digits[2:4])).isoformat()


def zen5_420_evidence(data: bytes, header: Optional[PatchHeader] = None) -> dict:
    """Guard the empirical B110/8015 profile with reproducible content checks.

    These checks are heuristics derived from the two supplied revisions, not
    vendor format validation. They never use opcode-name coverage, so adding
    or deleting a mnemonic cannot change where records are placed.
    """
    if header is None:
        header = parse_patch_header(data)
    complete = len(data) >= ZEN5_PATCH_SIZE
    checks = {
        "loader_8015": (len(data) >= OPTIONS_OFFSET + OPTIONS_SIZE
                        and parse_patch_options(data).loaderid == 0x8015),
        "processor_b110": header.processor_signature == 0xB110,
        "complete_patch": complete,
        "plaintext_flag": complete and data[OPTIONS_OFFSET + 1] == 0,
    }
    if not complete:
        return {"supported": False, "checks": checks}
    aligned = candidate_metrics(data, ZEN5_OPQUAD_OFFSET, ZEN5_OPQUAD_COUNT)
    upstream = candidate_metrics(data, ZENTOOL_ZEN5_OPQUAD_OFFSET, ZEN5_OPQUAD_COUNT)
    following = candidate_metrics(data, ZEN5_AUX_OFFSET, 32)
    last_words = struct.unpack_from("<4QI", data, ZEN5_AUX_OFFSET - ZEN5_OPQUAD_SIZE)
    checks.update({
        "extra_dwords_zero": data[ZEN5_PREFIX_OFFSET:ZEN5_OPQUAD_OFFSET] == bytes(8),
        "many_exact_nop_words": aligned["exact_zentool_nop_words"] >= 64,
        "more_complete_nops_than_418": aligned["exact_zentool_nop_words"] > upstream["exact_zentool_nop_words"],
        "class0_words_all_exact_nops": aligned["class0_other_than_exact_nop"] == 0,
        "all_256_sequences_nonzero": aligned["nonzero_sequences"] == ZEN5_OPQUAD_COUNT,
        "last_quad_nop_fill": last_words == (ZENTOOL_NOP_WORD,) * 4 + (1,),
        "following_region_changes_pattern": following["exact_zentool_nop_words"] == 0
            and following["class0_other_than_exact_nop"] > 0,
    })
    return {"supported": all(checks.values()), "checks": checks,
            "at_420": aligned, "at_418": upstream, "following_region": following}


# Loaders whose real body sits at +0x420 (256 quads + a 0x1000 tail) rather than
# tiling exactly from +0x418. 0x420 is NOT reachable by whole 36-byte records to
# the patch end (0x3820 % 36 == 4, but 0x420 % 36 == 12), so it cannot be chosen
# by an "exact-fit" rule; it must be detected from the op-quad/sequence content.
ZEN5_AUTODETECT_LOADERS = (0x8010, 0x8015)


def zen5_autodetect_body(data: bytes, header: Optional[PatchHeader] = None) -> Tuple[str, str]:
    """Pick the +0x420/256 or +0x418/370 body for 0x8010/0x8015 from the content.

    Returns (layout_mode, reason). +0x418 tiles the patch with no trailing bytes
    but, on updates whose real body is at +0x420, it reads every 36-byte record
    8 bytes early and the 32-bit sequence words collapse to 0x0. +0x420 keeps the
    documented +1 (0x1) sequence words. Decision, in order:
      1) The validated B110 profile (zen5_420_evidence) -> +0x420.
      2) Otherwise compare alignment at +0x420 vs +0x418: prefer +0x420 when it
         yields strictly more nonzero sequence words and no fewer exact NOP words.
      3) Otherwise +0x418/370 exact-fit (also the fallback for incomplete data).
    This is a descriptive content heuristic, never hardware validation.
    """
    if header is None:
        header = parse_patch_header(data)
    if len(data) < ZEN5_PATCH_SIZE:
        return "loader", "incomplete data; using +0x418/370 exact-fit"
    evidence = zen5_420_evidence(data, header)
    if evidence["supported"]:
        return "sample-420", ("validated B110 +0x420 profile "
                              "(256 nonzero sequence words, last quad NOP*4 + seqword 1)")
    m420 = candidate_metrics(data, ZEN5_OPQUAD_OFFSET, ZEN5_OPQUAD_COUNT)
    m418 = candidate_metrics(data, ZENTOOL_ZEN5_OPQUAD_OFFSET, ZEN5_OPQUAD_COUNT)
    if (m420["nonzero_sequences"] > m418["nonzero_sequences"]
            and m420["exact_zentool_nop_words"] >= m418["exact_zentool_nop_words"]):
        return "sample-420", (
            f"+0x420 aligns better than +0x418 "
            f"(nonzero sequence words {m420['nonzero_sequences']} vs {m418['nonzero_sequences']}, "
            f"seqword==1 {m420['sequence_one_count']} vs {m418['sequence_one_count']})")
    return "loader", (
        f"+0x420 shows no alignment advantage "
        f"(nonzero sequence words {m420['nonzero_sequences']} vs {m418['nonzero_sequences']}); "
        f"using +0x418/370 exact-fit")


def zen5_fit_equal_registers(data: bytes, lo: int = 4, hi: int = 48) -> dict:
    """Search equal match=mask register sizes placed BEFORE the microcode.

    For each size M (match[M] + mask[M] DWORDs at 0x328), the op-quads begin at
    0x328 + 8*M and fill the rest of the patch. Ranks sizes by sequence-word
    validity at that offset (fewest top-nibble-junk sequence words, then most
    nonzero, then most seqword==1). Descriptive alignment heuristic; the
    match/mask counts themselves are not documented hardware capacities.
    """
    psz = min(len(data), ZEN5_PATCH_SIZE)
    cands = []
    for m in range(lo, hi + 1):
        off = EXTENDED_HEADER_SIZE + 8 * m
        space = psz - off
        if space < ZEN5_OPQUAD_SIZE:
            continue
        quads = space // ZEN5_OPQUAD_SIZE
        rem = space - quads * ZEN5_OPQUAD_SIZE
        n = min(256, quads)
        me = candidate_metrics(data, off, n, 4)
        cands.append({
            "match_mask": m, "quad_offset": off, "quad_count": quads, "remainder": rem,
            "records_scored": n, "nonzero_sequences": me["nonzero_sequences"],
            "sequence_top_nibble_nonzero": me["sequence_top_nibble_nonzero"],
            "sequence_one_count": me["sequence_one_count"],
            "valid": me["sequence_top_nibble_nonzero"] <= max(1, n // 50) and me["nonzero_sequences"] == n,
        })
    cands.sort(key=lambda c: (c["sequence_top_nibble_nonzero"],
                              -c["nonzero_sequences"], -c["sequence_one_count"]))
    return {"note": "No documented evidence for these counts; empirical sequence-alignment ranking.",
            "candidates": cands, "best": cands[0] if cands else None}


def zen5_trailing_zero_start(data: bytes, end: Optional[int] = None) -> int:
    """Offset where the maximal run of trailing 0x00 bytes (ending at `end`) begins.

    `end` defaults to the patch extent (min of the data length and ZEN5_PATCH_SIZE).
    Returns `end` when the byte immediately before `end` is nonzero (no padding).
    """
    if end is None:
        end = min(len(data), ZEN5_PATCH_SIZE)
    end = min(end, len(data))
    i = end
    while i > 0 and data[i - 1] == 0:
        i -= 1
    return i


def zen5_body_padding_start(data: bytes, quad_offset: int, end: Optional[int] = None) -> int:
    """Where the trailing zero padding begins, seen from the op-quad grid at `quad_offset`.

    The raw trailing-zero start (first of the maximal run of 0x00 bytes) can fall INSIDE the
    last op-quad: a zero sequence word is RELATIVE target 0, a self-pointing terminator, and a
    terminator quad may also end in zero uops. Such a quad is microcode, not padding, so the
    boundary is moved to the end of the op-quad that contains the raw start whenever that
    quad still holds a nonzero byte. Returns the raw start when it is already on the grid, the
    quad containing it is entirely zero, or `quad_offset` is not before it.
    """
    if end is None:
        end = min(len(data), ZEN5_PATCH_SIZE)
    raw = zen5_trailing_zero_start(data, end)
    if quad_offset < 0 or raw <= quad_offset:
        return raw
    into = (raw - quad_offset) % ZEN5_OPQUAD_SIZE
    if into == 0:
        return raw
    quad_start = raw - into
    quad_end = quad_start + ZEN5_OPQUAD_SIZE
    if quad_end > end:
        return raw
    if any(data[quad_start:raw]):
        return quad_end
    return raw


def zen5_manual_fit(match_count: int, mask_count: int, data: Optional[bytes] = None) -> dict:
    """Op-quad geometry for a manual match/mask register boundary, plus fit guidance.

    The match/mask registers occupy match_count + mask_count DWORDs starting at
    0x328, so the op-quads begin at 0x328 + 4*(match+mask). When `data` is supplied
    and the patch has trailing zero padding, the body ends where that padding begins
    (padding_start); otherwise it fills the patch. Because op-quads are fixed 36-byte
    records, the body meets the boundary cleanly (tail_bytes == 0) only for certain
    totals; exact_fit_totals lists the nearest such match+mask totals. These counts
    are not documented hardware capacities.
    """
    total = match_count + mask_count
    quad_offset = EXTENDED_HEADER_SIZE + 4 * total
    padding_start = ZEN5_PATCH_SIZE
    if data is not None:
        # Grid-aware: a terminator quad whose zero sequence word (or trailing zero uops) starts
        # the zero run stays in the body; the padding begins after it.
        ps = zen5_body_padding_start(data, quad_offset, ZEN5_PATCH_SIZE)
        if ps > quad_offset:
            padding_start = ps
    body_end = padding_start
    avail = body_end - quad_offset
    quad_count = avail // ZEN5_OPQUAD_SIZE if avail > 0 else 0
    tail_bytes = avail - quad_count * ZEN5_OPQUAD_SIZE if quad_count > 0 else max(0, avail)
    padding_bytes = ZEN5_PATCH_SIZE - padding_start
    max_total = (body_end - EXTENDED_HEADER_SIZE - ZEN5_OPQUAD_SIZE) // 4
    # Nearest totals whose body tiles in whole op-quads exactly up to body_end. Search
    # a window rather than a modular formula so a non-4-aligned padding_start is handled.
    hits = []
    for t in range(max(2, total - 45), total + 46):
        av = body_end - (EXTENDED_HEADER_SIZE + 4 * t)
        if av > 0 and av % ZEN5_OPQUAD_SIZE == 0:
            hits.append(t)
    below = max((t for t in hits if t <= total), default=None)
    above = min((t for t in hits if t >= total), default=None)
    exact = sorted({t for t in (below, above) if t is not None})
    return {"quad_offset": quad_offset, "quad_count": quad_count,
            "tail_bytes": tail_bytes, "padding_start": padding_start,
            "padding_bytes": padding_bytes, "exact_fit_totals": exact, "max_total": max_total}


def zen5_tail_holds_registers(geometry: "LoaderLayout") -> bool:
    """Opt-in: True only for the experimental 'tail' layout.

    The DEFAULT and every other mode place match/mask registers BEFORE the
    microcode (documented Google Project Zero / zentool order). The experimental
    'tail' layout instead places metadata before the op-quads and the equal
    match/mask registers AFTER them (op-quads at 0x420 => valid sequences, the
    0x2820 region IS the register table => no trailer). It is selected only via
    layout='tail', marked by the geometry provenance.
    """
    return bool(geometry is not None and getattr(geometry, "provenance", "").startswith("tail-model"))


def _fixed_register_geometry(selector: int, match_count: int, mask_count: int, data: bytes,
                             provenance: str, label: str, evidence_note: str,
                             basis: Optional[str] = None) -> Tuple["LoaderLayout", dict, str]:
    """Geometry for fixed match/mask register counts placed BEFORE the op-quads.

    The op-quads begin at 0x328 + 4*(match+mask) and fill the patch up to the trailing
    zero padding (zen5_manual_fit), so the padding is a separate region instead of being
    decoded as zero op-quads. Shared by the confirmed 0x8015 default (31/31) and the
    experimental manual layout. Returns (geometry, fit, reason_text).
    """
    total = match_count + mask_count
    fit = zen5_manual_fit(match_count, mask_count, data)
    if fit["quad_count"] <= 0:
        boundary = ("the detected zero padding at "
                    f"0x{fit['padding_start']:x}" if fit["padding_bytes"]
                    else f"the patch end 0x{ZEN5_PATCH_SIZE:x}")
        raise ValueError(
            f"match+mask={total} DWORDs leaves no room for op-quads before {boundary}; "
            f"the total must be at most {fit['max_total']} DWORDs")
    # Fill the body to the padding boundary (or patch end when there is no padding);
    # a clean fit leaves no bytes between the last op-quad and the padding.
    kwargs = {} if basis is None else {"register_split_basis": basis}
    geometry = LoaderLayout(
        selector, fit["quad_offset"], fit["quad_count"], ZEN5_PATCH_SIZE, provenance,
        register_split=(match_count, mask_count), **kwargs)
    reason = (f"{label} -> op-quads at 0x{fit['quad_offset']:x}, {fit['quad_count']} quads"
              + evidence_note)
    if fit["padding_bytes"]:
        reason += (
            f"; auto-detected {fit['padding_bytes']} zero-padding bytes from "
            f"0x{fit['padding_start']:x}")
        if fit["tail_bytes"]:
            reason += (
                f"; {fit['tail_bytes']} bytes remain between the body and the padding -- "
                f"for a clean body|padding split use a match+mask total of "
                f"{fit['exact_fit_totals']} (any split summing to that)")
        else:
            reason += "; body meets the padding exactly (no bytes between)"
    elif fit["tail_bytes"]:
        reason += (
            f"; no trailing padding; {fit['tail_bytes']} bytes remain before the patch end -- "
            f"for zero tail use a match+mask total of {fit['exact_fit_totals']} "
            f"(any split summing to that)")
    else:
        reason += "; no trailing padding; exact fit to the patch end"
    return geometry, fit, reason


def parse_zen5_patch(data: bytes, base: int = 0, layout: str = "auto",
                     register_split: Optional[Tuple[int, int]] = None) -> ParsedZen5Patch:
    """Read-only parser; the loader id selects both the header end and the body.

    auto/loader: LE16 at +0x322 selects the loader. For 0x8015 (Zen5c) the
    confirmed geometry is applied: match[31] + mask[31] registers at 0x328
    (ZEN5_8015_REGISTER_SPLIT), op-quads from +0x420 up to the trailing zero
    padding. Other loaders use the exact-fit ZENELLA_LOADER_LAYOUTS geometry
    (0x8010 searches equal match/mask sizes for valid sequence words).
    zentool mode instead uses +0x08 and leaves the register area unsplit.
    The experimental sample-420 mode reproduces the old +0x420/256 profile
    (which leaves a 0x1000 tail). A loader-id mismatch between +0x08 and +0x322
    is reported, not silently repaired. Truncated/encrypted data is not decoded.
    """
    header = parse_patch_header(data, base)
    if header.effective_family_model[0] != 0x1A:
        raise ValueError("Zen5 analysis requires compact processor revision for Family 1Ah")
    available = len(data) - base
    options = (parse_patch_options(data, base)
               if available >= OPTIONS_OFFSET + OPTIONS_SIZE else None)
    selector_offset = (0x08 if layout == "zentool" else
                       SECONDARY_LOADER_OFFSET if options is not None else None)
    # A first-header fallback is ONLY a length estimate for incomplete/raw data.
    selector = (header.loader_id if layout == "zentool" or options is None
                else options.loaderid)
    if selector not in ZENTOOL_FORMATS:
        location = ("+0x08" if layout == "zentool" or options is None else "+0x322")
        raise ValueError(f"Unsupported loader ID 0x{selector:04x} at {location}; "
                         "no layout was applied and no boundary was guessed")
    # For the big loaders the correct body offset (+0x420 vs +0x418) is decided
    # from the op-quad/sequence-word content, not by an exact-fit rule, so the
    # documented +1 sequence words are not shifted into 0x0. Explicit modes
    # (zentool/sample-420) and an explicit --register-split are left untouched.
    effective_layout = layout
    autodetect_reason = None
    manual_fit = None
    if layout == "scan":
        if selector not in ZEN5_AUTODETECT_LOADERS:
            raise ValueError("The scan layout applies to loader 0x8010/0x8015 only")
        best = zen5_scan_body_offsets(data[base:])["best"]
        if best is None or best["register_dwords"] % 2:
            geometry = get_loader_layout(selector, "loader", register_split)
            autodetect_reason = (f"scan best offset unsuitable (odd register area); "
                                 f"used exact-fit 0x{geometry.quad_offset:x}/{geometry.quad_count}")
        else:
            regdw = best["register_dwords"]
            off = best["offset"]
            quad_count = min(256, (ZEN5_PATCH_SIZE - off) // ZEN5_OPQUAD_SIZE)
            geometry = LoaderLayout(
                selector, off, quad_count, ZEN5_PATCH_SIZE,
                "scan-selected (experimental; no documented evidence)",
                register_split=(regdw // 2, regdw // 2))
            autodetect_reason = (
                f"scan-selected body 0x{off:x}/{quad_count} quads, match/mask "
                f"{regdw // 2}/{regdw // 2}; top-nibble-junk seqwords="
                f"{best['sequence_top_nibble_nonzero']}, nonzero_seq="
                f"{best['nonzero_sequences']}/{best['records_scored']}, "
                f"seq==1 {best['sequence_one_count']}")
    elif layout == "tail":
        # Experimental: metadata before the op-quads, equal match/mask registers
        # AFTER them. Op-quads at 0x420 (valid sequences) and the 0x2820 region is
        # the register table, so no trailer and no 0x0 sequences at once.
        if selector not in ZEN5_AUTODETECT_LOADERS:
            raise ValueError("The tail layout applies to loader 0x8010/0x8015 only")
        geometry = LoaderLayout(
            selector, ZEN5_OPQUAD_OFFSET, ZEN5_OPQUAD_COUNT, ZEN5_PATCH_SIZE,
            "tail-model: metadata before op-quads, equal match/mask after",
            register_split=((ZEN5_OPQUAD_OFFSET - EXTENDED_HEADER_SIZE) // 8,) * 2)
        autodetect_reason = (
            "tail model: op-quads at 0x420 (valid sequences), equal match/mask registers in the "
            f"0x{geometry.code_end:x} tail (two halves of {geometry.auxiliary_size // 8} DWORDs), no trailer")
    elif layout == "manual":
        # Experimental: the caller sets the match and mask register counts directly,
        # so the op-quad boundary moves to 0x328 + 4*(match+mask). Unlike an ordinary
        # register split (which only re-partitions a fixed area), these counts DEFINE
        # the register-area size. No documented evidence backs any particular size.
        if selector not in ZEN5_AUTODETECT_LOADERS:
            raise ValueError("The manual layout applies to loader 0x8010/0x8015 only")
        if register_split is None:
            raise ValueError("The manual layout needs match:mask register DWORD counts")
        match_count, mask_count = register_split
        if (type(match_count) is not int or type(mask_count) is not int
                or match_count <= 0 or mask_count <= 0):
            raise ValueError("Manual match/mask register counts must be positive integers")
        geometry, manual_fit, autodetect_reason = _fixed_register_geometry(
            selector, match_count, mask_count, data[base:],
            "manual researcher-set match/mask register counts (experimental; no documented evidence)",
            f"manual match[{match_count}]/mask[{mask_count}]",
            "; no documented evidence backs this size")
    elif (layout in ("auto", "loader") and register_split is None
            and selector == 0x8015 and available >= ZEN5_PATCH_SIZE):
        # Confirmed Zen5c / 0x8015 geometry: match[31] + mask[31] registers at 0x328,
        # op-quads from 0x420 up to the trailing zero padding.
        match_count, mask_count = ZEN5_8015_REGISTER_SPLIT
        geometry, manual_fit, autodetect_reason = _fixed_register_geometry(
            selector, match_count, mask_count, data[base:],
            f"confirmed 0x{selector:04x} layout: match[{match_count}]/mask[{mask_count}] "
            "registers at 0x328, op-quads from 0x420",
            f"confirmed loader 0x{selector:04x} match[{match_count}]/mask[{mask_count}]", "",
            basis=f"confirmed {match_count}/{mask_count} match/mask partition for Zen5c loader 0x{selector:04x}")
    elif (layout in ("auto", "loader") and register_split is None
            and selector in ZEN5_AUTODETECT_LOADERS and available >= ZEN5_PATCH_SIZE):
        # Other big loaders (0x8010): equal match=mask registers BEFORE the microcode;
        # the size is searched so the op-quad offset yields sensible (non-0x0) sequence words.
        fit = zen5_fit_equal_registers(data[base:])
        best = fit["best"]
        m = best["match_mask"]
        geometry = LoaderLayout(
            selector, best["quad_offset"], best["quad_count"], ZEN5_PATCH_SIZE,
            "before-code equal match/mask, size-searched for valid sequences",
            register_split=(m, m))
        autodetect_reason = (
            f"searched equal match/mask sizes; best match[{m}]/mask[{m}] -> op-quads at "
            f"0x{best['quad_offset']:x}, {best['quad_count']} quads, {best['remainder']}-byte remainder; "
            f"sequences nonzero={best['nonzero_sequences']}/{best['records_scored']}, "
            f"top-nibble-junk={best['sequence_top_nibble_nonzero']}, seq==1={best['sequence_one_count']}")
    else:
        geometry = get_loader_layout(selector, effective_layout, register_split)
    size = min(available, geometry.patch_size)
    blob = _bounded(data, base, size)
    digest = hashlib.sha256(blob).hexdigest()
    chosen = "loader" if layout == "auto" else layout
    warnings = [
        "Opcode names and bitfields preserve the supplied Zenella mapping; no hardware execution semantics are inferred.",
        "No signature/checksum, decryption-correctness or hardware validation was performed.",
        "Sequence annotations use zentool's field projection; no Zen5 control-flow lift is performed.",
    ]
    if autodetect_reason is not None:
        warnings.append(
            f"Auto-detected body offset 0x{geometry.quad_offset:x}/"
            f"{geometry.quad_count} quads for loader 0x{selector:04x}: {autodetect_reason}.")
    if options is None:
        warnings.append("Second header is incomplete; the first header supplies only a raw extent estimate.")
        chosen = "raw"
    elif options.loaderid != header.loader_id:
        warnings.append(
            f"Loader ID mismatch: first header +0x08=0x{header.loader_id:04x}, "
            f"second header +0x322=0x{options.loaderid:04x}; "
            + ("zentool comparison uses +0x08." if layout == "zentool" else
               "Zenella uses the explicitly displayed second-header loaderid at +0x322."))
    complete = size == geometry.patch_size
    encrypted = size > OPTIONS_OFFSET + 1 and blob[OPTIONS_OFFSET + 1] != 0
    if not complete:
        warnings.append(f"Incomplete patch: 0x{size:x}/0x{geometry.patch_size:x} bytes; retaining raw data.")
        chosen = "raw"
    if encrypted:
        warnings.append("Encrypted flag is nonzero; instruction interpretation disabled.")
        chosen = "raw"
    if available > geometry.patch_size:
        warnings.append(f"0x{available - geometry.patch_size:x} appended bytes retained separately.")
    if size >= REVISION_COPY_OFFSET + 4:
        rev_copy = int.from_bytes(blob[REVISION_COPY_OFFSET:REVISION_COPY_OFFSET + 4], "little")
        if rev_copy != header.revision:
            warnings.append(f"Revision mismatch: header 0x{header.revision:08x}, copy 0x{rev_copy:08x}.")
    confidence = "raw-only" if chosen == "raw" else (
        "upstream-reference-only" if geometry.provenance == "zentool" else "loader-selected-research-profile")
    if chosen != "raw":
        if geometry.provenance == SAMPLE_420_LAYOUT.provenance:
            warnings.append(
                "0x420/256 is Zenella's two-sample research profile, not zentool's 0x418/370 boundary.")
            evidence = zen5_420_evidence(blob, header)
            if not evidence["supported"]:
                failed = ", ".join(k for k, v in evidence["checks"].items() if not v)
                warnings.append("Selected 0x420 profile differs from the tested sample patterns: " + failed)
        if zen5_tail_holds_registers(geometry):
            warnings.append(
                f"Match/mask registers follow the op-quads at 0x{geometry.code_end:x}, split into two "
                f"equal halves of {geometry.auxiliary_size // 8} DWORDs each; the "
                f"0x{geometry.register_offset:x} pre-op-quad block is high-entropy metadata, not "
                "match registers. The op-quad offset (the boundary that keeps sequence words sensible) "
                "is set by the metadata size and is chosen by auto-detect/scan. Record sub-format undocumented.")
        elif geometry.register_split is None:
            warnings.append(
                "Register-area extent is known for this profile; separate match/mask counts are not established.")
        else:
            warnings.append("Match/mask display: " + geometry.register_split_basis
                            + "; these tests do not establish hardware register capacities.")
    regions = []
    def add(name: str, offset: int, length: int, interpretation: str) -> None:
        take = min(length, max(0, size - offset))
        if take:
            regions.append(PatchRegion(name, base + offset, _bounded(blob, offset, take), interpretation))
    for name, offset, length in (
        ("header", 0, HEADER_SIZE), ("signature", SIGNATURE_OFFSET, SIGNATURE_SIZE),
        ("modulus", MODULUS_OFFSET, MODULUS_SIZE), ("check", CHECK_OFFSET, CHECK_SIZE),
        ("options", OPTIONS_OFFSET, OPTIONS_SIZE), ("revision_copy", REVISION_COPY_OFFSET, REVISION_COPY_SIZE),
    ):
        interpretation = "AMD microcode container " + name
        if name == "options":
            interpretation = ("autorun, encrypted, uint16_t loaderid; "
                              "Zenella profile selector is the stored LE16 at +0x322")
        elif name == "revision_copy":
            interpretation = "Revision copy from the extended header area"
        add(name, offset, length, interpretation)
    quads = ()
    if chosen == "raw":
        add("opaque_payload", EXTENDED_HEADER_SIZE, geometry.patch_size - EXTENDED_HEADER_SIZE, "uninterpreted")
    else:
        tail_regs = zen5_tail_holds_registers(geometry)
        if tail_regs:
            # The pre-op-quad block on these profiles is high-entropy metadata,
            # NOT match/mask registers (those follow the code, see below).
            add("prefix_metadata", geometry.register_offset, geometry.register_size,
                f"Loader 0x{geometry.format_id:04x}: {geometry.register_dwords} DWORDs of "
                "high-entropy metadata before the op-quads; not match/mask registers "
                "in observed Zen5 samples")
        elif geometry.register_split is None:
            add("register_table", geometry.register_offset, geometry.register_size,
                f"Loader 0x{geometry.format_id:04x} profile: {geometry.register_dwords} register-area DWORDs; "
                f"opquads at 0x{geometry.quad_offset:x}; no inferred match/mask split")
        else:
            match_count, mask_count = geometry.register_split
            add("match_registers", geometry.register_offset, match_count * 4,
                f"Loader 0x{geometry.format_id:04x}: match_reg[{match_count}]; "
                + geometry.register_split_basis)
            add("mask_registers", geometry.register_offset + match_count * 4, mask_count * 4,
                f"Loader 0x{geometry.format_id:04x}: mask_reg[{mask_count}]; "
                + geometry.register_split_basis)
        payload = _bounded(blob, geometry.quad_offset, geometry.quad_count * ZEN5_OPQUAD_SIZE)
        add("opquads", geometry.quad_offset, len(payload),
            f"{geometry.quad_count} opquads: four tagged uint64 operations + one stored uint32 sequence word")
        quads = tuple(iter_zen5_opquads(payload, base + geometry.quad_offset, strict=False))
        if geometry.auxiliary_size:
            if tail_regs:
                # Match/mask registers follow the op-quads, split into two equal
                # DWORD halves. 13-bit ROM addresses + control in the match half,
                # 0xffffffff/partial masks in the mask half; unused slots zero.
                half = geometry.auxiliary_size // 2
                add("match_registers", geometry.code_end, half,
                    f"Loader 0x{geometry.format_id:04x}: match_reg[{half // 4}] after the op-quads "
                    "(13-bit ROM match addresses + control); equal half of the post-code register area")
                add("mask_registers", geometry.code_end + half, geometry.auxiliary_size - half,
                    f"Loader 0x{geometry.format_id:04x}: mask_reg[{half // 4}] after the op-quads "
                    "(0xffffffff/partial masks); equal half; unused trailing slots are zero-filled")
            elif manual_fit is not None and manual_fit["padding_bytes"] > 0:
                # Manual layout: the body ends at the auto-detected zero padding. Any bytes
                # between the last whole op-quad and the padding are shown as a small tail
                # the user can remove by adjusting the match+mask total (see the warning).
                pad_off = manual_fit["padding_start"]
                gap = pad_off - geometry.code_end
                if gap > 0:
                    add("opquad_tail", geometry.code_end, gap,
                        "leftover bytes between the last op-quad and the auto-detected zero "
                        "padding; adjust the match+mask total to remove (see warning)")
                add("zero_padding", pad_off, geometry.patch_size - pad_off,
                    "auto-detected trailing zero padding at the end of the patch; not microcode")
            else:
                add("auxiliary_raw", geometry.code_end, geometry.auxiliary_size, "Stored DWORD data after the candidate opquad array; displayed inside body.data_words; purpose unverified")
    if available > size:
        regions.append(PatchRegion("appended_data", base + size, bytes(data[base + size:]), "outside the fixed-size patch"))
    cursor = base
    for region in regions:
        if region.offset != cursor:
            raise AssertionError("Internal region coverage error")
        cursor = region.end
    if cursor != len(data):
        raise AssertionError("Internal region coverage error at EOF")
    return ParsedZen5Patch(header, digest, chosen, confidence, tuple(warnings), tuple(regions), quads, base, geometry,
                           options, selector_offset)


def zen5_display_regions(parsed: ParsedZen5Patch) -> Tuple[PatchRegion, ...]:
    """Return a gap-free GUI view with one body and no separate trailer object.

    Analysis regions retain the distinction between opquads and data. Grouping
    them into one visible aggregate does not convert data into instructions.
    All source bytes remain in order and are represented exactly once.
    """
    result = []
    for index, region in enumerate(parsed.regions):
        if region.name == "auxiliary_raw":
            if not result or result[-1].name != "body" or result[-1].end != region.end:
                raise ValueError("Body data must immediately follow the opquad region")
            continue
        if region.name != "opquads":
            result.append(region)
            continue
        following = parsed.regions[index + 1] if index + 1 < len(parsed.regions) else None
        data = region.raw
        note = region.interpretation
        if following is not None and following.name == "auxiliary_raw":
            if following.offset != region.end or len(following.raw) % 4:
                raise ValueError("Noncontiguous or non-DWORD body data")
            data += following.raw
            note += f"; followed by {len(following.raw) // 4} stored data_words (purpose unverified)"
        result.append(PatchRegion("body", region.offset, data, note))
    if b"".join(r.raw for r in result) != parsed.patch_bytes:
        raise AssertionError("Display aggregation lost or reordered bytes")
    return tuple(result)


def candidate_metrics(data: bytes, start: int, count: int, uops_per_record: int = 4) -> dict:
    """Transparent alignment diagnostics, not a probability or ISA validity score.

    Counts compare equally sized record samples. Zero words are NOT NOP matches.
    class3==0 is only assessed against the exact upstream NOP pattern. Sequence
    frequencies are descriptive, not accepted/rejected based on an invented mask.
    """
    if uops_per_record not in (3, 4) or count <= 0 or start < 0:
        raise ValueError("Expected non-negative start, positive count and 3 or 4 words")
    stride = uops_per_record * 8 + 4
    _bounded(data, start, count * stride)
    words, sequences = [], []
    for index in range(count):
        pos = start + index * stride
        words.extend(struct.unpack_from("<" + "Q" * uops_per_record, data, pos))
        sequences.append(struct.unpack_from("<I", data, pos + uops_per_record * 8)[0])
    class0 = [word for word in words if ((word >> 59) & 7) == 0]
    return {
        "start": start, "end": start + count * stride, "records": count,
        "stride": stride, "uops_per_record": uops_per_record, "word_count": len(words),
        "zero_words": words.count(0), "exact_zentool_nop_words": words.count(ZENTOOL_NOP_WORD),
        "class0_words": len(class0),
        "class0_other_than_exact_nop": sum(word != ZENTOOL_NOP_WORD for word in class0),
        "nonzero_sequences": sum(word != 0 for word in sequences),
        "sequence_one_count": sequences.count(1),
        "sequence_top_nibble_nonzero": sum(word >> 28 != 0 for word in sequences),
        "sequence_common": [[f"0x{word:08x}", n] for word, n in Counter(sequences).most_common(12)],
        "class3_histogram": dict(sorted(Counter((word >> 59) & 7 for word in words).items())),
    }


def zen5_alignment_diagnostics(data: bytes, base: int = 0) -> dict:
    """Compare 9 dword phases for quads, 7 for triads, and the upstream full view."""
    blob = _bounded(data, base, ZEN5_PATCH_SIZE)
    return {
        "note": "Descriptive metrics, not ISA proof; loader profiles select boundaries; content checks only report discrepancies.",
        "profile_420_evidence": zen5_420_evidence(blob),
        "quads_256_by_phase": [candidate_metrics(blob, 0x400 + p * 4, 256, 4) for p in range(9)],
        "triads_256_by_phase": [candidate_metrics(blob, 0x400 + p * 4, 256, 3) for p in range(7)],
        "zentool_418_first_256": candidate_metrics(blob, 0x418, 256),
        "sample_420_256": candidate_metrics(blob, 0x420, 256),
        "zentool_418_all_370": candidate_metrics(blob, 0x418, 370),
        "post_2820_first_32_quads": candidate_metrics(blob, 0x2820, 32),
    }


def _shannon_entropy(data: bytes) -> float:
    """Byte-wise Shannon entropy in bits/byte (0.0 for empty)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 4) + 0.0


def analyze_zen5_tail(data: bytes, start: int, size: int) -> dict:
    """Descriptive, read-only classification of the post-op-quad tail region.

    Reports byte/DWORD statistics and tests several structural hypotheses for the
    bytes at [start, start+size) WITHOUT asserting any hardware meaning. Intended
    for the 0x2820..0x3820 (0x1000) region left after 256 op-quads at 0x420. The
    numbers are content diagnostics, not a decode; a concrete interpretation still
    requires corroborating real decrypted samples.
    """
    region = _bounded(data, start, size)
    dwords = list(struct.unpack_from("<" + "I" * (size // 4), region)) if size >= 4 else []
    qwords = list(struct.unpack_from("<" + "Q" * (size // 8), region)) if size >= 8 else []
    stats = {
        "offset": start, "end": start + size, "size": size,
        "nonzero_bytes": sum(b != 0 for b in region),
        "trailing_zero_bytes": len(region) - len(region.rstrip(b"\x00")),
        "leading_zero_bytes": len(region) - len(region.lstrip(b"\x00")),
        "entropy_bits_per_byte": _shannon_entropy(region),
        "dword_count": len(dwords),
        "distinct_dwords": len(set(dwords)),
        "zero_dwords": dwords.count(0),
        "nop_qwords": qwords.count(ZENTOOL_NOP_WORD),
        "dword_common": [[f"0x{w:08x}", n] for w, n in Counter(dwords).most_common(8)],
    }
    hypotheses = {}
    # H1: continuation of 36-byte op-quads (4x u64 + u32 seqword).
    q_records, q_rem = divmod(size, ZEN5_OPQUAD_SIZE)
    h1 = {"records": q_records, "remainder_bytes": q_rem, "clean_tiling": q_rem == 0}
    if q_records > 0:
        h1["metrics"] = candidate_metrics(region, 0, q_records, 4)
    hypotheses["opquads_36B"] = h1
    # H2: array of 32-byte records (e.g. bare op-quads without interleaved seqword).
    r32, rem32 = divmod(size, 32)
    hypotheses["records_32B"] = {"records": r32, "remainder_bytes": rem32, "clean_tiling": rem32 == 0}
    # H3: match_t[] array (each u32: m1[0:12], _u1[13], m2[14:26], _u2[27], pad[28:31]).
    match_like = sum(1 for w in dwords if ((w >> 28) & 0xF) == 0)
    hypotheses["match_t_array"] = {
        "dwords": len(dwords),
        "dwords_with_zero_top_nibble": match_like,
        "fraction_match_shaped": round(match_like / len(dwords), 4) if dwords else 0.0,
    }
    return {
        "note": "Descriptive content diagnostics only; not a decode or hardware validation.",
        "stats": stats,
        "structural_hypotheses": hypotheses,
    }


def zen5_scan_body_offsets(data: bytes, base: int = 0, start: int = 0x380,
                           stop: int = 0x464, step: int = 4, records: int = 256) -> dict:
    """Rank candidate op-quad offsets by sequence-word reasonableness.

    There is NO documented evidence for the register-area size (op-quad offset)
    or the match/mask split; zentool models only match registers and its 0x8015
    counts are guesses. Enlarging or shrinking the total register area moves the
    op-quad offset and therefore the 32-bit sequence-word alignment (the match-vs-
    mask split within the area does NOT affect alignment). This scans dword-aligned
    offsets and scores each by how "reasonable" its sequence words look, using a
    fixed record window so offsets compare fairly. Purely descriptive, not proof.

    Score keys per offset (from candidate_metrics): a well-aligned offset has few
    sequence words with a nonzero top nibble (bits 28..31 should be padding),
    every sequence word nonzero, and many exact NOP op-words. Candidates are
    sorted best-first by (sequence_top_nibble_nonzero asc, nonzero_sequences desc,
    exact_zentool_nop_words desc).
    """
    blob = _bounded(data, base, min(len(data) - base, ZEN5_PATCH_SIZE))
    patch_size = len(blob)
    candidates = []
    for off in range(start, stop, step):
        if off < EXTENDED_HEADER_SIZE or (off - EXTENDED_HEADER_SIZE) % 4:
            continue
        fit = (patch_size - off) // ZEN5_OPQUAD_SIZE
        n = min(records, fit)
        if n <= 0:
            continue
        m = candidate_metrics(blob, off, n, 4)
        regdw = (off - EXTENDED_HEADER_SIZE) // 4
        junk = m["sequence_top_nibble_nonzero"]
        candidates.append({
            "offset": off,
            "register_dwords": regdw,
            "match_mask": (regdw // 2, regdw // 2) if regdw % 2 == 0 else None,
            "records_scored": n,
            "tail_bytes": (patch_size - off) - fit * ZEN5_OPQUAD_SIZE,
            "nonzero_sequences": m["nonzero_sequences"],
            "sequence_one_count": m["sequence_one_count"],
            "sequence_top_nibble_nonzero": junk,
            "exact_nop_words": m["exact_zentool_nop_words"],
            "reasonable": junk <= max(1, n // 50) and m["nonzero_sequences"] == n,
        })
    candidates.sort(key=lambda c: (c["sequence_top_nibble_nonzero"],
                                   -c["nonzero_sequences"], -c["exact_nop_words"]))
    return {
        "note": ("No documented evidence exists for these boundaries; ranking is an "
                 "empirical sequence-word alignment heuristic, not hardware validation."),
        "records_window": records,
        "candidates": candidates,
        "best": candidates[0] if candidates else None,
    }


__all__: Sequence[str] = (
    "CORE_VERSION", "SECONDARY_LOADER_OFFSET", "PatchOptions", "parse_patch_options",
    "zen5_display_regions",
    "LoaderLayout", "ZENELLA_LOADER_LAYOUTS", "ZENELLA_REGISTER_SPLITS", "get_loader_layout",
    "ZentoolSequenceFields", "decode_zentool_sequence_word", "zen5_sequence_statistics",
    "load_zen5_opcode_names",
    "zen5_420_evidence",
    "ZEN5_PRECODE_OFFSET",
    "ZEN5_PRECODE_SIZE",
    "ZEN5_REFERENCE_SHA256S",
    "EXTENDED_HEADER_SIZE",
    "ZEN5_MATCH_ENTRY_COUNT",
    "ZEN5_PREFIX_OFFSET",
    "ZEN5_PREFIX_SIZE",
    "ZEN5_AUX_OFFSET",
    "ZEN5_AUX_SIZE",
    "ZENTOOL_ZEN5_OPQUAD_OFFSET",
    "ZENTOOL_ZEN5_OPQUAD_COUNT",
    "ZEN5_8015_REGISTER_SPLIT",
    "ZENTOOL_ZEN5_OPQUAD_REGION_SIZE",
    "ZENTOOL_NOP_WORD",
    "ZEN5_REFERENCE_SHA256",
    "ContainerGeometry",
    "PatchRegion",
    "ParsedZen5Patch",
    "ZENTOOL_FORMATS",
    "parse_zen5_patch",
    "candidate_metrics",
    "zen5_alignment_diagnostics",
    "analyze_zen5_tail",
    "zen5_autodetect_body",
    "zen5_scan_body_offsets",
    "zen5_fit_equal_registers",
    "zen5_manual_fit",
    "zen5_body_padding_start",
    "zen5_trailing_zero_start",
    "zen5_tail_holds_registers",
    "ZEN5_AUTODETECT_LOADERS",
    "header_date_iso",

    "BRANCH_NAMES",
    "CHECK_OFFSET",
    "CHECK_SIZE",
    "CPUID_PART_TO_PROFILE",
    "DecodedMatchEntry",
    "DecodedSequenceWord",
    "DecodedUop",
    "DecodedZen5OpQuad",
    "DecodedZen5Tag",
    "DetectionResult",
    "HEADER_OFFSET",
    "HEADER_SIZE",
    "MODULUS_OFFSET",
    "MODULUS_SIZE",
    "OPTIONS_OFFSET",
    "OPTIONS_SIZE",
    "PatchHeader",
    "PROFILES",
    "REGISTERS",
    "REVISION_COPY_OFFSET",
    "REVISION_COPY_SIZE",
    "SEGMENTS",
    "SIGNATURE_OFFSET",
    "SIGNATURE_SIZE",
    "SIZE_CODE_TO_BYTES",
    "ZenProfile",
    "ZEN1",
    "ZEN2",
    "ZEN5",
    "ZEN12_INSTRUCTION_SIZE",
    "ZEN12_INSTRUCTIONS_PER_PACKAGE",
    "ZEN12_MATCH_ENTRY_COUNT",
    "ZEN12_MATCH_OFFSET",
    "ZEN12_MATCH_SIZE",
    "ZEN12_PACKAGE_COUNT",
    "ZEN12_PACKAGE_SIZE",
    "ZEN12_PATCH_SIZE",
    "ZEN12_PAYLOAD_OFFSET",
    "ZEN12_PAYLOAD_SIZE",
    "ZEN12_ROM_START",
    "ZEN12_SEQUENCE_SIZE",
    "ZEN5_MATCH_OFFSET",
    "ZEN5_MATCH_SIZE",
    "ZEN5_OPQUAD_COUNT",
    "ZEN5_OPQUAD_OFFSET",
    "ZEN5_OPQUAD_REGION_SIZE",
    "ZEN5_OPQUAD_SIZE",
    "ZEN5_PATCH_SIZE",
    "ZEN5_PAYLOAD_OFFSET",
    "ZEN5_PAYLOAD_SIZE",
    "ZEN5_RECORD_COUNT",
    "ZEN5_RECORD_SIZE",
    "ZEN5_SEQUENCE_SIZE",
    "ZEN5_UOPS_PER_QUAD",
    "decode_match_entries",
    "decode_match_entry",
    "decode_sequence_word",
    "decode_uop",
    "decode_zen5_opquad",
    "decode_zen5_tag",
    "detect_profile",
    "disassemble_uop",
    "expanded_cpuid_from_processor_signature",
    "family_model_stepping_from_processor_signature",
    "get_profile",
    "iter_package_words",
    "iter_zen5_opquads",
    "package_offset",
    "parse_patch_header",
    "profile_from_processor_signature",
    "render_zen5_opquad_lines",
    "zen5_uop_field_text",
    "rom_address_to_payload_offset",
    "rom_address_to_slot",
    "slot_to_rom_address",
    "ZEN1_PROC_REV_PARTS",
    "ZEN2_PROC_REV_PARTS",
    "ZEN5_PROC_REV_PARTS",
)
