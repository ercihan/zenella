#####################################################################################################
#####################################################################################################
#####################################################################################################
# Author: Kaya Ercihan
# Version: 2.0.4
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

from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Sequence, Tuple


#####################################################################################################
# Shared update container offsets
#####################################################################################################
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
# Current Zenella Zen5 structural profile
#####################################################################################################
ZEN5_MATCH_OFFSET = 0x0328
ZEN5_MATCH_SIZE = 0x0028
ZEN5_MASK_OFFSET = 0x0350
ZEN5_MASK_SIZE = 0x0030
ZEN5_PAYLOAD_OFFSET = 0x0380
ZEN5_PATCH_SIZE = 0x3820
ZEN5_PAYLOAD_SIZE = ZEN5_PATCH_SIZE - ZEN5_PAYLOAD_OFFSET
# Each Zen5 payload record is a 4-byte structural tag: opcode(u8) b1(u8) imm16(u16)
# This is a container tag, not a decoded Zen5 instruction
ZEN5_RECORD_SIZE = 4

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
            f"{identification} identifies {by_cpuid.name}{trailing_text}",
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
# Zen5 structural tag rendering (experimental)
#
# Zen5 ISA semantics are not documented, so the payload is only structurally
# tagged: each 4-byte record is opcode(u8) b1(u8) imm16(u16), where opcode maps to
# the published AMD_Zen_Opcode structural-tag names. This renders those existing
# tags as an assembly-like listing; it is NOT a real Zen5 instruction decode.
#####################################################################################################
@dataclass(frozen=True)
class DecodedZen5Tag:
    offset: int
    raw: bytes
    opcode: int
    b1: int
    imm16: int


def decode_zen5_tag(record: bytes, offset: int = 0) -> DecodedZen5Tag:
    if len(record) != ZEN5_RECORD_SIZE:
        raise ValueError(
            f"Zen5 record must be exactly {ZEN5_RECORD_SIZE} bytes; got {len(record)}"
        )
    return DecodedZen5Tag(
        offset=offset,
        raw=bytes(record),
        opcode=record[0],
        b1=record[1],
        imm16=int.from_bytes(record[2:4], "little"),
    )


def _zen5_tag_mnemonic(opcode: int, tag_names: Dict[int, str]) -> Tuple[str, Optional[str]]:
    """Return (display_mnemonic, full_tag_name). Unknown opcodes fall back to .op."""
    full = tag_names.get(opcode)
    if full is None:
        return (f".op 0x{opcode:02x}", None)
    # Strip the shared AMD_ZEN_ prefix for a compact mnemonic column
    display = full
    for prefix in ("AMD_ZEN_REG_", "AMD_ZEN_SPEC_", "AMD_ZEN_"):
        if display.startswith(prefix):
            display = display[len(prefix):]
            break
    return (display.lower(), full)


def render_zen5_tag_lines(
    payload: bytes,
    tag_names: Dict[int, str],
    base_offset: int = ZEN5_PAYLOAD_OFFSET,
) -> Sequence[str]:
    """Render the Zen5 payload as one assembly-like line per 4-byte structural tag.

    Trailing all-zero records are collapsed into a single elision note so the
    listing stays readable without silently dropping data.
    """
    usable = len(payload) - (len(payload) % ZEN5_RECORD_SIZE)
    records = [
        decode_zen5_tag(payload[i:i + ZEN5_RECORD_SIZE], base_offset + i)
        for i in range(0, usable, ZEN5_RECORD_SIZE)
    ]

    # Determine how many trailing zero records to elide
    last_meaningful = len(records)
    while last_meaningful > 0 and records[last_meaningful - 1].raw == b"\x00\x00\x00\x00":
        last_meaningful -= 1

    lines = []
    for tag in records[:last_meaningful]:
        mnemonic, full = _zen5_tag_mnemonic(tag.opcode, tag_names)
        comment = f"  ; {full} (tag)" if full else "  ; unknown structural tag"
        lines.append(
            f"0x{tag.offset:04x}: "
            f"{tag.opcode:02x} {tag.b1:02x} {tag.imm16 & 0xff:02x} {(tag.imm16 >> 8) & 0xff:02x}  "
            f"{mnemonic:<16} b1=0x{tag.b1:02x} imm16=0x{tag.imm16:04x}{comment}"
        )

    elided = len(records) - last_meaningful
    if elided:
        lines.append(f"; ... {elided} trailing all-zero record(s) elided")
    if usable != len(payload):
        lines.append(f"; note: {len(payload) - usable} trailing byte(s) below record size ignored")
    return lines


__all__: Sequence[str] = (
    "BRANCH_NAMES",
    "CHECK_OFFSET",
    "CHECK_SIZE",
    "CPUID_PART_TO_PROFILE",
    "DecodedMatchEntry",
    "DecodedSequenceWord",
    "DecodedUop",
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
    "ZEN5_MASK_OFFSET",
    "ZEN5_MASK_SIZE",
    "ZEN5_MATCH_OFFSET",
    "ZEN5_MATCH_SIZE",
    "ZEN5_PATCH_SIZE",
    "ZEN5_PAYLOAD_OFFSET",
    "ZEN5_PAYLOAD_SIZE",
    "ZEN5_RECORD_SIZE",
    "decode_match_entries",
    "decode_match_entry",
    "decode_sequence_word",
    "decode_uop",
    "decode_zen5_tag",
    "detect_profile",
    "disassemble_uop",
    "expanded_cpuid_from_processor_signature",
    "family_model_stepping_from_processor_signature",
    "get_profile",
    "iter_package_words",
    "package_offset",
    "parse_patch_header",
    "profile_from_processor_signature",
    "render_zen5_tag_lines",
    "rom_address_to_payload_offset",
    "rom_address_to_slot",
    "slot_to_rom_address",
    "ZEN1_PROC_REV_PARTS",
    "ZEN2_PROC_REV_PARTS",
    "ZEN5_PROC_REV_PARTS",
)
