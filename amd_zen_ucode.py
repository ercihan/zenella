#####################################################################################################
#####################################################################################################
#####################################################################################################
# Author: Kaya Ercihan
# Version: 2.0.4
# Description: Parse AMD Zen microcode updates and lift Zen1 and Zen2 microcode in Binary Ninja
# Self-containment: define data types, patch layouts, decoders, LLIL lifting and plugin commands
# License: GPL-3.0-only
#####################################################################################################
#####################################################################################################
#####################################################################################################
"""Zenella: AMD Zen microcode container parsing and Zen1/Zen2 lifting.

This module keeps the original Zenella structural workflow for Zen5 updates and
adds a ZenUtils-compatible Zen1/Zen2 decoder as a Binary Ninja architecture.
Binary Ninja derives MLIL and HLIL from the LLIL emitted by that architecture.

The Zen1/Zen2 ISA knowledge is intentionally conservative: documented ZenUtils
encodings are disassembled and lifted where their data-flow is established.
Unknown operations retain known destination/flag clobbers and otherwise use
LLIL_UNIMPL rather than inventing unsupported semantics.
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from binaryninja import (
    Architecture,
    BranchType,
    Endianness,
    EnumerationBuilder,
    FlagRole,
    InstructionInfo,
    InstructionTextToken,
    InstructionTextTokenType,
    LowLevelILLabel,
    PluginCommand,
    QualifiedName,
    RegisterInfo,
    SectionSemantics,
    SegmentFlag,
    StructureBuilder,
    Symbol,
    SymbolType,
    Type,
    log_error,
    log_info,
    log_warn,
    show_plain_text_report,
)

try:  # Normal package import
    from .zenella_core import (
        CHECK_OFFSET,
        CHECK_SIZE,
        HEADER_SIZE,
        MODULUS_OFFSET,
        MODULUS_SIZE,
        OPTIONS_OFFSET,
        OPTIONS_SIZE,
        REGISTERS,
        REVISION_COPY_OFFSET,
        REVISION_COPY_SIZE,
        SEGMENTS,
        SIGNATURE_OFFSET,
        SIGNATURE_SIZE,
        SIZE_CODE_TO_BYTES,
        ZEN1,
        ZEN2,
        ZEN5,
        ZEN12_INSTRUCTION_SIZE,
        ZEN12_INSTRUCTIONS_PER_PACKAGE,
        ZEN12_MATCH_ENTRY_COUNT,
        ZEN12_MATCH_OFFSET,
        ZEN12_MATCH_SIZE,
        ZEN12_PACKAGE_COUNT,
        ZEN12_PACKAGE_SIZE,
        ZEN12_PATCH_SIZE,
        ZEN12_PAYLOAD_OFFSET,
        ZEN12_PAYLOAD_SIZE,
        ZEN12_ROM_START,
        ZEN5_MASK_OFFSET,
        ZEN5_MASK_SIZE,
        ZEN5_MATCH_OFFSET,
        ZEN5_MATCH_SIZE,
        ZEN5_PATCH_SIZE,
        ZEN5_PAYLOAD_OFFSET,
        ZEN5_PAYLOAD_SIZE,
        DecodedSequenceWord,
        DecodedUop,
        ZenProfile,
        decode_match_entries,
        decode_sequence_word,
        decode_uop,
        detect_profile,
        iter_package_words,
        parse_patch_header,
        render_zen5_tag_lines,
        rom_address_to_payload_offset,
        rom_address_to_slot,
        slot_to_rom_address,
    )
except ImportError:  # Direct import for manual development use
    from zenella_core import (  # type: ignore
        CHECK_OFFSET,
        CHECK_SIZE,
        HEADER_SIZE,
        MODULUS_OFFSET,
        MODULUS_SIZE,
        OPTIONS_OFFSET,
        OPTIONS_SIZE,
        REGISTERS,
        REVISION_COPY_OFFSET,
        REVISION_COPY_SIZE,
        SEGMENTS,
        SIGNATURE_OFFSET,
        SIGNATURE_SIZE,
        SIZE_CODE_TO_BYTES,
        ZEN1,
        ZEN2,
        ZEN5,
        ZEN12_INSTRUCTION_SIZE,
        ZEN12_INSTRUCTIONS_PER_PACKAGE,
        ZEN12_MATCH_ENTRY_COUNT,
        ZEN12_MATCH_OFFSET,
        ZEN12_MATCH_SIZE,
        ZEN12_PACKAGE_COUNT,
        ZEN12_PACKAGE_SIZE,
        ZEN12_PATCH_SIZE,
        ZEN12_PAYLOAD_OFFSET,
        ZEN12_PAYLOAD_SIZE,
        ZEN12_ROM_START,
        ZEN5_MASK_OFFSET,
        ZEN5_MASK_SIZE,
        ZEN5_MATCH_OFFSET,
        ZEN5_MATCH_SIZE,
        ZEN5_PATCH_SIZE,
        ZEN5_PAYLOAD_OFFSET,
        ZEN5_PAYLOAD_SIZE,
        DecodedSequenceWord,
        DecodedUop,
        ZenProfile,
        decode_match_entries,
        decode_sequence_word,
        decode_uop,
        detect_profile,
        iter_package_words,
        parse_patch_header,
        render_zen5_tag_lines,
        rom_address_to_payload_offset,
        rom_address_to_slot,
        slot_to_rom_address,
    )


PLUGIN_VERSION = "2.0.4"
SYNTHETIC_REGION_ALIGNMENT = 0x10000
SYNTHETIC_REGION_MASK = ~(SYNTHETIC_REGION_ALIGNMENT - 1)
CODE_LABEL_SYMBOL = getattr(SymbolType, "LocalLabelSymbol", SymbolType.DataSymbol)


#####################################################################################################
# Names and common data layout helpers
#####################################################################################################

T_LOADER_ENUM = "AMD_MC_LoaderIdTag"
T_CPUID = "AMD_MC_CpuId"
T_HEADER = "AMD_MC_Header"
T_OPTIONS = "AMD_MC_UcodeOptions"
T_ZEN12_OPTIONS = "AMD_Zen12_UcodeOptions"
T_ZEN12_MATCH = "AMD_Zen12_MatchEntry"
T_ZEN12_PACKAGE = "AMD_Zen12_InstructionPackage"
T_ZEN12_PAYLOAD = "AMD_Zen12_ExecutablePayload"
T_ZEN12_PATCH = "AMD_Zen12_Patch"
T_ZEN5_MATCH = "AMD_Zen5_MatchRegisterBlock"
T_ZEN5_MASK = "AMD_Zen5_MaskRegisterBlock"
T_ZEN5_TAG = "AMD_Zen5_MicroOpTag"
T_ZEN5_PAYLOAD = "AMD_Zen5_MicrocodeRegion"
T_ZEN5_PATCH = "AMD_Zen5_Patch"

# Keep the Zenella 1.2 type names for existing Binary Ninja databases
# Scripts, screenshots and research notes may still use these names
# New work uses the generation specific names above
T_LEGACY_OPCODE = "AMD_Zen_Opcode"
T_LEGACY_MATCH = "AMD_MC_MatchRegisterBlock"
T_LEGACY_MASK = "AMD_MC_MaskRegisterBlock"
T_LEGACY_UOP = "AMD_Zen_MicroOp"
T_LEGACY_PAYLOAD = "AMD_Zen_MicrocodeRegion"
T_LEGACY_PATCH = "AMD_MC_Patch"

LOADER_ID_ENUM = {
    "AMD_MC_LOADER_8004": 0x8004,
    "AMD_MC_LOADER_8005": 0x8005,
    "AMD_MC_LOADER_8010": 0x8010,
    "AMD_MC_LOADER_8015": 0x8015,
    "AMD_MC_LOADER_8016": 0x8016,
}

# Keep the Zenella 1.2 enum ABI exactly as published
# Existing BNDBs, scripts, screenshots and research notes depend on these names and values
# The opcode byte is only a structural tag
# It is not a complete Zen5 instruction decode
ZEN_OPCODE_ENUM = {
    # Opcodes whose meaning depends on the instruction class
    "AMD_ZEN_UOP_LD_ST_00":        0x00,
    "AMD_ZEN_BR_JMP":              0x05,

    # RegOp and RegX opcodes
    "AMD_ZEN_REG_NSUB":             0x19,
    "AMD_ZEN_REG_AND":              0x30,
    "AMD_ZEN_REG_SHL":              0x40,
    "AMD_ZEN_REG_BLL":              0x41,
    "AMD_ZEN_REG_ROL":              0x42,
    "AMD_ZEN_REG_RLC":              0x44,
    "AMD_ZEN_REG_RRD":              0x46,
    "AMD_ZEN_REG_SRC":              0x47,
    "AMD_ZEN_REG_SHR":              0x48,
    "AMD_ZEN_REG_ROR":              0x4A,
    "AMD_ZEN_REG_RRC":              0x4C,
    "AMD_ZEN_REG_SRD":              0x4F,
    "AMD_ZEN_REG_SUB":              0x50,
    "AMD_ZEN_REG_SBB":              0x52,
    "AMD_ZEN_REG_NADD":             0x55,
    "AMD_ZEN_REG_ADD2":             0x5C,
    "AMD_ZEN_REG_ADC":              0x5D,
    "AMD_ZEN_REG_ADD3":             0x5E,
    "AMD_ZEN_REG_ADD":              0x5F,
    "AMD_ZEN_REG_VZEROUPPER_64B":   0x6F,
    "AMD_ZEN_REG_POPCNT":           0x70,
    "AMD_ZEN_REG_SBIT":             0x72,
    "AMD_ZEN_REG_VZEROUPPER_32B":   0x7F,
    "AMD_ZEN_REG_MOV2":             0x93,
    "AMD_ZEN_REG_MOV_SREG":         0xA0,
    "AMD_ZEN_REG_BSWAP":            0xA9,
    "AMD_ZEN_REG_XOR":              0xB5,
    "AMD_ZEN_REG_OR":               0xBE,
    "AMD_ZEN_REG_SRC_CF_CANDIDATE": 0x47,

    # SpecOp opcode
    "AMD_ZEN_SPEC_NOP":             0xFF,

    "AMD_ZEN_TYPE5_READ":           0xDE,
}

# Generation specific structural types keep the original member names
# Do not add renamed aliases to AMD_Zen_Opcode
ZEN5_OPCODE_TAGS = ZEN_OPCODE_ENUM


def _build_zen5_tag_names() -> Dict[int, str]:
    # Reverse the opcode tag map for rendering; keep the first name seen so
    # duplicate values (e.g. 0x47 SRC / SRC_CF_CANDIDATE) resolve to the
    # canonical, non-candidate mnemonic.
    names: Dict[int, str] = {}
    for name, value in ZEN5_OPCODE_TAGS.items():
        names.setdefault(value, name)
    return names


_ZEN5_TAG_NAMES: Dict[int, str] = _build_zen5_tag_names()

# Keep a small built in CPUID table when the JSON file is unavailable
# This also covers users who copy only the Python files
# The fallback preserves the processor annotation from Zenella 1.2
_BUILTIN_CPUID_DESCRIPTIONS: Dict[str, List[str]] = {
    "00800F11": [
        "OctalCore AMD Ryzen 7 1800X, 3600 MHz (36 x 100) (Summit Ridge)",
    ],
    "00800F82": [
        "OctalCore AMD Ryzen 7 2700X, 4300 MHz (43 x 100) (Pinnacle Ridge, 12nm successor of Summit Ridge)",
    ],
    "00870F10": [
        "HexaCore AMD Ryzen 5 3600 (Matisse)",
    ],
    "00880F40": [
        "OctalCore AMD 4800S (Zen2)",
    ],
    "00B10F10": [
        "2x 192-Core AMD EPYC 9965 (Breithorn-D, Zen5c, Turin-D, SMT Off, top SKU, SP5 socket)",
    ],
    "00B40F40": [
        "OctalCore AMD Ryzen 7 9700X, 3200 MHz (32 x 100) (Granite Ridge, Zen5)",
    ],
}

_CPUID_DB: Optional[Dict[str, List[str]]] = None


def _qn(name: str) -> QualifiedName:
    return QualifiedName(name)


def _uint(width: int):
    """Construct an unsigned integer type across Binary Ninja API variants."""
    for args in ((width, False), (width, 0), (width,)):
        try:
            return Type.int(*args)
        except TypeError:
            continue
    raise RuntimeError(f"Cannot construct an unsigned {width}-byte integer type")


def u8():
    return _uint(1)


def u16():
    return _uint(2)


def u32():
    return _uint(4)


def u64():
    return _uint(8)


def _new_structure_builder():
    try:
        return StructureBuilder.create()
    except Exception:
        return StructureBuilder()


def _type_structure(builder):
    if hasattr(Type, "structure"):
        try:
            return Type.structure(builder)
        except Exception:
            pass
    if hasattr(Type, "structure_type"):
        return Type.structure_type(builder)
    raise RuntimeError("No Type.structure/Type.structure_type API is available")


def _named_type(bv, name: str):
    value = bv.get_type_by_name(name)
    if value is None:
        raise RuntimeError(f"Required Binary Ninja type {name!r} is missing")
    try:
        return Type.named_type_from_type(_qn(name), value)
    except Exception:
        return value


def _make_enum_type(values: Dict[str, int], width: int):
    try:
        builder = EnumerationBuilder.create()
    except Exception:
        try:
            builder = EnumerationBuilder()
        except Exception:
            return None
    try:
        builder.width = width
    except Exception:
        pass
    try:
        builder.signed = False
    except Exception:
        pass
    for name, value in values.items():
        try:
            builder.append(name, value)
        except Exception:
            return None
    for candidate in (
        lambda: Type.enumeration(builder),
        lambda: Type.enumeration_type(width, builder),
        lambda: Type.enumeration_type(builder, width),
        lambda: Type.enumeration_type(builder),
    ):
        try:
            return candidate()
        except Exception:
            continue
    return None


def _define_user_type_if_missing(bv, name: str, value) -> None:
    if bv.get_type_by_name(name) is None:
        bv.define_user_type(_qn(name), value)


def _append_cpuid_description(db: Dict[str, List[str]], key: str, description: str) -> None:
    normalized = str(key).strip().upper()
    value = str(description).strip()
    if not normalized or not value:
        return
    bucket = db.setdefault(normalized, [])
    if value not in bucket:
        bucket.append(value)


def _load_cpuid_db(force_reload: bool = False) -> Dict[str, List[str]]:
    """Load the bundled CPUID database, retaining a compiled-in fail-safe.

    Zenella 1.2 treated processor-description annotation as part of applying the
    layout.  The built-in entries ensure that behaviour does not disappear when
    the JSON file is omitted accidentally.  A bundled or user-replaced JSON file
    is then merged on top without discarding fallback entries.
    """
    global _CPUID_DB
    if _CPUID_DB is not None and not force_reload:
        return _CPUID_DB

    db: Dict[str, List[str]] = {
        key: list(values) for key, values in _BUILTIN_CPUID_DESCRIPTIONS.items()
    }
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cpuid_descriptions.json")
    loaded_descriptions = 0
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            for key, descriptions in data.items():
                if isinstance(descriptions, list):
                    for description in descriptions:
                        if description:
                            _append_cpuid_description(db, str(key), str(description))
                            loaded_descriptions += 1
                elif descriptions:
                    _append_cpuid_description(db, str(key), str(descriptions))
                    loaded_descriptions += 1
        elif isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                key = str(item.get("cpuid", "")).strip()
                description = str(item.get("description", "")).strip()
                if key and description:
                    _append_cpuid_description(db, key, description)
                    loaded_descriptions += 1
        else:
            raise ValueError("top-level value must be an object or an array")
        log_info(
            f"Zenella: loaded {loaded_descriptions} CPUID descriptions from {path} "
            f"({len(db)} CPUID keys including fail-safe entries)"
        )
    except FileNotFoundError:
        log_warn(
            "Zenella: cpuid_descriptions.json is missing; using the built-in "
            "AMD Zen fail-safe database"
        )
    except Exception as exc:
        log_warn(
            f"Zenella: failed to load CPUID descriptions from {path}: {exc}; "
            "using the built-in AMD Zen fail-safe database"
        )
    _CPUID_DB = db
    return db


def _expanded_cpuid_from_patch_signature(signature: int) -> int:
    """Convert AMD's compact patch signature to a conventional CPUID EAX key.

    ZenUtils uses the compact value directly to select the generation. The
    conversion is only for optional human-readable lookup in Zenella's CPUID DB.
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


def _cpuid_comment(signature: int, profile: Optional[ZenProfile] = None) -> str:
    """Return the Zenella 1.2-compatible processor revision annotation."""
    del profile  # Keep the argument for callers using the older function signature
    proc_rev = signature & 0xFFFF
    cpuid_value = _expanded_cpuid_from_patch_signature(proc_rev)
    db = _load_cpuid_db()

    descriptions: List[str] = []
    # Use the expanded CPUID key first
    # Accept the raw key as a fallback for custom local databases
    for key in (f"{cpuid_value:08X}", f"{signature & 0xFFFFFFFF:08X}"):
        for description in db.get(key, []):
            if description not in descriptions:
                descriptions.append(description)

    if descriptions:
        rendered = " | ".join(descriptions[:3])
        if len(descriptions) > 3:
            rendered += f" (+{len(descriptions) - 3} more)"
        return f"ProcRev 0x{proc_rev:04X} -> CPUID {cpuid_value:08X}: {rendered}"
    return (
        f"ProcRev 0x{proc_rev:04X} -> CPUID {cpuid_value:08X} "
        "(not in cpuid_descriptions.json)"
    )


def _ensure_types(
    bv,
    force_legacy_zen5: bool = False,
    force_zen12: bool = False,
) -> None:
    """Define common, Zen1/Zen2 and Zen5 structural types.

    'force_legacy_zen5' deliberately redefines the original Zenella 1.2
    'AMD_Zen_*'/'AMD_MC_*' type graph.  This repairs BNDBs that were
    opened with Zenella 2.0.0/2.0.1 and therefore retained an incorrect opcode
    enum even after the plug-in itself was replaced.

    'force_zen12' replaces the Zen1/Zen2 package and dependent aggregate
    types.  Zenella 2.0.0-2.0.3 represented the four serialized instruction
    words as one anonymous array.  Explicit 'uop0'...'uop3' fields make
    per-word annotations visible in Binary Ninja's Linear data view and also
    repair already-open BNDBs that retained the old aggregate.
    """
    # Loader ID enum
    if bv.get_type_by_name(T_LOADER_ENUM) is None:
        enum_type = _make_enum_type(LOADER_ID_ENUM, 2)
        if enum_type is not None:
            bv.define_user_type(_qn(T_LOADER_ENUM), enum_type)
        else:
            log_warn("Zenella: loader enum unsupported by this Binary Ninja build; using uint16")

    loader_type = _named_type(bv, T_LOADER_ENUM) if bv.get_type_by_name(T_LOADER_ENUM) else u16()

    # Keep the Zenella 1.2 processor signature type and field names
    # The pure Python parser exposes clearer property names
    # The Binary Ninja database ABI stays unchanged
    if bv.get_type_by_name(T_CPUID) is None:
        cpuid = _new_structure_builder()
        cpuid.packed = True
        cpuid.append(u32(), "proc_sig")
        bv.define_user_type(_qn(T_CPUID), _type_structure(cpuid))

    # Common 0x20 byte update header matching the Zenella 1.2 layout
    if bv.get_type_by_name(T_HEADER) is None:
        header = _new_structure_builder()
        header.packed = True
        header.append(u16(), "year")
        header.append(u8(), "day")
        header.append(u8(), "month")
        header.append(u32(), "update_revision")
        header.append(loader_type, "loader_id")
        header.append(u8(), "data_size")
        header.append(u8(), "init_flag")
        header.append(u32(), "data_checksum")
        header.append(u16(), "nb_ven")
        header.append(u16(), "nb_dev")
        header.append(u16(), "sb_ven")
        header.append(u16(), "sb_dev")
        header.append(_named_type(bv, T_CPUID), "proc_sig")
        header.append(u8(), "bios_revision")
        header.append(u8(), "flags")
        header.append(u8(), "reserved")
        header.append(u8(), "reserved2")
        bv.define_user_type(_qn(T_HEADER), _type_structure(header))

    # Keep the current Zenella interpretation of bytes 0x320 to 0x323
    if bv.get_type_by_name(T_OPTIONS) is None:
        options = _new_structure_builder()
        options.packed = True
        options.append(u8(), "autorun")
        options.append(u8(), "encrypted")
        options.append(u16(), "loaderid")
        bv.define_user_type(_qn(T_OPTIONS), _type_structure(options))

    # ZenUtils reads these four bytes as two option bytes
    # Zen1 and Zen2 use the remaining two bytes as generation specific unknown values
    if bv.get_type_by_name(T_ZEN12_OPTIONS) is None:
        options = _new_structure_builder()
        options.packed = True
        options.append(u8(), "autorun")
        options.append(u8(), "encrypted")
        options.append(u8(), "unknown1")
        options.append(u8(), "unknown2")
        bv.define_user_type(_qn(T_ZEN12_OPTIONS), _type_structure(options))

    # Keep each Zen1 and Zen2 match entry as a raw dword for older Binary Ninja APIs
    # Decoded bitfield values are added as comments
    if bv.get_type_by_name(T_ZEN12_MATCH) is None:
        match_entry = _new_structure_builder()
        match_entry.packed = True
        match_entry.append(u32(), "raw")
        bv.define_user_type(_qn(T_ZEN12_MATCH), _type_structure(match_entry))

    if force_zen12 or bv.get_type_by_name(T_ZEN12_PACKAGE) is None:
        package = _new_structure_builder()
        package.packed = True
        for index in range(ZEN12_INSTRUCTIONS_PER_PACKAGE):
            package.append(u64(), f"uop{index}")
        package.append(u32(), "sequence_word")
        bv.define_user_type(_qn(T_ZEN12_PACKAGE), _type_structure(package))

    if force_zen12 or bv.get_type_by_name(T_ZEN12_PAYLOAD) is None:
        payload = _new_structure_builder()
        payload.packed = True
        payload.append(Type.array(_named_type(bv, T_ZEN12_PACKAGE), ZEN12_PACKAGE_COUNT), "packages")
        bv.define_user_type(_qn(T_ZEN12_PAYLOAD), _type_structure(payload))

    if force_zen12 or bv.get_type_by_name(T_ZEN12_PATCH) is None:
        patch = _new_structure_builder()
        patch.packed = True
        patch.append(_named_type(bv, T_HEADER), "header")
        patch.append(Type.array(u8(), SIGNATURE_SIZE), "signature")
        patch.append(Type.array(u8(), MODULUS_SIZE), "modulus")
        patch.append(Type.array(u8(), CHECK_SIZE), "check")
        patch.append(_named_type(bv, T_ZEN12_OPTIONS), "options")
        patch.append(u32(), "revision_copy")
        patch.append(Type.array(_named_type(bv, T_ZEN12_MATCH), ZEN12_MATCH_ENTRY_COUNT), "match_entries")
        patch.append(_named_type(bv, T_ZEN12_PAYLOAD), "payload")
        bv.define_user_type(_qn(T_ZEN12_PATCH), _type_structure(patch))

    # Zen5 remains a structural tagging profile
    # Do not infer unsupported instruction semantics from the four byte records
    # Repair existing databases with the exact Zenella 1.2 enum
    # This also restores the legacy type graph
    if force_legacy_zen5 or bv.get_type_by_name("AMD_Zen5_OpcodeTag") is None:
        enum_type = _make_enum_type(ZEN_OPCODE_ENUM, 1)
        if enum_type is not None:
            bv.define_user_type(_qn("AMD_Zen5_OpcodeTag"), enum_type)

    if force_legacy_zen5 or bv.get_type_by_name(T_LEGACY_OPCODE) is None:
        enum_type = _make_enum_type(ZEN_OPCODE_ENUM, 1)
        if enum_type is not None:
            bv.define_user_type(_qn(T_LEGACY_OPCODE), enum_type)
        else:
            log_warn("Zenella: could not create AMD_Zen_Opcode; falling back to uint8")

    opcode_type = (
        _named_type(bv, "AMD_Zen5_OpcodeTag")
        if bv.get_type_by_name("AMD_Zen5_OpcodeTag")
        else u8()
    )
    legacy_opcode_type = (
        _named_type(bv, T_LEGACY_OPCODE)
        if bv.get_type_by_name(T_LEGACY_OPCODE)
        else opcode_type
    )

    if force_legacy_zen5 or bv.get_type_by_name(T_ZEN5_MATCH) is None:
        match = _new_structure_builder()
        match.packed = True
        match.append(Type.array(u32(), ZEN5_MATCH_SIZE // 4), "match_reg")
        bv.define_user_type(_qn(T_ZEN5_MATCH), _type_structure(match))

    if force_legacy_zen5 or bv.get_type_by_name(T_LEGACY_MATCH) is None:
        match = _new_structure_builder()
        match.packed = True
        match.append(Type.array(u32(), ZEN5_MATCH_SIZE // 4), "match_reg")
        bv.define_user_type(_qn(T_LEGACY_MATCH), _type_structure(match))

    if force_legacy_zen5 or bv.get_type_by_name(T_ZEN5_MASK) is None:
        mask = _new_structure_builder()
        mask.packed = True
        mask.append(Type.array(u32(), ZEN5_MASK_SIZE // 4), "mask_reg")
        bv.define_user_type(_qn(T_ZEN5_MASK), _type_structure(mask))

    if force_legacy_zen5 or bv.get_type_by_name(T_LEGACY_MASK) is None:
        mask = _new_structure_builder()
        mask.packed = True
        mask.append(Type.array(u32(), ZEN5_MASK_SIZE // 4), "mask_reg")
        bv.define_user_type(_qn(T_LEGACY_MASK), _type_structure(mask))

    if force_legacy_zen5 or bv.get_type_by_name(T_ZEN5_TAG) is None:
        tag = _new_structure_builder()
        tag.packed = True
        tag.append(opcode_type, "opcode_tag")
        tag.append(u8(), "b1")
        tag.append(u16(), "imm16_or_payload")
        bv.define_user_type(_qn(T_ZEN5_TAG), _type_structure(tag))

    if force_legacy_zen5 or bv.get_type_by_name(T_LEGACY_UOP) is None:
        tag = _new_structure_builder()
        tag.packed = True
        tag.append(legacy_opcode_type, "opcode")
        tag.append(u8(), "b1")
        tag.append(u16(), "imm16")
        bv.define_user_type(_qn(T_LEGACY_UOP), _type_structure(tag))

    if force_legacy_zen5 or bv.get_type_by_name(T_ZEN5_PAYLOAD) is None:
        payload = _new_structure_builder()
        payload.packed = True
        payload.append(Type.array(_named_type(bv, T_ZEN5_TAG), ZEN5_PAYLOAD_SIZE // 4), "records")
        bv.define_user_type(_qn(T_ZEN5_PAYLOAD), _type_structure(payload))

    if force_legacy_zen5 or bv.get_type_by_name(T_LEGACY_PAYLOAD) is None:
        payload = _new_structure_builder()
        payload.packed = True
        payload.append(Type.array(_named_type(bv, T_LEGACY_UOP), ZEN5_PAYLOAD_SIZE // 4), "uops")
        bv.define_user_type(_qn(T_LEGACY_PAYLOAD), _type_structure(payload))

    if force_legacy_zen5 or bv.get_type_by_name(T_ZEN5_PATCH) is None:
        patch = _new_structure_builder()
        patch.packed = True
        patch.append(_named_type(bv, T_HEADER), "header")
        patch.append(Type.array(u8(), SIGNATURE_SIZE), "signature")
        patch.append(Type.array(u8(), MODULUS_SIZE), "modulus")
        patch.append(Type.array(u8(), CHECK_SIZE), "check")
        patch.append(_named_type(bv, T_OPTIONS), "options")
        patch.append(u32(), "revision_copy")
        patch.append(_named_type(bv, T_ZEN5_MATCH), "match_regs")
        patch.append(_named_type(bv, T_ZEN5_MASK), "mask_regs")
        patch.append(_named_type(bv, T_ZEN5_PAYLOAD), "payload")
        bv.define_user_type(_qn(T_ZEN5_PATCH), _type_structure(patch))

    if force_legacy_zen5 or bv.get_type_by_name(T_LEGACY_PATCH) is None:
        patch = _new_structure_builder()
        patch.packed = True
        patch.append(_named_type(bv, T_HEADER), "header")
        patch.append(Type.array(u8(), SIGNATURE_SIZE), "signature")
        patch.append(Type.array(u8(), MODULUS_SIZE), "modulus")
        patch.append(Type.array(u8(), CHECK_SIZE), "check")
        patch.append(_named_type(bv, T_OPTIONS), "options")
        patch.append(u32(), "rev")
        patch.append(_named_type(bv, T_LEGACY_MATCH), "match_regs")
        patch.append(_named_type(bv, T_LEGACY_MASK), "mask_regs")
        patch.append(_named_type(bv, T_LEGACY_PAYLOAD), "microcode")
        bv.define_user_type(_qn(T_LEGACY_PATCH), _type_structure(patch))


def _safe_undefine_data_var(bv, address: int) -> None:
    try:
        bv.undefine_user_data_var(address)
    except Exception:
        pass


def _define_data_var(bv, address: int, value_type, name: str, comment: str) -> None:
    _safe_undefine_data_var(bv, address)
    bv.define_user_data_var(address, value_type)
    try:
        bv.define_user_symbol(Symbol(SymbolType.DataSymbol, address, name))
    except Exception:
        pass
    try:
        bv.set_comment_at(address, comment)
    except Exception:
        pass


def _add_symbol(
    bv,
    symbol_type,
    address: int,
    name: str,
    *,
    warn: bool = True,
) -> bool:
    try:
        bv.define_user_symbol(Symbol(symbol_type, address, name))
        return True
    except Exception as exc:
        if warn:
            log_warn(f"Zenella: could not define symbol {name!r}: {exc}")
        return False


def _get_comment_at_compat(bv, address: int) -> str:
    """Read an address comment without depending on one BN API generation."""

    try:
        value = bv.get_comment_at(address)
        return "" if value is None else str(value)
    except Exception:
        pass

    # Test doubles and some older integrations expose their comment map directly
    try:
        value = getattr(bv, "comments", {}).get(address, "")
        return "" if value is None else str(value)
    except Exception:
        return ""


def _append_comment_at(bv, address: int, text: str) -> None:
    """Append a unique line while preserving a pre-existing layout comment."""

    text = str(text).strip()
    if not text:
        return
    existing = _get_comment_at_compat(bv, address).rstrip()
    if text in existing.splitlines():
        return
    combined = f"{existing}\n{text}" if existing else text
    try:
        bv.set_comment_at(address, combined)
    except Exception:
        pass


def _update_analysis_compat(bv, *, wait: bool = False) -> None:
    """Request analysis and optionally wait for the small microcode corpus."""

    if wait:
        try:
            bv.update_analysis_and_wait()
            return
        except Exception:
            pass
    try:
        bv.update_analysis()
    except Exception:
        pass


def _available_bytes(bv, base: int, desired: int) -> int:
    try:
        return len(bv.read(base, desired))
    except Exception:
        return 0


def _apply_common_comments(bv, base: int, profile: Optional[ZenProfile]) -> None:
    try:
        raw = bv.read(base + 0x18, 4)
        if len(raw) == 4:
            signature = int.from_bytes(raw, "little")
            comment = _cpuid_comment(signature, profile)
            bv.set_comment_at(base + 0x18, comment)
            log_info(comment)
    except Exception as exc:
        log_warn(f"Zenella: processor-signature annotation failed: {exc}")


def _uop_annotation(decoded: DecodedUop, profile: ZenProfile, rom_address: int, index: int) -> str:
    rendered = decoded.text()
    classification = decoded.instruction_class
    details = (
        f"class={classification}, operation=0x{decoded.operation:02x}, "
        f"exec_unit={decoded.exec_unit}, raw=0x{decoded.word:016x}"
    )
    if decoded.unknown_reason:
        details += f", reason={decoded.unknown_reason}"
    return (
        f"{profile.name} package 0x{rom_address:04x}.uop{index}: "
        f"{rendered} [{details}]"
    )


def _sequence_annotation(
    decoded: DecodedSequenceWord,
    profile: ZenProfile,
    rom_address: int,
) -> str:
    return (
        f"{profile.name} package 0x{rom_address:04x}.seq: {decoded.text} "
        f"[raw=0x{decoded.word:08x}]"
    )


def _annotate_zen12_source_payload(
    bv,
    payload_base: int,
    profile: ZenProfile,
    payload: bytes,
) -> Tuple[int, int, int]:
    """Annotate every complete serialized package in the original data view.

    The supplied ZenUtils format stores exactly four 64-bit instruction words
    followed by one 32-bit sequence word in each 0x24-byte package.  Comments
    are attached to the individual field addresses so Linear view shows the
    decoded operation alongside the raw aggregate instead of only exposing a
    'uint64_t[4]' blob.
    """

    complete_packages = min(ZEN12_PACKAGE_COUNT, len(payload) // ZEN12_PACKAGE_SIZE)
    previous_word = 0
    decoded_uops = 0
    decoded_sequences = 0
    prefix = profile.name.lower()

    for slot in range(complete_packages):
        package_offset = slot * ZEN12_PACKAGE_SIZE
        package_address = payload_base + package_offset
        rom_address = slot_to_rom_address(slot)
        _append_comment_at(
            bv,
            package_address,
            f"{profile.name} serialized package slot {slot} / microcode address "
            f"0x{rom_address:04x}: four 64-bit uops + one 32-bit sequence word",
        )
        # Keep the established payload symbol at slot zero
        # Add package symbols for direct navigation through the raw update
        if slot:
            _add_symbol(
                bv,
                SymbolType.DataSymbol,
                package_address,
                f"{prefix}_patch_pkg_{rom_address:04x}",
                warn=False,
            )

        for index in range(ZEN12_INSTRUCTIONS_PER_PACKAGE):
            word_address = package_address + index * ZEN12_INSTRUCTION_SIZE
            start = package_offset + index * ZEN12_INSTRUCTION_SIZE
            word = int.from_bytes(payload[start:start + ZEN12_INSTRUCTION_SIZE], "little")
            decoded = decode_uop(word, previous_word)
            previous_word = word
            _append_comment_at(
                bv,
                word_address,
                _uop_annotation(decoded, profile, rom_address, index),
            )
            if index:
                _add_symbol(
                    bv,
                    SymbolType.DataSymbol,
                    word_address,
                    f"{prefix}_patch_{rom_address:04x}_uop{index}",
                    warn=False,
                )
            decoded_uops += 1

        sequence_address = package_address + (
            ZEN12_INSTRUCTIONS_PER_PACKAGE * ZEN12_INSTRUCTION_SIZE
        )
        sequence_start = package_offset + (
            ZEN12_INSTRUCTIONS_PER_PACKAGE * ZEN12_INSTRUCTION_SIZE
        )
        sequence_word = int.from_bytes(
            payload[sequence_start:sequence_start + 4], "little"
        )
        decoded_sequence = decode_sequence_word(sequence_word)
        _append_comment_at(
            bv,
            sequence_address,
            _sequence_annotation(decoded_sequence, profile, rom_address),
        )
        _add_symbol(
            bv,
            SymbolType.DataSymbol,
            sequence_address,
            f"{prefix}_patch_{rom_address:04x}_seq",
            warn=False,
        )
        decoded_sequences += 1

    return complete_packages, decoded_uops, decoded_sequences


def _apply_zen12_layout(bv, base: int, profile: ZenProfile) -> bool:
    """Apply a visible Zen1/Zen2 layout while preserving inline comments.

    As with the original Zenella Zen5 workflow, the complete aggregate remains
    defined in the type system but the header and every major region are
    exposed as separate data variables.  This is required for Binary Ninja's
    Linear view to render the processor-revision comment at 'base + 0x18'.
    """

    # Rebuild the Zen1 and Zen2 package types in older BNDB files
    # This adds explicit uop0 through uop3 fields and per word comments
    _ensure_types(bv, force_zen12=True)
    available = _available_bytes(bv, base, ZEN12_PATCH_SIZE)
    if available < HEADER_SIZE:
        log_error(f"Zenella: only 0x{available:x} bytes are available at 0x{base:x}")
        return False
    if available < ZEN12_PATCH_SIZE:
        log_warn(
            f"Zenella: partial {profile.name} patch: 0x{available:x}/0x{ZEN12_PATCH_SIZE:x} bytes"
        )

    patch_type = bv.get_type_by_name(T_ZEN12_PATCH)
    header_type = bv.get_type_by_name(T_HEADER)
    options_type = bv.get_type_by_name(T_ZEN12_OPTIONS)
    match_entry_type = bv.get_type_by_name(T_ZEN12_MATCH)
    payload_type = bv.get_type_by_name(T_ZEN12_PAYLOAD)
    package_type = bv.get_type_by_name(T_ZEN12_PACKAGE)
    if not all((patch_type, header_type, options_type, match_entry_type, payload_type, package_type)):
        log_error("Zenella: required Zen1/Zen2 types are missing after type creation")
        return False

    # Define the complete aggregate before replacing it with the header at the same address
    # This keeps nested comments visible in Linear view
    if available >= ZEN12_PATCH_SIZE:
        _define_data_var(
            bv,
            base,
            patch_type,
            f"amd_{profile.name.lower()}_patch",
            f"{profile.name} AMD microcode update (ZenUtils-compatible 0x{ZEN12_PATCH_SIZE:x} layout)",
        )
    _define_data_var(bv, base, header_type, "amd_mc_header", "AMD microcode patch header")
    _apply_common_comments(bv, base, profile)

    def define_fixed_region(offset: int, size: int, value_type, name: str, comment: str) -> None:
        remaining = max(0, available - offset)
        if remaining <= 0:
            return
        if remaining >= size:
            region_type = value_type
        else:
            region_type = Type.array(u8(), remaining)
            comment = f"{comment} (partial: 0x{remaining:x}/0x{size:x} bytes)"
        _define_data_var(bv, base + offset, region_type, name, comment)

    define_fixed_region(
        SIGNATURE_OFFSET,
        SIGNATURE_SIZE,
        Type.array(u8(), SIGNATURE_SIZE),
        "amd_mc_signature",
        "0x100-byte signature block",
    )
    define_fixed_region(
        MODULUS_OFFSET,
        MODULUS_SIZE,
        Type.array(u8(), MODULUS_SIZE),
        "amd_mc_modulus",
        "0x100-byte modulus block",
    )
    define_fixed_region(
        CHECK_OFFSET,
        CHECK_SIZE,
        Type.array(u8(), CHECK_SIZE),
        "amd_mc_check",
        "0x100-byte check block",
    )
    define_fixed_region(
        OPTIONS_OFFSET,
        OPTIONS_SIZE,
        options_type,
        "amd_mc_options",
        "Zen1/Zen2 autorun/encrypted/unknown option bytes",
    )
    define_fixed_region(
        REVISION_COPY_OFFSET,
        REVISION_COPY_SIZE,
        u32(),
        "amd_mc_revision_copy",
        "Revision copy from the extended header area",
    )
    define_fixed_region(
        ZEN12_MATCH_OFFSET,
        ZEN12_MATCH_SIZE,
        Type.array(_named_type(bv, T_ZEN12_MATCH), ZEN12_MATCH_ENTRY_COUNT),
        "amd_zen12_match_entries",
        "22 packed entries representing 44 logical match registers",
    )

    payload_available = max(0, min(available - ZEN12_PAYLOAD_OFFSET, ZEN12_PAYLOAD_SIZE))
    if payload_available:
        if payload_available == ZEN12_PAYLOAD_SIZE:
            visible_payload_type = payload_type
            payload_comment = (
                f"{profile.name} executable payload: 64 packages, four 64-bit uops and one "
                "32-bit sequence word per package"
            )
        else:
            complete_packages = payload_available // ZEN12_PACKAGE_SIZE
            if complete_packages and payload_available % ZEN12_PACKAGE_SIZE == 0:
                visible_payload_type = Type.array(
                    _named_type(bv, T_ZEN12_PACKAGE), complete_packages
                )
            else:
                visible_payload_type = Type.array(u8(), payload_available)
            payload_comment = (
                f"Partial {profile.name} executable payload: 0x{payload_available:x}/"
                f"0x{ZEN12_PAYLOAD_SIZE:x} bytes"
            )
        _define_data_var(
            bv,
            base + ZEN12_PAYLOAD_OFFSET,
            visible_payload_type,
            "amd_zen12_payload_raw",
            payload_comment,
        )
        try:
            payload_bytes = bv.read(base + ZEN12_PAYLOAD_OFFSET, payload_available)
            packages, uops, sequences = _annotate_zen12_source_payload(
                bv,
                base + ZEN12_PAYLOAD_OFFSET,
                profile,
                payload_bytes,
            )
            log_info(
                f"Zenella: annotated raw {profile.name} payload: "
                f"packages={packages}, uops={uops}, sequence_words={sequences}"
            )
        except Exception as exc:
            log_warn(f"Zenella: raw payload annotation failed: {exc}")

    if available >= ZEN12_MATCH_OFFSET + ZEN12_MATCH_SIZE:
        try:
            raw_match = bv.read(base + ZEN12_MATCH_OFFSET, ZEN12_MATCH_SIZE)
            for index, entry in enumerate(decode_match_entries(raw_match)):
                address = base + ZEN12_MATCH_OFFSET + index * 4
                bv.set_comment_at(
                    address,
                    f"match[{index}]: m1=0x{entry.m1:03x} u1={int(entry.u1)} "
                    f"m2=0x{entry.m2:03x} u2={int(entry.u2)} pad=0x{entry.padding:x}",
                )
        except Exception as exc:
            log_warn(f"Zenella: match-register annotation failed: {exc}")

    _update_analysis_compat(bv)
    log_info(
        f"Zenella: applied visible {profile.name} 0x{ZEN12_PATCH_SIZE:x} layout at 0x{base:x}"
    )
    return available >= ZEN12_PATCH_SIZE


def _apply_zen5_layout(bv, base: int) -> bool:
    """Apply the original Zenella 1.2 Zen5 layout without changing its ABI.

    The order is intentional.  Zenella 1.2 first made the aggregate type
    available, then exposed the header and every region as individual data
    variables.  Binary Ninja consequently renders the comment at 'base+0x18'
    inside 'AMD_MC_Header'.  Replacing this with only an outer aggregate was
    the regression that hid the CPUID text in 2.0.0/2.0.1.
    """
    _ensure_types(bv, force_legacy_zen5=True)

    available = _available_bytes(bv, base, ZEN5_PATCH_SIZE)
    if available < HEADER_SIZE:
        log_error(f"Zenella: only 0x{available:x} bytes are available at 0x{base:x}")
        return False
    if available < ZEN5_PATCH_SIZE:
        log_warn(
            f"Zenella: partial Zen5 patch: 0x{available:x}/0x{ZEN5_PATCH_SIZE:x} bytes; "
            "the visible region types will be truncated where necessary"
        )

    patch_type = bv.get_type_by_name(T_LEGACY_PATCH)
    header_type = bv.get_type_by_name(T_HEADER)
    options_type = bv.get_type_by_name(T_OPTIONS)
    match_type = bv.get_type_by_name(T_LEGACY_MATCH)
    mask_type = bv.get_type_by_name(T_LEGACY_MASK)
    payload_type = bv.get_type_by_name(T_LEGACY_PAYLOAD)
    uop_type = bv.get_type_by_name(T_LEGACY_UOP)

    if not all((patch_type, header_type, options_type, match_type, mask_type, payload_type, uop_type)):
        log_error("Zenella: legacy Zen5 type repair failed; required Zenella 1.2 types are missing")
        return False

    # Keep the complete patch type available before reproducing the original visible layout
    # The header replaces the aggregate data variable at the same address
    if available >= ZEN5_PATCH_SIZE:
        _define_data_var(
            bv,
            base,
            patch_type,
            "amd_mc_patch",
            "AMD microcode patch container (header/signature/modulus/check/options/rev/match/mask/microcode)",
        )

    _define_data_var(
        bv, base, header_type, "amd_mc_header", "AMD microcode patch header"
    )
    _apply_common_comments(bv, base, ZEN5)

    def define_fixed_region(offset: int, size: int, value_type, name: str, comment: str) -> None:
        remaining = max(0, available - offset)
        if remaining <= 0:
            return
        if remaining >= size:
            region_type = value_type
        else:
            region_type = Type.array(u8(), remaining)
            comment = f"{comment} (partial: 0x{remaining:x}/0x{size:x} bytes)"
        _define_data_var(bv, base + offset, region_type, name, comment)

    define_fixed_region(
        SIGNATURE_OFFSET, SIGNATURE_SIZE, Type.array(u8(), SIGNATURE_SIZE),
        "amd_mc_signature", "0x100-byte signature block",
    )
    define_fixed_region(
        MODULUS_OFFSET, MODULUS_SIZE, Type.array(u8(), MODULUS_SIZE),
        "amd_mc_modulus", "0x100-byte modulus block",
    )
    define_fixed_region(
        CHECK_OFFSET, CHECK_SIZE, Type.array(u8(), CHECK_SIZE),
        "amd_mc_check", "0x100-byte check block",
    )
    define_fixed_region(
        OPTIONS_OFFSET, OPTIONS_SIZE, options_type,
        "amd_mc_options", "autorun/encrypted/loaderid option bytes",
    )
    define_fixed_region(
        REVISION_COPY_OFFSET, REVISION_COPY_SIZE, u32(),
        "amd_mc_rev", "Revision copy from the extended header area",
    )
    define_fixed_region(
        ZEN5_MATCH_OFFSET, ZEN5_MATCH_SIZE, match_type,
        "amd_mc_match_regs", "Match register block",
    )
    define_fixed_region(
        ZEN5_MASK_OFFSET, ZEN5_MASK_SIZE, mask_type,
        "amd_mc_mask_regs", "Mask register block",
    )

    microcode_base = base + ZEN5_PAYLOAD_OFFSET
    microcode_available = max(0, min(available - ZEN5_PAYLOAD_OFFSET, ZEN5_PAYLOAD_SIZE))
    microcode_size = microcode_available - (microcode_available % 4)
    uop_count = microcode_size // 4
    if uop_count:
        if microcode_size == ZEN5_PAYLOAD_SIZE:
            visible_payload_type = payload_type
            payload_comment = "Decoded microcode uop region"
        else:
            # Use a named element array for partial updates
            # This keeps the AMD_Zen_Opcode enum visible
            try:
                visible_payload_type = Type.array(_named_type(bv, T_LEGACY_UOP), uop_count)
            except Exception:
                visible_payload_type = Type.array(uop_type, uop_count)
            payload_comment = "Decoded microcode uop region (auto-sized)"
        _define_data_var(
            bv, microcode_base, visible_payload_type,
            "amd_ucode_region", payload_comment,
        )

    try:
        bv.update_analysis()
    except Exception:
        pass

    log_info(
        f"Zenella: applied original Zenella 1.2 Zen5 layout at 0x{base:x} "
        f"(microcode_off=0x{ZEN5_PAYLOAD_OFFSET:x}, uops=0x{uop_count:x})"
    )
    return available >= ZEN5_PATCH_SIZE


#####################################################################################################
# Zen1 and Zen2 custom architecture and LLIL lifter
#####################################################################################################

SEGMENT_BASE_REGISTERS: Dict[int, str] = {
    code: f"seg_{SEGMENTS.get(code, str(code))}" for code in range(16)
}


def _build_registers() -> Dict[str, RegisterInfo]:
    result = {name: RegisterInfo(name, 8) for name in REGISTERS}
    result.update({name: RegisterInfo(name, 8) for name in SEGMENT_BASE_REGISTERS.values()})
    result["ucode_sp"] = RegisterInfo("ucode_sp", 8)
    result["ucode_ra"] = RegisterInfo("ucode_ra", 8)
    return result


UCODE_REGS = _build_registers()
UCODE_FLAGS = [
    "uc_zf", "uc_cf", "uc_sf", "uc_of",
    "native_zf", "native_cf", "native_sf", "native_of",
]
UCODE_FLAG_ROLES = {
    "uc_zf": FlagRole.ZeroFlagRole,
    "uc_cf": FlagRole.CarryFlagRole,
    "uc_sf": FlagRole.NegativeSignFlagRole,
    "uc_of": FlagRole.OverflowFlagRole,
    "native_zf": FlagRole.ZeroFlagRole,
    "native_cf": FlagRole.CarryFlagRole,
    "native_sf": FlagRole.NegativeSignFlagRole,
    "native_of": FlagRole.OverflowFlagRole,
}


@dataclass(frozen=True)
class _MappedPayload:
    architecture_name: str
    profile_name: str
    synthetic_base: int
    source_patch_base: int
    words: Dict[int, int]


_MAPPING_LOCK = threading.RLock()
_MAPPINGS: Dict[Tuple[str, int], _MappedPayload] = {}


def _register_word_cache(
    architecture_name: str,
    profile_name: str,
    synthetic_base: int,
    source_patch_base: int,
    payload: bytes,
) -> None:
    words: Dict[int, int] = {}
    for slot, uops, _sequence in iter_package_words(payload):
        package_address = synthetic_base + slot * ZEN12_PACKAGE_SIZE
        for index, word in enumerate(uops):
            words[package_address + index * ZEN12_INSTRUCTION_SIZE] = word
    with _MAPPING_LOCK:
        _MAPPINGS[(architecture_name, synthetic_base)] = _MappedPayload(
            architecture_name=architecture_name,
            profile_name=profile_name,
            synthetic_base=synthetic_base,
            source_patch_base=source_patch_base,
            words=words,
        )


def _mapping_for_address(architecture_name: str, address: int) -> Optional[_MappedPayload]:
    base = address & SYNTHETIC_REGION_MASK
    with _MAPPING_LOCK:
        return _MAPPINGS.get((architecture_name, base))


def _previous_uop_address(address: int) -> Optional[int]:
    base = address & SYNTHETIC_REGION_MASK
    relative = address - base
    if relative <= 0:
        return None
    package_relative = relative % ZEN12_PACKAGE_SIZE
    if package_relative == 0:
        return address - (ZEN12_INSTRUCTION_SIZE + 4)
    if package_relative in (8, 16, 24):
        return address - ZEN12_INSTRUCTION_SIZE
    return None


def _uop_location(address: int) -> Optional[Tuple[str, int]]:
    base = address & SYNTHETIC_REGION_MASK
    relative = address - base
    if not 0 <= relative < ZEN12_PAYLOAD_SIZE:
        return None
    within_package = relative % ZEN12_PACKAGE_SIZE
    if within_package in (0, 8, 16, 24):
        return "uop", ZEN12_INSTRUCTION_SIZE
    if within_package == 32:
        return "sequence", 4
    return None


def _mapped_target(address: int, rom_target: int) -> Optional[int]:
    payload_offset = rom_address_to_payload_offset(rom_target)
    if payload_offset is None:
        return None
    return (address & SYNTHETIC_REGION_MASK) + payload_offset


def _read_prev_word(architecture_name: str, address: int) -> int:
    previous = _previous_uop_address(address)
    if previous is None:
        return 0
    mapping = _mapping_for_address(architecture_name, address)
    if mapping is None:
        return 0
    return mapping.words.get(previous, 0)


def _token(token_type, text: str, value: Optional[int] = None) -> InstructionTextToken:
    if value is None:
        return InstructionTextToken(token_type, text)
    try:
        return InstructionTextToken(token_type, text, value)
    except TypeError:
        return InstructionTextToken(token_type, text)


def _instruction_token_type(name: str, *fallback_names: str):
    """Resolve a token kind across Binary Ninja API versions.

    Binary Ninja 5.3 does not expose 'DirectiveToken' even though newer API
    examples may do so.  Rendering must never abort architecture callbacks
    merely because a cosmetic token category is absent.
    """

    for candidate in (name, *fallback_names, "TextToken"):
        value = getattr(InstructionTextTokenType, candidate, None)
        if value is not None:
            return value
    raise RuntimeError("Binary Ninja exposes no usable instruction-text token type")


TOKEN_DIRECTIVE = _instruction_token_type("DirectiveToken", "InstructionToken")
TOKEN_COMMENT = _instruction_token_type("CommentToken", "TextToken")


def _comma(tokens: List[InstructionTextToken]) -> None:
    tokens.append(_token(InstructionTextTokenType.OperandSeparatorToken, ", "))


def _register_token(name: str) -> InstructionTextToken:
    return _token(InstructionTextTokenType.RegisterToken, name)


def _integer_token(value: int) -> InstructionTextToken:
    return _token(InstructionTextTokenType.IntegerToken, hex(value), value)


def _uop_tokens(decoded: DecodedUop, address: int) -> List[InstructionTextToken]:
    if not decoded.valid:
        tokens = [
            _token(TOKEN_DIRECTIVE, ".insn"),
            _token(InstructionTextTokenType.TextToken, " "),
            _integer_token(decoded.word),
        ]
        if decoded.unknown_reason:
            tokens.append(_token(TOKEN_COMMENT, f" ; {decoded.unknown_reason}"))
        return tokens

    tokens: List[InstructionTextToken] = [
        _token(InstructionTextTokenType.InstructionToken, decoded.display_mnemonic)
    ]
    if decoded.mnemonic == "nop":
        return tokens
    tokens.append(_token(InstructionTextTokenType.TextToken, " "))

    if decoded.instruction_class == "regop":
        tokens.append(_register_token(decoded.rd_name))
        _comma(tokens)
        if decoded.mnemonic != "mov":
            tokens.append(_register_token(decoded.rs_name))
            _comma(tokens)
        if decoded.imm_mode:
            tokens.append(_integer_token(decoded.imm16))
        else:
            tokens.append(_register_token(decoded.rt_name))
        if decoded.imm32_mode:
            _comma(tokens)
            tokens.append(_token(InstructionTextTokenType.TextToken, f"imm32:0x{decoded.immediate:x}"))
        return tokens

    if decoded.instruction_class == "ldop":
        tokens.append(_register_token(decoded.rd_name))
        _comma(tokens)
        tokens.extend(_memory_tokens(decoded))
        return tokens

    if decoded.instruction_class == "stop":
        tokens.extend(_memory_tokens(decoded))
        _comma(tokens)
        tokens.append(_register_token(decoded.rd_name))
        return tokens

    if decoded.instruction_class == "brop":
        target = decoded.target or 0
        mapped = _mapped_target(address, target)
        tokens.append(
            _token(
                InstructionTextTokenType.PossibleAddressToken,
                hex(target),
                mapped if mapped is not None else target,
            )
        )
        return tokens

    return tokens


def _memory_tokens(decoded: DecodedUop) -> List[InstructionTextToken]:
    tokens: List[InstructionTextToken] = [
        _token(InstructionTextTokenType.TextToken, f"{decoded.segment_name}:["),
        _register_token(decoded.rs_name),
    ]
    if decoded.rt != 0:
        tokens.append(_token(InstructionTextTokenType.TextToken, " + "))
        tokens.append(_register_token(decoded.rt_name))
    if decoded.offset != 0:
        tokens.append(_token(InstructionTextTokenType.TextToken, " + "))
        tokens.append(_integer_token(decoded.offset))
    tokens.append(_token(InstructionTextTokenType.TextToken, "]"))
    return tokens


def _sequence_tokens(decoded: DecodedSequenceWord, address: int) -> List[InstructionTextToken]:
    if decoded.action == "continue":
        return [_token(InstructionTextTokenType.InstructionToken, ".sw_continue")]
    if decoded.action == "complete":
        tokens = [_token(InstructionTextTokenType.InstructionToken, ".sw_complete")]
    elif decoded.action == "branch":
        target = decoded.target or 0
        mapped = _mapped_target(address, target)
        tokens = [
            _token(InstructionTextTokenType.InstructionToken, ".sw_branch"),
            _token(InstructionTextTokenType.TextToken, " "),
            _token(
                InstructionTextTokenType.PossibleAddressToken,
                hex(target),
                mapped if mapped is not None else target,
            ),
        ]
    else:
        tokens = [
            _token(TOKEN_DIRECTIVE, ".sw"),
            _token(InstructionTextTokenType.TextToken, " "),
            _integer_token(decoded.word),
        ]
    if decoded.immediate:
        tokens.append(_token(TOKEN_COMMENT, " ; immediately"))
    return tokens


class ZenUcodeArchitecture(Architecture):
    """Common Zen1/Zen2 microcode architecture.

    The executable payload is mapped at a 64 KiB-aligned synthetic address.
    That invariant lets the global architecture callback recover package and
    sequence-word boundaries without changing the architecture of the host
    firmware BinaryView.
    """

    name = "amd_zen_ucode_base"
    profile_name = "Zen"
    endianness = Endianness.LittleEndian
    address_size = 8
    default_int_size = 8
    instr_alignment = 1
    max_instr_length = 8
    opcode_display_length = 8
    regs = UCODE_REGS
    stack_pointer = "ucode_sp"
    link_reg = "ucode_ra"
    flags = UCODE_FLAGS
    flag_roles = UCODE_FLAG_ROLES

    def _decode(self, data: bytes, address: int):
        location = _uop_location(address)
        if location is None:
            return None
        kind, length = location
        if len(data) < length:
            return None
        if kind == "sequence":
            return kind, decode_sequence_word(int.from_bytes(data[:4], "little")), length
        previous = _read_prev_word(self.name, address)
        return kind, decode_uop(int.from_bytes(data[:8], "little"), previous), length

    def get_instruction_info(self, data: bytes, address: int):
        decoded_tuple = self._decode(data, address)
        if decoded_tuple is None:
            return None
        kind, decoded, length = decoded_tuple
        info = InstructionInfo()
        info.length = length

        if kind == "sequence":
            if decoded.action == "branch":
                target = _mapped_target(address, decoded.target or 0)
                if target is None:
                    info.add_branch(BranchType.UnresolvedBranch)
                else:
                    info.add_branch(BranchType.UnconditionalBranch, target)
            elif decoded.action == "complete":
                info.add_branch(BranchType.FunctionReturn)
            return info

        if decoded.instruction_class == "brop" and decoded.valid:
            target = _mapped_target(address, decoded.target or 0)
            if decoded.mnemonic == "jmp":
                if target is None:
                    info.add_branch(BranchType.UnresolvedBranch)
                else:
                    info.add_branch(BranchType.UnconditionalBranch, target)
            else:
                if target is None:
                    info.add_branch(BranchType.UnresolvedBranch)
                else:
                    info.add_branch(BranchType.TrueBranch, target)
                info.add_branch(BranchType.FalseBranch, address + length)
        return info

    def get_instruction_text(self, data: bytes, address: int):
        decoded_tuple = self._decode(data, address)
        if decoded_tuple is None:
            return None
        kind, decoded, length = decoded_tuple
        if kind == "sequence":
            return _sequence_tokens(decoded, address), length
        return _uop_tokens(decoded, address), length

    @staticmethod
    def _selected_flag_names(decoded: DecodedUop) -> Tuple[str, str, str, str]:
        prefix = "native" if decoded.native_flags else "uc"
        return f"{prefix}_zf", f"{prefix}_cf", f"{prefix}_sf", f"{prefix}_of"

    @staticmethod
    def _condition_expression(il, decoded: DecodedUop):
        zf_name, cf_name, sf_name, of_name = ZenUcodeArchitecture._selected_flag_names(decoded)
        zf = il.flag(zf_name)
        cf = il.flag(cf_name)
        sf = il.flag(sf_name)
        of = il.flag(of_name)
        sf_xor_of = il.xor_expr(0, sf, of)
        condition = decoded.condition
        if condition == 1:  # jmp
            return il.const(0, 1)
        if condition == 2:  # jb
            return cf
        if condition == 3:  # jnb
            return il.not_expr(0, cf)
        if condition == 4:  # jz / je
            return zf
        if condition == 5:  # jnz / jne
            return il.not_expr(0, zf)
        if condition == 6:  # jbe
            return il.or_expr(0, cf, zf)
        if condition == 7:  # ja
            return il.and_expr(0, il.not_expr(0, cf), il.not_expr(0, zf))
        if condition == 8:  # jl
            return sf_xor_of
        if condition == 9:  # jge
            return il.not_expr(0, sf_xor_of)
        if condition == 10:  # jle
            return il.or_expr(0, zf, sf_xor_of)
        if condition == 11:  # jg
            return il.and_expr(0, il.not_expr(0, zf), il.not_expr(0, sf_xor_of))
        if condition == 12:  # js
            return sf
        if condition == 13:  # jns
            return il.not_expr(0, sf)
        return il.undefined()

    def _emit_conditional_branch(
        self,
        il,
        condition,
        destination: Optional[int],
        fallthrough: int,
    ) -> None:
        true_label = il.get_label_for_address(self, destination) if destination is not None else None
        false_label = il.get_label_for_address(self, fallthrough)
        local_true = true_label is None
        local_false = false_label is None
        if true_label is None:
            true_label = LowLevelILLabel()
        if false_label is None:
            false_label = LowLevelILLabel()
        il.append(il.if_expr(condition, true_label, false_label))
        if local_true:
            il.mark_label(true_label)
            if destination is None:
                il.append(il.unimplemented())
                il.append(il.no_ret())
            else:
                il.append(il.jump(il.const_pointer(self.address_size, destination)))
        if local_false:
            il.mark_label(false_label)

    @staticmethod
    def _rhs(il, decoded: DecodedUop, size: int):
        if decoded.imm_mode:
            value = decoded.signed_immediate
            mask = (1 << (size * 8)) - 1
            return il.const(size, value & mask)
        return il.reg(size, decoded.rt_name)

    @staticmethod
    def _memory_address(il, decoded: DecodedUop):
        segment_register = SEGMENT_BASE_REGISTERS.get(decoded.segment or 0, "seg_0")
        address = il.add(8, il.reg(8, segment_register), il.reg(8, decoded.rs_name))
        if decoded.rt != 0:
            address = il.add(8, address, il.reg(8, decoded.rt_name))
        if decoded.scaled_offset:
            address = il.add(8, address, il.const(8, decoded.scaled_offset))
        return address

    @staticmethod
    def _set_documented_flags(
        il,
        decoded: DecodedUop,
        size: int,
        result,
        lhs=None,
        rhs=None,
        carry_in=None,
    ) -> None:
        zf_name, cf_name, _sf_name, _of_name = ZenUcodeArchitecture._selected_flag_names(decoded)
        if decoded.write_zf:
            il.append(il.set_flag(zf_name, il.compare_equal(size, result, il.const(size, 0))))
        if not decoded.write_cf:
            return

        cf_expr = None
        if decoded.mnemonic == "add" and lhs is not None:
            cf_expr = il.compare_unsigned_less_than(size, result, lhs)
        elif decoded.mnemonic == "adc" and lhs is not None and carry_in is not None:
            cf_expr = il.or_expr(
                0,
                il.compare_unsigned_less_than(size, result, lhs),
                il.and_expr(0, carry_in, il.compare_equal(size, result, lhs)),
            )
        elif decoded.mnemonic in ("sub", "sub2") and lhs is not None and rhs is not None:
            cf_expr = il.compare_unsigned_less_than(size, lhs, rhs)
        elif decoded.mnemonic == "sbb" and lhs is not None and rhs is not None and carry_in is not None:
            cf_expr = il.or_expr(
                0,
                il.compare_unsigned_less_than(size, lhs, rhs),
                il.and_expr(0, carry_in, il.compare_equal(size, lhs, rhs)),
            )
        elif decoded.mnemonic in ("and", "xor", "or"):
            # ZenUtils does not document the carry result for logical operations
            # Keep the conventional ALU value explicit in LLIL
            # This makes the assumption easy to find and revise
            cf_expr = il.const(0, 0)
        else:
            cf_expr = il.undefined()
        il.append(il.set_flag(cf_name, cf_expr))

    @staticmethod
    def _set_unknown_written_flags(il, decoded: DecodedUop) -> None:
        """Model documented flag writes even when the value is not known."""

        zf_name, cf_name, _sf_name, _of_name = ZenUcodeArchitecture._selected_flag_names(decoded)
        if decoded.write_zf:
            il.append(il.set_flag(zf_name, il.undefined()))
        if decoded.write_cf:
            il.append(il.set_flag(cf_name, il.undefined()))

    def _lift_unknown_regop(self, il, decoded: DecodedUop) -> None:
        """Preserve the destination clobber of an undecoded RegOp.

        ZenUtils can identify the RegOp class even when its operation byte has
        no mnemonic.  Emitting only LLIL_UNIMPL loses the known write to 'rd'
        and causes stale-value propagation in MLIL/HLIL.  An undefined result
        is conservative and retains that data-flow fact.
        """

        size = SIZE_CODE_TO_BYTES.get(decoded.size_code, 8)
        il.append(il.set_reg(size, decoded.rd_name, il.undefined()))
        self._set_unknown_written_flags(il, decoded)

    def _lift_movxy(self, il, decoded: DecodedUop, size: int, rhs) -> None:
        """Lift the ZenUtils MOVXY condition mux.

        The operation low nibble forms the same condition table as BrOp.  The
        endpoint encodings are named 'movxy_x' and 'movxy_y' by ZenUtils;
        therefore X is 'rs' and Y is 'rt'/the immediate, with a true
        condition selecting Y.  This produces useful, explicit HLIL while
        keeping the inference isolated in one helper for future revision.
        """

        x_value = il.reg(size, decoded.rs_name)
        y_value = rhs
        if decoded.mnemonic == "movxy_x":
            il.append(il.set_reg(size, decoded.rd_name, x_value))
            self._set_documented_flags(il, decoded, size, x_value)
            return
        if decoded.mnemonic == "movxy_y":
            il.append(il.set_reg(size, decoded.rd_name, y_value))
            self._set_documented_flags(il, decoded, size, y_value)
            return

        condition = self._condition_expression(il, decoded)
        choose_y = LowLevelILLabel()
        choose_x = LowLevelILLabel()
        done = LowLevelILLabel()
        il.append(il.if_expr(condition, choose_y, choose_x))

        il.mark_label(choose_y)
        il.append(il.set_reg(size, decoded.rd_name, y_value))
        self._set_documented_flags(il, decoded, size, y_value)
        il.append(il.goto(done))

        il.mark_label(choose_x)
        il.append(il.set_reg(size, decoded.rd_name, x_value))
        self._set_documented_flags(il, decoded, size, x_value)
        il.mark_label(done)

    def _lift_regop(self, il, decoded: DecodedUop) -> None:
        size = SIZE_CODE_TO_BYTES.get(decoded.size_code, 8)
        mnemonic = decoded.mnemonic
        if mnemonic == "nop":
            il.append(il.nop())
            return

        if mnemonic and mnemonic.startswith("movxy_"):
            self._lift_movxy(il, decoded, size, self._rhs(il, decoded, size))
            return

        rhs = self._rhs(il, decoded, size)
        if mnemonic == "mov":
            result = rhs
            il.append(il.set_reg(size, decoded.rd_name, result))
            self._set_documented_flags(il, decoded, size, result)
            return

        lhs = il.reg(size, decoded.rs_name)
        _zf_name, cf_name, _sf_name, _of_name = self._selected_flag_names(decoded)
        carry_in = il.flag(cf_name) if decoded.read_cf else il.const(0, 0)

        if mnemonic == "add":
            result = il.add(size, lhs, rhs)
        elif mnemonic == "adc":
            result = il.add_carry(size, lhs, rhs, carry_in)
        elif mnemonic in ("sub", "sub2"):
            result = il.sub(size, lhs, rhs)
        elif mnemonic == "sbb":
            result = il.sub_borrow(size, lhs, rhs, carry_in)
        elif mnemonic == "mul":
            result = il.mult(size, lhs, rhs)
        elif mnemonic == "and":
            result = il.and_expr(size, lhs, rhs)
        elif mnemonic == "xor":
            result = il.xor_expr(size, lhs, rhs)
        elif mnemonic == "or":
            result = il.or_expr(size, lhs, rhs)
        elif mnemonic == "shl":
            result = il.shift_left(size, lhs, rhs)
        elif mnemonic == "shr":
            result = il.logical_shift_right(size, lhs, rhs)
        elif mnemonic == "sar":
            result = il.arith_shift_right(size, lhs, rhs)
        elif mnemonic == "rol":
            result = il.rotate_left(size, lhs, rhs)
        elif mnemonic == "ror":
            result = il.rotate_right(size, lhs, rhs)
        elif mnemonic == "rcl":
            result = il.rotate_left_carry(size, lhs, rhs, carry_in)
        elif mnemonic == "rcr":
            result = il.rotate_right_carry(size, lhs, rhs, carry_in)
        elif mnemonic in ("scl", "scr"):
            # The destination write is known
            # ZenUtils does not define the exact carry and shift behavior for these operations
            self._lift_unknown_regop(il, decoded)
            return
        else:
            self._lift_unknown_regop(il, decoded)
            return

        il.append(il.set_reg(size, decoded.rd_name, result))
        self._set_documented_flags(il, decoded, size, result, lhs, rhs, carry_in)

    def _lift_uop(self, il, decoded: DecodedUop, address: int, length: int) -> None:
        if not decoded.valid:
            if decoded.instruction_class == "regop":
                self._lift_unknown_regop(il, decoded)
            else:
                il.append(il.unimplemented())
            return
        if decoded.instruction_class == "regop":
            self._lift_regop(il, decoded)
            return
        if decoded.instruction_class == "ldop":
            size = SIZE_CODE_TO_BYTES.get(decoded.size_code, 8)
            result = il.load(size, self._memory_address(il, decoded))
            il.append(il.set_reg(size, decoded.rd_name, result))
            self._set_documented_flags(il, decoded, size, result)
            return
        if decoded.instruction_class == "stop":
            size = SIZE_CODE_TO_BYTES.get(decoded.size_code, 8)
            il.append(
                il.store(
                    size,
                    self._memory_address(il, decoded),
                    il.reg(size, decoded.rd_name),
                )
            )
            return
        if decoded.instruction_class == "brop":
            target = _mapped_target(address, decoded.target or 0)
            if decoded.mnemonic == "jmp":
                if target is None:
                    il.append(il.unimplemented())
                    il.append(il.no_ret())
                else:
                    il.append(il.jump(il.const_pointer(self.address_size, target)))
                return
            condition = self._condition_expression(il, decoded)
            self._emit_conditional_branch(il, condition, target, address + length)
            return
        il.append(il.unimplemented())

    def _lift_sequence(self, il, decoded: DecodedSequenceWord, address: int) -> None:
        if decoded.action == "continue":
            il.append(il.nop())
            return
        if decoded.action == "complete":
            il.append(il.ret(il.reg(self.address_size, "ucode_ra")))
            return
        if decoded.action == "branch":
            target = _mapped_target(address, decoded.target or 0)
            if target is None:
                il.append(il.unimplemented())
                il.append(il.no_ret())
            else:
                il.append(il.jump(il.const_pointer(self.address_size, target)))
            return
        il.append(il.unimplemented())

    def get_instruction_low_level_il(self, data: bytes, address: int, il):
        decoded_tuple = self._decode(data, address)
        if decoded_tuple is None:
            return None
        kind, decoded, length = decoded_tuple
        try:
            il.set_current_address(address, self)
        except Exception:
            pass
        if kind == "sequence":
            self._lift_sequence(il, decoded, address)
        else:
            self._lift_uop(il, decoded, address, length)
        return length


class Zen1UcodeArchitecture(ZenUcodeArchitecture):
    name = "amd_zen1_ucode"
    profile_name = "Zen1"


class Zen2UcodeArchitecture(ZenUcodeArchitecture):
    name = "amd_zen2_ucode"
    profile_name = "Zen2"


# Register the architectures once when the plugin module is imported
for _architecture_class in (Zen1UcodeArchitecture, Zen2UcodeArchitecture):
    try:
        Architecture[_architecture_class.name]
    except Exception:
        _architecture_class.register()


#####################################################################################################
# Executable payload mapping and reports
#####################################################################################################


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _section_name(profile: ZenProfile, patch_base: int) -> str:
    return f".zenella_{profile.name.lower()}_ucode_{patch_base:x}"


def _find_free_synthetic_base(bv) -> int:
    highest = int(getattr(bv, "end", 0))
    try:
        for segment in bv.segments:
            highest = max(highest, int(segment.end))
    except Exception:
        pass
    candidate = _align_up(highest + SYNTHETIC_REGION_ALIGNMENT, SYNTHETIC_REGION_ALIGNMENT)
    while True:
        collision = False
        try:
            collision = bv.get_segment_at(candidate) is not None
        except Exception:
            pass
        if not collision:
            return candidate
        candidate += SYNTHETIC_REGION_ALIGNMENT


def _source_data_offset(bv, source_address: int) -> Optional[int]:
    try:
        value = bv.get_data_offset_for_address(source_address)
        if value is not None:
            return int(value)
    except Exception:
        pass
    # Raw BinaryViews map file offsets directly to addresses
    # Do not assume this from an image base of zero because parsed firmware views can also start there
    # Those views may still use a different backing file mapping
    try:
        if str(getattr(bv, "view_type", "")).lower() == "raw":
            return source_address
    except Exception:
        pass
    return None


def _analysis_root_slots(payload: bytes, every_slot: bool = False) -> Tuple[int, ...]:
    """Return package starts needed to cover the complete update payload.

    A single function at slot 0 is insufficient for real updates: a sequence
    word can branch into immutable microcode ROM, complete execution, or carry
    an unknown custom action, leaving later replacement packages unreachable
    from that one root.  'every_slot=False' is the optional compact mode: it
    starts a new function after each terminating/non-continuing package and at
    every in-patch branch target.  The normal 2.0.4 workflow passes
    'every_slot=True' so all 64 packages receive independent function heads.
    """

    if every_slot:
        return tuple(range(ZEN12_PACKAGE_COUNT))

    roots = {0}
    previous_word = 0
    for slot, words, sequence_word in iter_package_words(payload):
        for word in words:
            decoded = decode_uop(word, previous_word)
            previous_word = word
            if decoded.instruction_class == "brop" and decoded.target is not None:
                target_slot = rom_address_to_slot(decoded.target)
                if target_slot is not None:
                    roots.add(target_slot)

        sequence = decode_sequence_word(sequence_word)
        if sequence.target is not None:
            target_slot = rom_address_to_slot(sequence.target)
            if target_slot is not None:
                roots.add(target_slot)

        # Only .sw_continue has a guaranteed physical fallthrough
        # Start a new analysis chain after branches, completion and raw sequence words
        # This keeps every package reachable
        if sequence.action != "continue" and slot + 1 < ZEN12_PACKAGE_COUNT:
            roots.add(slot + 1)

    return tuple(sorted(roots))


def _create_user_function_compat(bv, address: int, platform) -> bool:
    """Create a mixed-architecture user function across BN Python variants.

    Never fall back to the BinaryView's host platform.  A raw update commonly
    opens as x86_64; creating an unqualified function there would silently
    defeat the Zen microcode lifter and produce host-ISA disassembly instead.
    Binary Ninja 5.3 accepts the named 'plat' argument, while older builds
    also accepted the platform positionally.
    """

    attempts = (
        lambda: bv.create_user_function(address, plat=platform),
        lambda: bv.create_user_function(address, platform),
    )
    last_error: Optional[Exception] = None
    for attempt in attempts:
        try:
            result = attempt()
            # Binary Ninja versions may return either a Function or None here
            # Both results mean the request reached the core
            # Treat both as success
            del result
            return True
        except TypeError as exc:
            last_error = exc
            continue
        except Exception as exc:
            last_error = exc
            break
    if last_error is not None:
        log_warn(f"Zenella: could not create microcode function at 0x{address:x}: {last_error}")
    return False


def _annotate_zen12_executable_payload(
    bv,
    synthetic_base: int,
    profile: ZenProfile,
    payload: bytes,
    function_slots: Sequence[int],
) -> Tuple[int, int, int]:
    """Label and comment all 320 records in the executable mirror."""

    function_slot_set = set(function_slots)
    previous_word = 0
    package_count = 0
    uop_count = 0
    sequence_count = 0
    prefix = profile.name.lower()

    for slot, words, sequence_word in iter_package_words(payload):
        package_address = synthetic_base + slot * ZEN12_PACKAGE_SIZE
        rom_address = slot_to_rom_address(slot)
        role = "package function" if slot in function_slot_set else "covered by compact root"
        _append_comment_at(
            bv,
            package_address,
            f"{profile.name} instruction package slot {slot} / microcode address "
            f"0x{rom_address:04x}; {role}",
        )

        for index, word in enumerate(words):
            word_address = package_address + index * ZEN12_INSTRUCTION_SIZE
            decoded = decode_uop(word, previous_word)
            previous_word = word
            _append_comment_at(
                bv,
                word_address,
                _uop_annotation(decoded, profile, rom_address, index),
            )
            if index:
                _add_symbol(
                    bv,
                    CODE_LABEL_SYMBOL,
                    word_address,
                    f"{prefix}_{rom_address:04x}_uop{index}",
                    warn=False,
                )
            uop_count += 1

        sequence_address = package_address + (
            ZEN12_INSTRUCTIONS_PER_PACKAGE * ZEN12_INSTRUCTION_SIZE
        )
        decoded_sequence = decode_sequence_word(sequence_word)
        _append_comment_at(
            bv,
            sequence_address,
            _sequence_annotation(decoded_sequence, profile, rom_address),
        )
        _add_symbol(
            bv,
            CODE_LABEL_SYMBOL,
            sequence_address,
            f"{prefix}_{rom_address:04x}_seq",
            warn=False,
        )
        sequence_count += 1
        package_count += 1

    return package_count, uop_count, sequence_count


def _map_executable_payload(
    bv,
    patch_base: int,
    profile: ZenProfile,
    analyze_all_slots: bool = True,
) -> Optional[int]:
    if profile not in (ZEN1, ZEN2):
        log_error("Zenella: executable lifting is currently defined only for Zen1 and Zen2")
        return None
    payload = bv.read(patch_base + ZEN12_PAYLOAD_OFFSET, ZEN12_PAYLOAD_SIZE)
    if len(payload) != ZEN12_PAYLOAD_SIZE:
        log_error(
            f"Zenella: need 0x{ZEN12_PAYLOAD_SIZE:x} payload bytes for LLIL; got 0x{len(payload):x}"
        )
        return None

    name = _section_name(profile, patch_base)
    section = None
    try:
        section = bv.get_section_by_name(name)
    except Exception:
        pass
    if section is not None:
        synthetic_base = int(section.start)
    else:
        synthetic_base = _find_free_synthetic_base(bv)
        data_offset = _source_data_offset(bv, patch_base + ZEN12_PAYLOAD_OFFSET)
        if data_offset is None:
            log_error(
                "Zenella: BinaryView cannot translate the payload address to a backing-file offset; "
                "open the raw patch or apply the command in the Raw view"
            )
            return None
        try:
            bv.add_user_segment(
                synthetic_base,
                ZEN12_PAYLOAD_SIZE,
                data_offset,
                ZEN12_PAYLOAD_SIZE,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable,
            )
            bv.add_user_section(
                name,
                synthetic_base,
                ZEN12_PAYLOAD_SIZE,
                SectionSemantics.ReadOnlyCodeSectionSemantics,
            )
        except Exception as exc:
            log_error(f"Zenella: could not map executable payload: {exc}")
            return None

    architecture = Architecture[
        Zen1UcodeArchitecture.name if profile == ZEN1 else Zen2UcodeArchitecture.name
    ]
    _register_word_cache(
        architecture.name,
        profile.name,
        synthetic_base,
        patch_base,
        payload,
    )

    function_slots = set(_analysis_root_slots(payload, every_slot=analyze_all_slots))

    for slot in range(ZEN12_PACKAGE_COUNT):
        package_address = synthetic_base + slot * ZEN12_PACKAGE_SIZE
        rom_address = slot_to_rom_address(slot)
        symbol_type = (
            SymbolType.FunctionSymbol if slot in function_slots else SymbolType.DataSymbol
        )
        _add_symbol(
            bv,
            symbol_type,
            package_address,
            (
                f"{profile.name.lower()}_ucode_pkg_{rom_address:04x}"
                if analyze_all_slots
                else f"{profile.name.lower()}_ucode_root_{rom_address:04x}"
                if slot in function_slots
                else f"{profile.name.lower()}_ucode_package_{rom_address:04x}"
            ),
        )

    packages, annotated_uops, annotated_sequences = _annotate_zen12_executable_payload(
        bv,
        synthetic_base,
        profile,
        payload,
        tuple(sorted(function_slots)),
    )

    created_roots = 0
    for slot in sorted(function_slots):
        address = synthetic_base + slot * ZEN12_PACKAGE_SIZE
        if _create_user_function_compat(bv, address, architecture.standalone_platform):
            created_roots += 1

    _append_comment_at(
        bv,
        patch_base + ZEN12_PAYLOAD_OFFSET,
        f"{profile.name} executable mirror: section {name} at 0x{synthetic_base:x}; "
        f"architecture {architecture.name}; {created_roots}/{len(function_slots)} package functions",
    )
    _append_comment_at(
        bv,
        synthetic_base,
        f"Mapped from update payload 0x{patch_base + ZEN12_PAYLOAD_OFFSET:x}; "
        f"hardware package addresses are 0x{ZEN12_ROM_START:04x}-"
        f"0x{ZEN12_ROM_START + ZEN12_PACKAGE_COUNT - 1:04x}",
    )

    # The payload has only 64 packages
    # Waiting here avoids a partial first view in Binary Ninja
    _update_analysis_compat(bv, wait=True)
    log_info(
        f"Zenella: mapped {profile.name} payload from 0x{patch_base + ZEN12_PAYLOAD_OFFSET:x} "
        f"to executable 0x{synthetic_base:x}; architecture={architecture.name}; "
        f"package_functions={created_roots}/{len(function_slots)}; "
        f"annotated_records={annotated_uops + annotated_sequences}/"
        f"{ZEN12_PACKAGE_COUNT * (ZEN12_INSTRUCTIONS_PER_PACKAGE + 1)}; "
        f"packages={packages}"
    )
    return synthetic_base


def _format_header_directives(blob: bytes) -> List[str]:
    header = parse_patch_header(blob)
    return [
        "; Header",
        f".date 0x{header.date:08x}",
        f".revision 0x{header.revision:08x}",
        f".format 0x{header.loader_id:04x}",
        f".patchlen 0x{header.patch_length:02x}",
        f".init 0x{header.init_flag:02x}",
        f".checksum 0x{header.checksum:08x}",
        f".nbvid 0x{header.northbridge_vendor:04x}",
        f".nbdid 0x{header.northbridge_device:04x}",
        f".sbvid 0x{header.southbridge_vendor:04x}",
        f".sbdid 0x{header.southbridge_device:04x}",
        f".cpuid 0x{header.processor_signature:08x}",
        f".biosrev 0x{header.bios_revision:02x}",
        f".flags 0x{header.flags:02x}",
    ]


def _zen12_report_text(blob: bytes, profile: ZenProfile) -> str:
    if len(blob) < ZEN12_PATCH_SIZE:
        raise ValueError(f"Need 0x{ZEN12_PATCH_SIZE:x} bytes; got 0x{len(blob):x}")
    lines = [f"; Zenella {PLUGIN_VERSION} / ZenUtils-compatible {profile.name} disassembly", ""]
    lines.extend(_format_header_directives(blob))
    lines.extend(["", "; Match Register"])
    match_data = blob[ZEN12_MATCH_OFFSET:ZEN12_MATCH_OFFSET + ZEN12_MATCH_SIZE]
    for index, entry in enumerate(decode_match_entries(match_data)):
        lines.append(f".match_reg {index * 2} 0x{entry.m1:08x} ; enabled={int(entry.u1)}")
        lines.append(f".match_reg {index * 2 + 1} 0x{entry.m2:08x} ; enabled={int(entry.u2)}")

    lines.extend(["", "; Instruction Packages"])
    payload = blob[ZEN12_PAYLOAD_OFFSET:ZEN12_PAYLOAD_OFFSET + ZEN12_PAYLOAD_SIZE]
    previous_word = 0
    for slot, words, sequence_word in iter_package_words(payload):
        rom_address = slot_to_rom_address(slot)
        all_words = " ".join(f"0x{word:016x}" for word in words)
        lines.append("")
        lines.append(
            f"; Slot {slot} @ 0x{rom_address:04x} ({all_words} 0x{sequence_word:08x})"
        )
        for word in words:
            decoded = decode_uop(word, previous_word)
            lines.append(decoded.text())
            previous_word = word
        lines.append(decode_sequence_word(sequence_word).text)
    return "\n".join(lines)


def _show_zen12_report(bv, base: int, profile: Optional[ZenProfile] = None) -> None:
    blob = bv.read(base, ZEN12_PATCH_SIZE)
    if len(blob) < HEADER_SIZE:
        log_error("Zenella: no complete AMD patch header at the selected address")
        return
    if profile is None:
        detection = detect_profile(blob)
        profile = detection.profile
        if profile not in (ZEN1, ZEN2):
            log_error(f"Zenella: report needs Zen1/Zen2; detection result: {detection.reason}")
            return
    try:
        text = _zen12_report_text(blob, profile)
        show_plain_text_report(f"Zenella {profile.name} disassembly @ 0x{base:x}", text)
    except Exception as exc:
        log_error(f"Zenella: disassembly report failed: {exc}")


def _zen5_report_text(blob: bytes) -> str:
    if len(blob) < ZEN5_PATCH_SIZE:
        raise ValueError(f"Need 0x{ZEN5_PATCH_SIZE:x} bytes; got 0x{len(blob):x}")
    lines = [
        f"; Zenella {PLUGIN_VERSION} / EXPERIMENTAL Zen5 structural-tag listing",
        "; This renders the AMD_Zen_Opcode structural tags only.",
        "; It is NOT a decoded Zen5 instruction stream: Zen5 ISA semantics are",
        "; undocumented, so operands beyond the raw imm16 tag payload are unknown.",
        "",
    ]
    lines.extend(_format_header_directives(blob))

    lines.extend(["", "; Match Registers"])
    for index in range(0, ZEN5_MATCH_SIZE, 4):
        word = int.from_bytes(blob[ZEN5_MATCH_OFFSET + index:ZEN5_MATCH_OFFSET + index + 4], "little")
        lines.append(f".match_reg {index // 4} 0x{word:08x}")

    lines.extend(["", "; Mask Registers"])
    for index in range(0, ZEN5_MASK_SIZE, 4):
        word = int.from_bytes(blob[ZEN5_MASK_OFFSET + index:ZEN5_MASK_OFFSET + index + 4], "little")
        lines.append(f".mask_reg {index // 4} 0x{word:08x}")

    lines.extend(["", "; Micro-op structural tags (offset: opcode b1 imm16lo imm16hi)"])
    payload = blob[ZEN5_PAYLOAD_OFFSET:ZEN5_PAYLOAD_OFFSET + ZEN5_PAYLOAD_SIZE]
    lines.extend(render_zen5_tag_lines(payload, _ZEN5_TAG_NAMES))
    return "\n".join(lines)


def _show_zen5_report(bv, base: int) -> None:
    blob = bv.read(base, ZEN5_PATCH_SIZE)
    if len(blob) < HEADER_SIZE:
        log_error("Zenella: no complete AMD patch header at the selected address")
        return
    detection = detect_profile(blob)
    if detection.profile is not None and detection.profile != ZEN5:
        log_warn(
            f"Zenella: address looks like {detection.profile.name}, not Zen5; "
            "rendering the Zen5 structural tags anyway (experimental)"
        )
    try:
        text = _zen5_report_text(blob)
        show_plain_text_report(f"Zenella Zen5 tag listing @ 0x{base:x}", text)
    except Exception as exc:
        log_error(f"Zenella: Zen5 tag listing failed: {exc}")


def _apply_profile(
    bv,
    base: int,
    profile: ZenProfile,
    map_hlil: bool = True,
    analyze_all_slots: bool = True,
) -> Optional[int]:
    if profile in (ZEN1, ZEN2):
        complete = _apply_zen12_layout(bv, base, profile)
        synthetic = None
        if complete and map_hlil:
            synthetic = _map_executable_payload(bv, base, profile, analyze_all_slots)
        return synthetic
    if profile == ZEN5:
        _apply_zen5_layout(bv, base)
        return None
    log_error(f"Zenella: unsupported profile {profile.name}")
    return None


def _auto_detect_and_apply(bv, base: int, analyze_all_slots: bool = True) -> None:
    blob = bv.read(base, ZEN5_PATCH_SIZE)
    detection = detect_profile(blob)
    if detection.profile is None:
        log_error(f"Zenella: architecture auto-detection failed: {detection.reason}")
        return
    log_info(
        f"Zenella: detected {detection.profile.name} ({detection.confidence} confidence): "
        f"{detection.reason}"
    )
    _apply_profile(
        bv,
        base,
        detection.profile,
        map_hlil=detection.profile in (ZEN1, ZEN2),
        analyze_all_slots=analyze_all_slots,
    )


#####################################################################################################
# Plugin command callbacks
#####################################################################################################


def cmd_define_types(bv):
    # Repair the legacy Zen5 ABI and the Zen1 and Zen2 package types
    # This covers BNDB files created before Zenella 2.0.4
    _ensure_types(bv, force_legacy_zen5=True, force_zen12=True)
    log_info(
        "Zenella: AMD Zen1/Zen2/Zen5 types are available; "
        "Zenella 1.2 Zen5 types and explicit Zen1/Zen2 uop fields restored"
    )


def cmd_legacy_define_types(bv):
    _ensure_types(bv, force_legacy_zen5=True)


def cmd_legacy_apply_at_zero(bv):
    _apply_zen5_layout(bv, 0)


def cmd_legacy_apply_at_cursor(bv, address):
    _apply_zen5_layout(bv, address)


def cmd_reload_cpuid_db(bv):
    del bv
    db = _load_cpuid_db(force_reload=True)
    log_info(f"Zenella: CPUID description database reloaded ({len(db)} keys)")


def cmd_auto_start(bv):
    _auto_detect_and_apply(bv, 0)


def cmd_auto_cursor(bv, address):
    _auto_detect_and_apply(bv, address)


def cmd_auto_all_slots_start(bv):
    _auto_detect_and_apply(bv, 0, analyze_all_slots=True)


def cmd_auto_all_slots_cursor(bv, address):
    _auto_detect_and_apply(bv, address, analyze_all_slots=True)


def cmd_auto_compact_start(bv):
    _auto_detect_and_apply(bv, 0, analyze_all_slots=False)


def cmd_auto_compact_cursor(bv, address):
    _auto_detect_and_apply(bv, address, analyze_all_slots=False)


def cmd_zen1_start(bv):
    _apply_profile(bv, 0, ZEN1)


def cmd_zen1_cursor(bv, address):
    _apply_profile(bv, address, ZEN1)


def cmd_zen2_start(bv):
    _apply_profile(bv, 0, ZEN2)


def cmd_zen2_cursor(bv, address):
    _apply_profile(bv, address, ZEN2)


def cmd_zen5_start(bv):
    _apply_profile(bv, 0, ZEN5, map_hlil=False)


def cmd_zen5_cursor(bv, address):
    _apply_profile(bv, address, ZEN5, map_hlil=False)


def cmd_report_start(bv):
    _show_zen12_report(bv, 0)


def cmd_report_cursor(bv, address):
    _show_zen12_report(bv, address)


def cmd_zen5_report_start(bv):
    _show_zen5_report(bv, 0)


def cmd_zen5_report_cursor(bv, address):
    _show_zen5_report(bv, address)


# Keep the original Zenella 1.2 commands unchanged
# They also repair stale type definitions from Zenella 2.0.0 and 2.0.1
PluginCommand.register(
    "AMD Microcode\\Define types (self-contained)",
    "Define AMD microcode structs (+ enums best-effort) in this database",
    cmd_legacy_define_types,
)
PluginCommand.register(
    "AMD Microcode\\Apply layout at file start (0x0)",
    "Define types (if needed) and apply AMD microcode layout at 0",
    cmd_legacy_apply_at_zero,
)
PluginCommand.register_for_address(
    "AMD Microcode\\Apply layout at cursor",
    "Define types (if needed) and apply AMD microcode layout at cursor address",
    cmd_legacy_apply_at_cursor,
)

PluginCommand.register(
    "AMD Microcode\\Define Zenella types (Zen1/Zen2/Zen5)",
    "Define AMD microcode structures for all supported Zenella profiles",
    cmd_define_types,
)
PluginCommand.register(
    "AMD Microcode\\Reload CPUID description database",
    "Reload bundled or locally replaced cpuid_descriptions.json without restarting Binary Ninja",
    cmd_reload_cpuid_db,
)
PluginCommand.register(
    "AMD Microcode\\Auto-detect and analyze at file start",
    "Detect Zen1, Zen2, or Zen5; annotate every record and create all 64 Zen1/Zen2 package functions",
    cmd_auto_start,
)
PluginCommand.register_for_address(
    "AMD Microcode\\Auto-detect and analyze at cursor",
    "Detect an embedded patch; annotate every record and create all 64 Zen1/Zen2 package functions",
    cmd_auto_cursor,
)
PluginCommand.register(
    "AMD Microcode\\Zen1\\Apply layout + LLIL/HLIL at file start",
    "Force the Zen1 0xc80 layout and map its 64 instruction packages as executable code",
    cmd_zen1_start,
)
PluginCommand.register_for_address(
    "AMD Microcode\\Zen1\\Apply layout + LLIL/HLIL at cursor",
    "Force the Zen1 layout for an embedded patch at the cursor",
    cmd_zen1_cursor,
)
PluginCommand.register(
    "AMD Microcode\\Zen2\\Apply layout + LLIL/HLIL at file start",
    "Force the Zen2 0xc80 layout and map its 64 instruction packages as executable code",
    cmd_zen2_start,
)
PluginCommand.register_for_address(
    "AMD Microcode\\Zen2\\Apply layout + LLIL/HLIL at cursor",
    "Force the Zen2 layout for an embedded patch at the cursor",
    cmd_zen2_cursor,
)
PluginCommand.register(
    "AMD Microcode\\Zen5\\Apply structural layout at file start",
    "Apply the Zen5 0x3820 structural/tag layout (no unsupported ISA semantics inferred)",
    cmd_zen5_start,
)
PluginCommand.register_for_address(
    "AMD Microcode\\Zen5\\Apply structural layout at cursor",
    "Apply the Zen5 structural/tag layout to an embedded patch",
    cmd_zen5_cursor,
)
PluginCommand.register(
    "AMD Microcode\\Zen5\\(Experimental) Disassemble tags to assembly at file start",
    "Render the Zen5 structural tags as an assembly-like listing (no ISA semantics inferred)",
    cmd_zen5_report_start,
)
PluginCommand.register_for_address(
    "AMD Microcode\\Zen5\\(Experimental) Disassemble tags to assembly at cursor",
    "Render an embedded Zen5 patch's structural tags as an assembly-like listing",
    cmd_zen5_report_cursor,
)
PluginCommand.register(
    "AMD Microcode\\Zen1-Zen2\\Show ZenUtils-style disassembly at file start",
    "Open a text report containing all 64 packages, four uops per package, and sequence words",
    cmd_report_start,
)
PluginCommand.register_for_address(
    "AMD Microcode\\Zen1-Zen2\\Show ZenUtils-style disassembly at cursor",
    "Open a ZenUtils-style report for an embedded Zen1/Zen2 patch",
    cmd_report_cursor,
)
PluginCommand.register(
    "AMD Microcode\\Zen1-Zen2\\Analyze all 64 package entries at file start (aggressive)",
    "Compatibility alias: exhaustive 64-package LLIL/HLIL analysis is now the default",
    cmd_auto_all_slots_start,
)
PluginCommand.register_for_address(
    "AMD Microcode\\Zen1-Zen2\\Analyze all 64 package entries at cursor (aggressive)",
    "Compatibility alias: create a function at every package entry in an embedded update",
    cmd_auto_all_slots_cursor,
)
PluginCommand.register(
    "AMD Microcode\\Zen1-Zen2\\Analyze compact control-flow roots at file start",
    "Create only the minimum disconnected control-flow roots instead of all 64 package functions",
    cmd_auto_compact_start,
)
PluginCommand.register_for_address(
    "AMD Microcode\\Zen1-Zen2\\Analyze compact control-flow roots at cursor",
    "Use compact root-only analysis for an embedded Zen1/Zen2 update",
    cmd_auto_compact_cursor,
)

log_info(
    f"Zenella {PLUGIN_VERSION}: loaded from {os.path.abspath(__file__)}; "
    "registered Zen1/Zen2 decoders, LLIL lifters, and Zen5 structural parser"
)
