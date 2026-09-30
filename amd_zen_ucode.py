#####################################################################################################
#####################################################################################################
#####################################################################################################
# Author: Kaya Ercihan
# Version: 2.2.0
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
import sys
import traceback
import threading
import re
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

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

# The DataRenderer showing opcode enum names and the original instruction fields lives
# in binaryninja.datarender (NOT the top-level package); DisassemblyTextLine is in
# binaryninja.function. Import both defensively so a headless/stub import still works.
try:
    from binaryninja.datarender import DataRenderer
except Exception:  # pragma: no cover - depends on Binary Ninja build
    DataRenderer = None
try:
    from binaryninja.function import DisassemblyTextLine
except Exception:  # pragma: no cover - depends on Binary Ninja build
    try:
        from binaryninja import DisassemblyTextLine
    except Exception:
        DisassemblyTextLine = None

if __package__:  # Never fall back to an unrelated installed copy on ImportError.
    from . import zenella_core as _core_module
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
        ZEN5_AUX_OFFSET,
        parse_zen5_patch,
        zen5_display_regions,
        zen5_tail_holds_registers,
        LoaderLayout,
        get_loader_layout,
        decode_zentool_sequence_word,
        zen5_sequence_statistics,
        ZEN5_PATCH_SIZE,
        ZEN5_OPQUAD_SIZE,
        ZEN5_UOPS_PER_QUAD,
        ZEN5_RECORD_SIZE,
        DecodedSequenceWord,
        ParsedZen5Patch,
        DecodedUop,
        ZenProfile,
        decode_match_entries,
        decode_sequence_word,
        decode_uop,
        decode_zen5_tag,
        detect_profile,
        iter_package_words,
        parse_patch_header,
        zen5_uop_field_text,
        zen5_uop_operand_text,
        zen5_is_ldstop,
        zen5_is_alignment_artifact,
        zen5_detect_body_sections,
        zen5_nop_alignment_hint,
        OPCLASS_NAMES,
        rom_address_to_payload_offset,
        rom_address_to_slot,
        slot_to_rom_address,
    )
else:  # Direct import for manual development use
    import zenella_core as _core_module
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
        ZEN5_AUX_OFFSET,
        parse_zen5_patch,
        zen5_display_regions,
        zen5_tail_holds_registers,
        LoaderLayout,
        get_loader_layout,
        decode_zentool_sequence_word,
        zen5_sequence_statistics,
        ZEN5_PATCH_SIZE,
        ZEN5_OPQUAD_SIZE,
        ZEN5_UOPS_PER_QUAD,
        ZEN5_RECORD_SIZE,
        DecodedSequenceWord,
        ParsedZen5Patch,
        DecodedUop,
        ZenProfile,
        decode_match_entries,
        decode_sequence_word,
        decode_uop,
        decode_zen5_tag,
        detect_profile,
        iter_package_words,
        parse_patch_header,
        zen5_uop_field_text,
        zen5_uop_operand_text,
        zen5_is_ldstop,
        zen5_is_alignment_artifact,
        zen5_detect_body_sections,
        zen5_nop_alignment_hint,
        OPCLASS_NAMES,
        rom_address_to_payload_offset,
        rom_address_to_slot,
        slot_to_rom_address,
    )


if __package__:
    from . import zenella_inspect as _inspect_module
else:
    import zenella_inspect as _inspect_module

PLUGIN_VERSION = "2.2.0"
# A balanced menu: auto-detect, one submenu per architecture (Zen1/Zen2 disassembly
# + lifting, Zen5 structural layout), plus the Zen1-Zen2 report. Remove old installed
# plugin copies so their separate menu registrations/renderers cannot compete.
MENU_ROOT = "AMD Microcode"
# Retained so existing scripts referencing the old two-command names keep working.
APPLY_START_COMMAND = MENU_ROOT + r"\Zen5\Apply structural layout at file start"
APPLY_CURSOR_COMMAND = MENU_ROOT + r"\Zen5\Apply structural layout at cursor"


def _check_module_versions() -> None:
    """Prevent a stale core from silently restoring an older layout on reapply."""
    root = os.path.dirname(os.path.realpath(__file__))
    for module, attr in ((_core_module, "CORE_VERSION"), (_inspect_module, "VERSION")):
        actual = getattr(module, attr, "missing")
        path = os.path.realpath(getattr(module, "__file__", ""))
        if actual != PLUGIN_VERSION or os.path.dirname(path) != root:
            raise RuntimeError(
                f"Zenella {PLUGIN_VERSION}: mixed or stale modules: {path} is {actual}. "
                f"Replace all three scripts in {root} and restart Binary Ninja; "
                "no layout has been applied.")



def _check_loaded_plugin_copies() -> None:
    """Reject competing in-process Zenella renderers before changing the BNDB.

    Detection is limited to imported modules, not a recursive disk scan. Module
    aliases for the same object are harmless. No code is unloaded or monkey-
    patched: native DataRenderer registrations can outlive Python references.
    """
    current = sys.modules.get(__name__)
    seen = {id(current)}
    conflicts = []
    for name, module in tuple(sys.modules.items()):
        if module is None or id(module) in seen:
            continue
        seen.add(id(module))
        namespace = getattr(module, "__dict__", {})
        filename = os.path.basename(str(namespace.get("__file__", "")))
        old_filename = re.fullmatch(r"(?:\d{4}-\d{2}-\d{2}_)?amd_zen_ucode\.py", filename)
        if (old_filename or (isinstance(namespace.get("ZEN_OPCODE_ENUM"), dict)
                and callable(namespace.get("_apply_zen5_layout")))):
            conflicts.append(
                f"{name}: version {namespace.get('PLUGIN_VERSION', 'unknown')} at "
                f"{namespace.get('__file__', '<unknown path>')}")
    if conflicts:
        raise RuntimeError(
            "Another Zenella plugin module is loaded; its commands or renderer "
            "can replace this build's output. Move the older plugin copy outside "
            "Binary Ninja's plugin directories and restart. Conflicting modules:\n"
            + "\n".join(conflicts))


def _show_apply_error(message: str) -> None:
    """Make a failed click visible instead of leaving only a Log entry."""
    try:
        from binaryninja.interaction import show_message_box
        show_message_box(f"Zenella {PLUGIN_VERSION}: layout NOT applied", message)
    except (ImportError, AttributeError):
        # Headless integrations still receive the full error via log_error.
        return
    except Exception as exc:
        log_warn(f"Zenella: could not display the error dialog: {exc}")


def _show_notice(title: str, message: str) -> None:
    """Make a non-fatal notice visible instead of leaving only a Log entry."""
    try:
        from binaryninja.interaction import show_message_box
        show_message_box(f"Zenella {PLUGIN_VERSION}: {title}", message)
    except (ImportError, AttributeError):
        # Headless integrations still receive the same text via log_warn.
        return
    except Exception as exc:
        log_warn(f"Zenella: could not display the notice dialog: {exc}")


_check_module_versions()
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
T_ZEN5_PRECODE = "AMD_Zen5_PreCodeMetadata"
T_ZEN5_TAG = "AMD_Zen5_MicroOpTag"
T_ZEN5_PAYLOAD = "AMD_Zen5_MicrocodeRegion"
T_ZEN5_PATCH = "AMD_Zen5_Patch"

# Both layouts use enum-backed 64-bit field structures and four-uop records.
# The empirical 0x420 and upstream 0x418 geometries are independently selectable.
T_ZEN5_MICROOP64 = "AMD_Zen5_MicroOp64"
T_ZEN5_OPQUAD = "AMD_Zen5_OpQuad"
T_ZEN5_OPQUAD_REGION = "AMD_Zen5_OpQuadRegion"
T_ZEN5_AUX = "AMD_Zen5_AuxiliaryRaw"
T_ZEN5_MATCHMASK = "AMD_Zen5_MatchMaskTable"
SYM_ZEN5_OPQUADS = "amd_ucode_opquads"
SYM_ZEN5_BODY = "amd_ucode_body"
SYM_ZEN5_PRECODE = "amd_mc_register_table"
SYM_ZEN5_METADATA = "amd_mc_prefix_metadata"
SYM_ZEN5_MATCHMASK = "amd_mc_match_mask_table"
SYM_ZEN5_AUX = "amd_mc_auxiliary_raw"

# Superseded type names; unrelated database types are never deleted globally.
OBSOLETE_ZEN5_TYPES = (
    "AMD_Zen5_OpClass",
    "AMD_Zen5_LdStOpcodeTag",
    "AMD_Zen5_UnknownPrefix",
)

# Keep the Zenella 1.2 type names for existing Binary Ninja databases
# Scripts, screenshots and research notes may still use these names
# New work uses the generation specific names above
T_LEGACY_OPCODE = "AMD_Zen_Opcode"
T_LEGACY_MATCH = "AMD_MC_MatchRegisterBlock"
T_LEGACY_MASK = "AMD_MC_MaskRegisterBlock"
T_LEGACY_UOP = "AMD_Zen_MicroOp"
T_LEGACY_PAYLOAD = "AMD_Zen_MicrocodeRegion"
T_LEGACY_PATCH = "AMD_MC_Patch"

# Register dimensions are provided by get_loader_layout(), never a global
# 10/12 partition. The optional researcher split is configured centrally in
# zenella_core.ZENELLA_REGISTER_SPLITS and must consume the complete table.

LOADER_ID_ENUM = {
    "AMD_MC_LOADER_8004": 0x8004,
    "AMD_MC_LOADER_8005": 0x8005,
    "AMD_MC_LOADER_8010": 0x8010,
    "AMD_MC_LOADER_8015": 0x8015,
    "AMD_MC_LOADER_8016": 0x8016,
}

# Keep the Zenella 1.2 enum ABI exactly as published
# Existing BNDBs, scripts, screenshots and research notes depend on these names and values
# The opcode tag is the original full-word bit slice 47..54
# It is not a complete Zen5 instruction decode
ZEN_OPCODE_ENUM = {
    # Opcodes whose meaning depends on the instruction class
    "AMD_ZEN_UOP_LD_ST_00":        0x00,
    # LdStOp resolves to a concrete LD/ST by the ldst bit (bit45). Synthetic values (>0xFF)
    # never collide with the 8-bit [47:55] opcode slice used by RegOps; the 16-bit-wide enum
    # holds them fine. A LdStOp is identified by class (bits 59..61), not by these values.
    "AMD_ZEN_LD":                  0x100,
    "AMD_ZEN_ST":                  0x101,
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

# Absolute little-endian bit positions; preserved from the supplied Zenella mapping.
ZEN5_UOP_FIELDS = (
    ("imm16", 0, 16), ("imm_flags", 16, 5), ("rt", 21, 5),
    ("rs", 26, 5), ("rd", 31, 5), ("flags", 36, 6),
    ("size", 42, 3), ("load", 45, 1), ("store", 46, 1),
    ("opcode", 47, 8), ("mid", 55, 4), ("exec_unit", 59, 3),
    ("hi", 62, 2),
)

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
    """Freeze the existing builder, preserving its width, packing and bitfields.

    Type.structure(builder) is NOT a builder finalizer in BN 6: its first
    argument is a member iterable and packed defaults to False. Reconstructing
    an already-built structure that way needlessly loses builder attributes.
    """
    freeze = getattr(builder, "immutable_copy", None)
    if callable(freeze):
        result = freeze()
    else:
        # Older APIs exposed a dedicated conversion, not the members factory.
        convert = getattr(Type, "structure_type", None)
        if not callable(convert):
            raise RuntimeError("Binary Ninja provides no supported structure-builder finalizer")
        result = convert(builder)
    if len(result) != builder.width:
        raise RuntimeError(f"Structure finalization changed width: {builder.width} -> {len(result)}")
    packed = getattr(result, "packed", None)
    if packed is not None and bool(packed) != bool(builder.packed):
        raise RuntimeError("Structure finalization did not preserve packed layout")
    return result


def _named_type(bv, name: str):
    value = bv.get_type_by_name(name)
    if value is None:
        raise RuntimeError(f"Required Binary Ninja type {name!r} is missing")
    # Registered references bind to the actual BNDB type ID, rather than a
    # detached snapshot retaining unknown1/unknown2 or the old register table.
    factory = getattr(Type, "named_type_from_registered_type", None)
    if callable(factory):
        return factory(bv, _qn(name))
    try:
        return Type.named_type_from_type(_qn(name), value)
    except Exception:
        return value


def _insert_bitfield(builder, member_type, name: str, bit_offset: int, bit_width: int) -> None:
    """Insert a packed bitfield member across Binary Ninja API variants.

    'bit_offset' is the absolute bit position within the containing word; it is
    split into a byte offset and an in-byte bit position for the Binary Ninja API.
    """
    byte_offset, bit_position = divmod(bit_offset, 8)
    attempts = (
        lambda: builder.insert(
            byte_offset, member_type, name, overwrite_existing=False,
            bit_position=bit_position, bit_width=bit_width,
        ),
        lambda: builder.add_member_at_offset(
            name, member_type, byte_offset, overwrite_existing=False,
            bit_position=bit_position, bit_width=bit_width,
        ),
    )
    last_error = None
    for attempt in attempts:
        try:
            attempt()
            return
        except Exception as exc:
            last_error = exc
    raise RuntimeError(f"Cannot insert bitfield {name!r}") from last_error


def _make_enum_type(values: Dict[str, int], width: int):
    """Create an unsigned enum with an exact byte width.

    Binary Ninja 5.x changed the positional Type.enumeration signature; keyword
    arguments and immutable_copy avoid accidentally creating a native-width or
    signed enum (which would render high opcode tags as negative numbers).
    """
    members = list(values.items())
    try:
        return Type.enumeration(arch=None, members=members, width=width, sign=False)
    except Exception:
        pass
    try:
        builder = EnumerationBuilder.create(width=width, sign=False)
    except Exception:
        try:
            builder = EnumerationBuilder.create()
            builder.width = width
            builder.signed = False
        except Exception:
            return None
    for name, value in members:
        try:
            builder.append(name, value)
        except Exception:
            return None
    try:
        return builder.immutable_copy()
    except Exception:
        pass
    for candidate in (
        lambda: Type.enumeration_type(None, builder, width, False),
        lambda: Type.enumeration_type(None, builder),
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
        return (f"ProcRev 0x{proc_rev:04X} -> CPUID {cpuid_value:08X}; "
                f"database example(s): {rendered}. "
                "CPUID alone does not identify SKU, socket count, core count, or SMT state.")
    return (
        f"ProcRev 0x{proc_rev:04X} -> CPUID {cpuid_value:08X} "
        "(not in cpuid_descriptions.json)"
    )


def _is_default_zen5_geometry(geometry: LoaderLayout) -> bool:
    """Canonical names describe one fixed geometry, so other loaders cannot resize it."""
    return (geometry.format_id, geometry.quad_offset, geometry.quad_count,
            geometry.patch_size, geometry.register_split) == (
                0x8015, 0x420, 256, 0x3820, (31, 31))


def _zen5_layout_type_names(geometry: LoaderLayout) -> Dict[str, str]:
    """Keep screenshot-era names for the default profile; scope alternative layouts."""
    if zen5_tail_holds_registers(geometry):
        # Experimental tail model: metadata before the op-quads; equal match/mask
        # register halves after them. Distinct _TAIL_ names so these never collide
        # with the before-code default's T_ZEN5_*/legacy type names.
        suffix = f"L{geometry.format_id:04X}_{geometry.quad_offset:04X}_{geometry.quad_count:03X}_TAIL"
        return {
            "prefix_metadata": f"AMD_Zen5_{suffix}_PreCodeMetadata",
            "opquads": f"AMD_Zen5_{suffix}_OpQuadRegion",
            "body": f"AMD_Zen5_{suffix}_MicrocodeRegion",
            "match_registers": f"AMD_Zen5_{suffix}_MatchRegisterBlock",
            "mask_registers": f"AMD_Zen5_{suffix}_MaskRegisterBlock",
            "patch": f"AMD_Zen5_{suffix}_Patch",
        }
    if _is_default_zen5_geometry(geometry):
        return {
            "register_table": T_ZEN5_PRECODE,  # not instantiated in the split view
            "match_registers": T_LEGACY_MATCH,
            "mask_registers": T_LEGACY_MASK,
            "opquads": T_ZEN5_OPQUAD_REGION,
            "body": T_ZEN5_PAYLOAD,
            "auxiliary_raw": T_ZEN5_AUX,
            "patch": T_ZEN5_PATCH,
        }
    suffix = f"L{geometry.format_id:04X}_{geometry.quad_offset:04X}_{geometry.quad_count:03X}"
    if geometry.register_split is not None:
        suffix += "_M%d_K%d" % geometry.register_split
    return {
        "register_table": f"AMD_MC_{suffix}_RegisterTable",
        "match_registers": f"AMD_MC_{suffix}_MatchRegisterBlock",
        "mask_registers": f"AMD_MC_{suffix}_MaskRegisterBlock",
        "opquads": f"AMD_Zen5_{suffix}_OpQuadRegion",
        "body": f"AMD_Zen5_{suffix}_MicrocodeRegion",
        "auxiliary_raw": f"AMD_Zen5_{suffix}_AuxiliaryData",
        "patch": f"AMD_Zen5_{suffix}_Patch",
    }


def _define_zen5_tail_register_types(bv, geometry: LoaderLayout, names: Dict[str, str]) -> None:
    """Corrected Zen5 model: metadata block -> op-quads -> match/mask table.

    On the real 0x8015/B110 samples the match/mask registers follow the op-quads
    (low-entropy 13-bit ROM addresses + masks + control words), and the 0x328
    pre-op-quad block is high-entropy metadata, not match registers.
    """
    prefix = _new_structure_builder()
    prefix.packed = True
    prefix.append(Type.array(u32(), geometry.register_dwords), "metadata_word")
    prefix_type = _type_structure(prefix)
    if len(prefix_type) != geometry.register_size:
        raise RuntimeError("Prefix metadata block width differs from the selected profile")
    bv.define_user_type(_qn(names["prefix_metadata"]), prefix_type)

    region = _new_structure_builder()
    region.packed = True
    region.append(Type.array(_named_type(bv, T_ZEN5_OPQUAD), geometry.quad_count), "opquads")
    region_type = _type_structure(region)
    bv.define_user_type(_qn(names["opquads"]), region_type)
    bv.define_user_type(_qn(names["body"]), region_type)  # body is op-quads only

    if geometry.auxiliary_size % 8:
        raise RuntimeError("post-code register area is not two equal DWORD halves")
    half_dwords = geometry.auxiliary_size // 8
    for key, field in (("match_registers", "match_reg"), ("mask_registers", "mask_reg")):
        block = _new_structure_builder()
        block.packed = True
        block.append(Type.array(u32(), half_dwords), field)
        block_type = _type_structure(block)
        if len(block_type) != half_dwords * 4:
            raise RuntimeError("Register block width differs from the selected profile")
        bv.define_user_type(_qn(names[key]), block_type)

    patch = _new_structure_builder()
    patch.packed = True
    patch.append(_named_type(bv, T_HEADER), "header")
    patch.append(Type.array(u8(), SIGNATURE_SIZE), "signature")
    patch.append(Type.array(u8(), MODULUS_SIZE), "modulus")
    patch.append(Type.array(u8(), CHECK_SIZE), "check")
    patch.append(_named_type(bv, T_OPTIONS), "options")
    patch.append(u32(), "rev")
    patch.append(_named_type(bv, names["prefix_metadata"]), "prefix_metadata")
    if patch.width != geometry.quad_offset:
        raise RuntimeError("Microcode body offset differs from the selected loader profile")
    patch.append(_named_type(bv, names["body"]), "body")
    patch.append(_named_type(bv, names["match_registers"]), "match_registers")
    patch.append(_named_type(bv, names["mask_registers"]), "mask_registers")
    patch_type = _type_structure(patch)
    if len(patch_type) != geometry.patch_size:
        raise RuntimeError("Patch aggregate must cover the loader-selected extent")
    bv.define_user_type(_qn(names["patch"]), patch_type)


def _define_zen5_geometry_types(bv, geometry: LoaderLayout, body_opquads_only: bool = False) -> None:
    """Two independent named blocks, not a replacement generic RegisterTable.

    body_opquads_only: the manual layout separates the trailing zero padding into
    its own region, so the body is the op-quads alone (no folded data_words) and the
    patch aggregate carries the padding as a distinct trailing member.
    """
    names = _zen5_layout_type_names(geometry)
    if zen5_tail_holds_registers(geometry):
        _define_zen5_tail_register_types(bv, geometry, names)
        return
    metadata_members = []
    if geometry.register_split is None:
        table = _new_structure_builder()
        table.packed = True
        table.append(Type.array(u32(), geometry.register_dwords), "register_word")
        bv.define_user_type(_qn(names["register_table"]), _type_structure(table))
        metadata_members.append((names["register_table"], "register_table"))
    else:
        for key, count, field, member in zip(
            ("match_registers", "mask_registers"), geometry.register_split,
            ("match_reg", "mask_reg"), ("match_regs", "mask_regs"),
        ):
            block = _new_structure_builder()
            block.packed = True
            block.append(Type.array(u32(), count), field)
            block_type = _type_structure(block)
            if len(block_type) != count * 4:
                raise RuntimeError("Register block width differs from the selected profile")
            bv.define_user_type(_qn(names[key]), block_type)
            metadata_members.append((names[key], member))
        if _is_default_zen5_geometry(geometry):
            bv.define_user_type(_qn(T_ZEN5_MATCH), bv.get_type_by_name(T_LEGACY_MATCH))
            bv.define_user_type(_qn(T_ZEN5_MASK), bv.get_type_by_name(T_LEGACY_MASK))
    if sum(len(bv.get_type_by_name(n)) for n, _ in metadata_members) != geometry.register_size:
        raise RuntimeError("Register blocks must end exactly at the selected body offset")

    # Keep the instruction-only type for scripts; the visible body also accounts
    # for stored data after the 256 quads. These words are NOT made-up opcodes.
    region = _new_structure_builder()
    region.packed = True
    region.append(Type.array(_named_type(bv, T_ZEN5_OPQUAD), geometry.quad_count), "opquads")
    bv.define_user_type(_qn(names["opquads"]), _type_structure(region))

    body = _new_structure_builder()
    body.packed = True
    body.append(Type.array(_named_type(bv, T_ZEN5_OPQUAD), geometry.quad_count), "opquads")
    if geometry.auxiliary_size and not body_opquads_only:
        if geometry.auxiliary_size % 4:
            raise RuntimeError("Selected body-data extent is not a whole number of DWORDs")
        body.append(Type.array(u32(), geometry.auxiliary_size // 4), "data_words")
    body_type = _type_structure(body)
    expected_body_len = (geometry.quad_count * ZEN5_OPQUAD_SIZE if body_opquads_only
                         else geometry.patch_size - geometry.quad_offset)
    if len(body_type) != expected_body_len:
        raise RuntimeError("Body type must cover all bytes after the register blocks")
    bv.define_user_type(_qn(names["body"]), body_type)
    if _is_default_zen5_geometry(geometry):
        bv.define_user_type(_qn(T_LEGACY_PAYLOAD), body_type)

    patch = _new_structure_builder()
    patch.packed = True
    patch.append(_named_type(bv, T_HEADER), "header")
    patch.append(Type.array(u8(), SIGNATURE_SIZE), "signature")
    patch.append(Type.array(u8(), MODULUS_SIZE), "modulus")
    patch.append(Type.array(u8(), CHECK_SIZE), "check")
    patch.append(_named_type(bv, T_OPTIONS), "options")
    patch.append(u32(), "rev")
    for name, member in metadata_members:
        patch.append(_named_type(bv, name), member)
    # Independent size check prevents a guessed register count shifting code.
    if patch.width != geometry.quad_offset:
        raise RuntimeError("Microcode body offset differs from the selected loader profile")
    patch.append(_named_type(bv, names["body"]), "body")
    if body_opquads_only:
        trailing = geometry.patch_size - geometry.code_end
        if trailing > 0:
            patch.append(Type.array(u8(), trailing), "zero_padding")
    patch_type = _type_structure(patch)
    if len(patch_type) != geometry.patch_size:
        raise RuntimeError("Patch aggregate must cover the loader-selected extent")
    bv.define_user_type(_qn(names["patch"]), patch_type)
    if _is_default_zen5_geometry(geometry):
        bv.define_user_type(_qn(T_LEGACY_PATCH), patch_type)


def _ensure_types(
    bv,
    force_legacy_zen5: bool = False,
    force_zen12: bool = False,
    zen5_layout: str = "loader",
    zen5_geometry: Optional[LoaderLayout] = None,
    zen5_body_opquads_only: bool = False,
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
    if force_legacy_zen5 or bv.get_type_by_name(T_LOADER_ENUM) is None:
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
    if force_legacy_zen5 or bv.get_type_by_name(T_HEADER) is None:
        header = _new_structure_builder()
        header.packed = True
        header.append(u16(), "year")
        header.append(u8(), "day")
        header.append(u8(), "month")
        header.append(u32(), "update_revision")
        header.append(loader_type, "loader_id")
        header.append(u16(), "size_of_patch")
        header.append(u32(), "minimum_patch_level")
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

    # Restore the screenshot-era API: autorun, encrypted, uint16_t loaderid.
    # The research profile selects its geometry using this LE16 at +0x322.
    # Native zentool still calls the bytes unknown1/unknown2 and uses +0x08;
    # the parser retains that distinction in explicit reference mode.
    if force_legacy_zen5 or bv.get_type_by_name(T_OPTIONS) is None:
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

    # Restore the complete user enum, including aliases and custom mappings.
    # It is a labeling table; it is not restricted by old-zentool operation classes.
    for enum_name in (T_LEGACY_OPCODE, "AMD_Zen5_OpcodeTag"):
        if force_legacy_zen5 or bv.get_type_by_name(enum_name) is None:
            enum_type = _make_enum_type(ZEN_OPCODE_ENUM, 2)
            if enum_type is not None:
                bv.define_user_type(_qn(enum_name), enum_type)

    opcode_type = (_named_type(bv, T_LEGACY_OPCODE)
                   if bv.get_type_by_name(T_LEGACY_OPCODE) is not None else u16())
    def _build_zen5_uop():
        uop = _new_structure_builder()
        uop.packed = True
        # A backing type must hold bit_position + bit_width. For example rd
        # begins at byte 3, bit 7 and needs uint16_t, not a one-byte container.
        for field, bit_offset, bit_width in ZEN5_UOP_FIELDS:
            member_type = opcode_type if field == "opcode" else (
                u16() if bit_offset % 8 + bit_width > 8 else u8())
            _insert_bitfield(uop, member_type, field, bit_offset, bit_width)
        uop.width = ZEN5_RECORD_SIZE
        result = _type_structure(uop)
        if len(result) != ZEN5_RECORD_SIZE:
            raise RuntimeError("Zen5 micro-op type must occupy exactly eight bytes")
        _verify_opcode_types(bv, result)
        return result

    for name in (T_ZEN5_MICROOP64, T_ZEN5_TAG, T_LEGACY_UOP):
        if force_legacy_zen5 or bv.get_type_by_name(name) is None:
            bv.define_user_type(_qn(name), _build_zen5_uop())

    if force_legacy_zen5 or bv.get_type_by_name(T_ZEN5_OPQUAD) is None:
        quad = _new_structure_builder()
        quad.packed = True
        for index in range(ZEN5_UOPS_PER_QUAD):
            quad.append(_named_type(bv, T_ZEN5_MICROOP64), f"uop{index}")
        quad.append(u32(), "sequence_word")
        quad_type = _type_structure(quad)
        if len(quad_type) != ZEN5_OPQUAD_SIZE:
            raise RuntimeError("Zen5 op-quad type must occupy exactly 36 bytes")
        bv.define_user_type(_qn(T_ZEN5_OPQUAD), quad_type)

    # Always keep canonical names fixed at the 8015 / 0x420 / 256-quad view (the
    # legacy, screenshot-era profile). This must be that layout so the legacy type
    # names (AMD_MC_MatchRegisterBlock, ...) matched by _is_default_zen5_geometry
    # are defined; "loader" now applies the confirmed 0x8015 match[31]/mask[31]
    # geometry whose op-quad count follows the zero padding, so request the
    # canonical profile explicitly. Other geometries get scoped names.
    canonical = get_loader_layout(0x8015, "sample-420")
    _define_zen5_geometry_types(bv, canonical)
    geometry = zen5_geometry or get_loader_layout(0x8015, zen5_layout)
    # Always define the actual geometry's types unless it is exactly the canonical
    # default; the tail model shares the default tuple but needs its own _TAIL_ types.
    if not _is_default_zen5_geometry(geometry) or zen5_tail_holds_registers(geometry):
        _define_zen5_geometry_types(bv, geometry, body_opquads_only=zen5_body_opquads_only)


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


# Recognize only Zenella's artifacts. A renamed/symbol-less data variable must
# also be migrated: looking only for symbols missed those objects in older BNDBs.
_ZEN5_OWNED_SYMBOLS = {
    "amd_mc_header", "amd_mc_signature", "amd_mc_modulus", "amd_mc_check",
    "amd_mc_options", "amd_mc_rev", "amd_mc_revision_copy", "amd_mc_register_table",
    "amd_mc_match_regs", "amd_mc_mask_regs", "amd_mc_match_words", "amd_mc_match_tail",
    "amd_mc_unknown_prefix", "amd_mc_precode_metadata", "amd_mc_payload_raw",
    "amd_ucode_region", "amd_ucode_opquads", "amd_mc_auxiliary_raw",
    "amd_mc_patch", "amd_zen5_patch", "amd_ucode_body",
    "amd_mc_nop_section", "amd_mc_nop_sparse_opquads", "amd_mc_finalization_section",
    "amd_mc_body_data_words",
}


def _registered_type_name(value_type) -> str:
    # Type.registered_name is a NamedTypeReferenceType, NOT a string; use
    # its .name. Type.name raises NotImplementedError for unnamed integers.
    for attr in ("registered_name", "registered_type_name", "name"):
        try:
            name = getattr(value_type, attr, None)
            if name is not None:
                if isinstance(name, (str, QualifiedName)):
                    return str(name)
                return str(getattr(name, "name", name))
        except (AttributeError, NotImplementedError):
            continue
    return ""


def _zen5_owned_region_type(value_type) -> bool:
    name = _registered_type_name(value_type)
    return (name in {T_HEADER, T_OPTIONS, T_LEGACY_MATCH, T_LEGACY_MASK,
                     T_ZEN5_MATCH, T_ZEN5_MASK, T_ZEN5_PATCH, T_LEGACY_PATCH,
                     T_ZEN5_PRECODE, T_ZEN5_OPQUAD_REGION, T_ZEN5_PAYLOAD,
                     T_ZEN5_MATCHMASK, T_LEGACY_PAYLOAD, T_ZEN5_AUX, T_ZEN5_OPQUAD,
                     T_ZEN5_MICROOP64, T_ZEN5_TAG, T_LEGACY_UOP, "AMD_Zen5_MatchTail",
                     "AMD_Zen5_UnknownPrefix"}
            or (name.startswith(("AMD_MC_L", "AMD_Zen5_L")) and name.endswith(
                ("RegisterTable", "MatchRegisterBlock", "MaskRegisterBlock",
                 "OpQuadRegion", "MicrocodeRegion", "AuxiliaryData", "MatchMaskTable",
                 "PreCodeMetadata", "Patch"))))


def _symbols_at(bv, address: int):
    # Current and legacy APIs both expose get_symbols(start, length).
    try:
        return list(bv.get_symbols(address, 1))
    except (AttributeError, TypeError):
        symbol = bv.get_symbol_at(address)
        return [symbol] if symbol is not None else []


def _data_var_type_at(bv, address: int):
    item = bv.get_data_var_at(address)
    return None if item is None else item.type



def _remove_owned_data_var(bv, address: int) -> None:
    """Remove both analysis layers at a previously identified Zenella address.

    undefine_user_data_var alone can expose an older AUTO data variable underneath.
    Only the cleanup routine calls this, after proving ownership by type, symbol,
    or a generated-region comment. Never erase arbitrary neighboring annotations.
    """
    bv.undefine_user_data_var(address)
    remaining = bv.get_data_var_at(address)
    if remaining is not None:
        if not bool(getattr(remaining, "auto_discovered", False)):
            raise RuntimeError(f"Could not remove stale user variable at 0x{address:x}")
        remove_auto = getattr(bv, "undefine_data_var", None)
        if not callable(remove_auto):
            raise RuntimeError(f"Cannot remove stale auto variable at 0x{address:x} on this API")
        remove_auto(address, blacklist=True)
        if bv.get_data_var_at(address) is not None:
            raise RuntimeError(f"Stale variable at 0x{address:x} survived cleanup")


def _remove_owned_symbol(bv, symbol) -> None:
    """Use the matching API for user versus auto-discovered symbols."""
    if bool(getattr(symbol, "auto", False)):
        remove = getattr(bv, "undefine_auto_symbol", None)
        if not callable(remove):
            raise RuntimeError(f"Cannot remove auto symbol {symbol.name} on this API")
        remove(symbol)
    else:
        bv.undefine_user_symbol(symbol)


def _cleanup_stale_zen5_layout(bv, base: int, size: int = ZEN5_PATCH_SIZE) -> None:
    """Remove old owned variables even when their symbols have been renamed.

    Scope is this patch only. Unrelated types/symbols/comments are retained;
    changes are made inside the apply command's undoable transaction.
    """
    addresses = {base, base + OPTIONS_OFFSET, base + REVISION_COPY_OFFSET}
    addresses.update(base + off for off in range(0x328, min(size, 0x424), 4))
    addresses.update((base + SIGNATURE_OFFSET, base + MODULUS_OFFSET,
                      base + CHECK_OFFSET, base + ZEN5_AUX_OFFSET))
    addresses.update(int(a) for a in bv.data_vars if base <= int(a) < base + size)
    for address in sorted(addresses):
        if not base <= address < base + size:
            continue
        symbols = _symbols_at(bv, address)
        ours = [sym for sym in symbols if sym.name in _ZEN5_OWNED_SYMBOLS]
        value_type = _data_var_type_at(bv, address)
        comment = _get_comment_at_compat(bv, address)
        generated_region = (address < base + 0x424 or address == base + ZEN5_AUX_OFFSET) and (
            comment.startswith("Zenella.layout:") or "layout=" in comment and "confidence=" in comment)
        if value_type is not None and (ours or _zen5_owned_region_type(value_type) or generated_region):
            _remove_owned_data_var(bv, address)
        for symbol in ours:
            _remove_owned_symbol(bv, symbol)
    # Generated comments are replaced, not accumulated. Researcher notes stay.
    comment_offsets = set(range(0x320, size, 4))
    if size > 0x322:
        comment_offsets.add(0x322)  # old unknown1/unknown2 annotation was unaligned
    for offset in sorted(comment_offsets):
        address = base + offset
        existing = _get_comment_at_compat(bv, address)
        retained = [line for line in existing.splitlines() if not (
            line.startswith(("candidate_quad[", "Zenella.uop[", "Zenella.seq[",
                             "Zenella.layout:", "Raw option bytes as LE16:"))
            or "layout=" in line and "confidence=" in line
            or line in ("Match register block", "Mask register block")
            or line.startswith("Raw match_tail bytes")
        )]
        if retained != existing.splitlines():
            bv.set_comment_at(address, "\n".join(retained))


def _resolve_registered_type(bv, value_type):
    for _ in range(8):
        target = getattr(value_type, "target", None)
        if not callable(target):
            return value_type
        value_type = target(bv)
        if value_type is None:
            raise RuntimeError("Unresolved named type in the applied layout")
    raise RuntimeError("Cyclic named type in the applied layout")


def _member_signature(bv, value_type):
    value_type = _resolve_registered_type(bv, value_type)
    return [(m.name, m.offset, len(m.type)) for m in value_type.members]



def _enum_items(bv, value_type) -> Dict[str, int]:
    value_type = _resolve_registered_type(bv, value_type)
    members = getattr(value_type, "members", ())
    if not members or not all(hasattr(member, "value") for member in members):
        members = getattr(value_type, "enumeration_members", ())
    return {member.name: int(member.value) for member in members}


def _uop_member_fields(value_type) -> Dict[str, Tuple[int, int]]:
    """Read effective bit ranges, independently of member enumeration order.

    BN represents an ordinary full-width member with bit_width == 0. For
    example uint16_t imm16 at byte zero is the same 16-bit slice as imm16:16.
    Zero width must NOT be accepted for an 8-bit opcode backed by a 16-bit enum.
    """
    fields = {}
    for member in value_type.members:
        name = str(member.name)
        if name in fields:
            raise RuntimeError(f"Duplicate micro-op field {name!r}")
        position = int(getattr(member, "bit_position", 0))
        offset = int(getattr(member, "bit_offset", int(member.offset) * 8 + position))
        width = int(getattr(member, "bit_width", 0))
        if width == 0:
            if position != 0:
                raise RuntimeError(f"Non-bitfield {name!r} has a nonzero bit position")
            width = len(member.type) * 8
        if offset < 0 or width <= 0 or offset + width > 64:
            raise RuntimeError(f"Micro-op field {name!r} extends outside its 64-bit word")
        fields[name] = (offset, width)
    return fields


def _verify_opcode_types(bv, uop_type) -> None:
    """Verify effective fields and all enum values, not API list order.

    A real position/width error still aborts. Diagnostics include each differing
    field instead of the former unhelpful 'positions differ' message.
    """
    uop_type = _resolve_registered_type(bv, uop_type)
    if len(uop_type) != ZEN5_RECORD_SIZE:
        raise RuntimeError("Micro-op structure must occupy exactly eight bytes")
    expected = {name: (offset, width) for name, offset, width in ZEN5_UOP_FIELDS}
    actual = _uop_member_fields(uop_type)
    if actual != expected:
        differences = [f"{name}: expected {expected.get(name)}, observed {actual.get(name)}"
                       for name in sorted(set(expected) | set(actual))
                       if actual.get(name) != expected.get(name)]
        raise RuntimeError("Micro-op bit ranges differ:\n" + "\n".join(differences))
    opcode_type = next(member.type for member in uop_type.members if member.name == "opcode")
    if _enum_items(bv, opcode_type) != ZEN_OPCODE_ENUM:
        raise RuntimeError("Applied opcode enum does not preserve every supplied opcode mapping")


def _verify_applied_zen5_layout(bv, base: int, parsed: ParsedZen5Patch, before: bytes) -> None:
    """Read back ACTUAL data variables, not just the types we attempted to define."""
    if bv.read(base, len(before)) != before:
        raise RuntimeError("Input bytes changed during an annotation-only operation")
    carve = None
    for r in zen5_display_regions(parsed):
        if r.name == "body":
            # The body may be carved into named op-quad-array sections (see _zen5_body_carve_plan);
            # then each section is verified instead of one body struct.
            carve = _zen5_body_carve_plan(parsed, r, "")
            if carve is not None:
                _verify_carved_zen5_body(bv, base, carve)
                continue
        actual = _data_var_type_at(bv, base + r.offset)
        if actual is None or len(actual) != len(r.raw):
            raise RuntimeError(f"Applied {r.name} variable at +0x{r.offset:x} has wrong width")
        actual = _resolve_registered_type(bv, actual)
        if r.name == "options" and len(r.raw) == 4:
            if _member_signature(bv, actual) != [("autorun", 0, 1), ("encrypted", 1, 1), ("loaderid", 2, 2)]:
                raise RuntimeError("Stale AMD_MC_UcodeOptions: expected uint16_t loaderid at +2")
        if r.name in ("match_registers", "mask_registers"):
            field = "match_reg" if r.name == "match_registers" else "mask_reg"
            if _member_signature(bv, actual) != [(field, 0, len(r.raw))]:
                raise RuntimeError(f"Stale {field} structure remains at +0x{r.offset:x}")
            if actual.members[0].type.count != len(r.raw) // 4:
                raise RuntimeError(f"Wrong {field} array count")
        if r.name == "body":
            code_size = len(parsed.quads) * ZEN5_OPQUAD_SIZE
            tail = zen5_tail_holds_registers(parsed.geometry)
            # Manual layout separates the trailing zero padding into its own region,
            # so the body is op-quads only (no folded data_words).
            separate_padding = any(reg.name == "zero_padding" for reg in parsed.regions)
            folds_data_words = bool(parsed.geometry.auxiliary_size) and not tail and not separate_padding
            expected_members = [("opquads", 0, code_size)]
            if folds_data_words:
                expected_members.append(("data_words", code_size, parsed.geometry.auxiliary_size))
            if _member_signature(bv, actual) != expected_members:
                raise RuntimeError("Old/raw instruction region is still applied")
            if folds_data_words:
                data_array = actual.members[1].type
                if len(data_array.element_type) != 4 or data_array.count * 4 != parsed.geometry.auxiliary_size:
                    raise RuntimeError("Body data_words must retain every stored 32-bit value")
            array = actual.members[0].type
            if array.count != len(parsed.quads):
                raise RuntimeError("Applied opquad count differs from selected loader")
            if _member_signature(bv, array.element_type) != [
                ("uop0", 0, 8), ("uop1", 8, 8), ("uop2", 16, 8), ("uop3", 24, 8), ("sequence_word", 32, 4)
            ]:
                raise RuntimeError("Expected four uint64 operations and a uint32 sequence word at +32")
            quad_type = _resolve_registered_type(bv, array.element_type)
            for member in quad_type.members[:4]:
                uop_type = _resolve_registered_type(bv, member.type)
                _verify_opcode_types(bv, uop_type)
    # An old auto-defined variable at +0x380/+0x418 can interrupt Linear View
    # even when every new region start has the right type.
    expected_addresses = {base + region.offset for region in zen5_display_regions(parsed)}
    if carve is not None:
        expected_addresses.update(base + seg[0] for seg in carve)
    for address, item in bv.data_vars.items():
        if base <= int(address) < base + len(before) and int(address) not in expected_addresses:
            if _zen5_owned_region_type(item.type) or any(
                    symbol.name in _ZEN5_OWNED_SYMBOLS for symbol in _symbols_at(bv, int(address))):
                raise RuntimeError(f"Stale Zenella variable still overlaps the layout at 0x{address:x}")
    if parsed.quads:
        scopes = _zen5_layout_type_names(parsed.geometry)
        expected = {"options": (T_OPTIONS, "amd_mc_options"),
                    "revision_copy": (None, "amd_mc_rev"),
                    "match_registers": (scopes["match_registers"], "amd_mc_match_regs"),
                    "mask_registers": (scopes["mask_registers"], "amd_mc_mask_regs"),
                    "body": (scopes["body"], SYM_ZEN5_BODY)}
        for region in zen5_display_regions(parsed):
            if region.name not in expected:
                continue
            if region.name == "body" and carve is not None:
                continue  # carved sections were verified above
            name, symbol = expected[region.name]
            actual_symbol = bv.get_symbol_at(base + region.offset)
            if actual_symbol is None or actual_symbol.name != symbol:
                raise RuntimeError(f"Expected visible symbol {symbol}; a competing symbol remains")
            if name and _registered_type_name(_data_var_type_at(bv, base + region.offset)) != name:
                raise RuntimeError(f"Expected registered type {name}; a detached/stale type remains")
        for quad in parsed.quads:
            if bv.read(base + quad.offset, ZEN5_OPQUAD_SIZE) != quad.raw:
                raise RuntimeError("Operation or sequence bytes disagree with the selected layout")


def _apply_zen5_layout(
    bv,
    base: int,
    layout: str = "loader",
    register_split: Optional[Tuple[int, int]] = None,
) -> bool:
    """Single apply engine: preflight -> cleanup -> types -> regions -> verify.

    Normal Apply uses the configured second-header loader profile. Opcode names
    and stored sequence values are unchanged; the 8015 display uses equal blocks.
    Failure is visible in a dialog AND the Log. Partial/encrypted raw fallback
    is useful in read-only reports but is not success for an Apply-code request.
    """
    stage = "preflight"
    try:
        _check_module_versions()
        _check_loaded_plugin_copies()
        if type(base) is not int or base < 0:
            raise ValueError("Patch address must be a non-negative integer")
        blob = bv.read(base, ZEN5_PATCH_SIZE)
        parsed = parse_zen5_patch(blob, layout=layout, register_split=register_split)
        geometry = parsed.geometry
        if geometry is None:
            raise RuntimeError("Parser returned no loader geometry")
        if layout != "raw" and not parsed.quads:
            raise RuntimeError(
                "No instruction layout was selected: the input is incomplete or "
                "marked encrypted. Existing analysis was not replaced.\n"
                + "\n".join(parsed.warnings))
        selector_label = (f"+0x{parsed.selector_offset:x}"
                          if parsed.selector_offset is not None else "unavailable")
        log_info(
            f"Zenella {PLUGIN_VERSION} APPLY BEGIN: mode={layout}, base=0x{base:x}, "
            f"selector={selector_label}, loaderid=0x{geometry.format_id:04x}, "
            f"body=0x{geometry.quad_offset:x}; module={os.path.abspath(__file__)}")

        transaction = getattr(bv, "undoable_transaction", None)
        if not callable(transaction):
            log_warn("Zenella: this API has no undoable_transaction; changes cannot be rolled back atomically")
        with transaction() if callable(transaction) else nullcontext():
            stage = "remove stale Zenella variables and symbols"
            _cleanup_stale_zen5_layout(bv, base, len(blob))
            stage = "rebuild loader-selected types"
            body_opquads_only = any(r.name == "zero_padding" for r in parsed.regions)
            _ensure_types(bv, force_legacy_zen5=True, zen5_geometry=geometry,
                          zen5_body_opquads_only=body_opquads_only)
            stage = "apply regions and annotations"
            _apply_zen5_regions(bv, base, parsed)
            stage = "verify applied database objects"
            _verify_applied_zen5_layout(bv, base, parsed, blob)

        _update_analysis_compat(bv)
        selector = (f"+0x{parsed.selector_offset:x}"
                    if parsed.selector_offset is not None else "unavailable")
        complete = len(blob) >= geometry.patch_size
        log_info(
            f"Zenella {PLUGIN_VERSION} APPLIED+VERIFIED: layout={parsed.layout}, "
            f"selector={selector}, loaderid=0x{geometry.format_id:04x}, "
            f"match/mask={geometry.register_split}, body=0x{geometry.quad_offset:x}, "
            f"quads={len(parsed.quads)}, complete={complete}; "
            f"module={os.path.abspath(__file__)}"
        )
        return complete
    except Exception as exc:
        message = (f"Stage: {stage}\n{exc}\n\n"
                   f"Plugin: {os.path.abspath(__file__)}\n"
                   "No successful Apply is reported. The Log contains the traceback.")
        log_error(f"Zenella {PLUGIN_VERSION}: apply layout FAILED: {message}\n{traceback.format_exc()}")
        _show_apply_error(message)
        return False


_ZEN5_OPQUAD_MEMBERS = [
    ("uop0", 0, 8), ("uop1", 8, 8), ("uop2", 16, 8), ("uop3", 24, 8), ("sequence_word", 32, 4)
]


def _zen5_body_carve_plan(parsed: ParsedZen5Patch, region, base_comment: str):
    """Plan how the op-quad body is carved into named AMD_Zen5_OpQuad[] data vars so the NOP
    section and the finalization sequence appear as distinct labelled blocks in the linear
    view (framed exactly like amd_mc_zero_padding) while every op-quad still decodes.

    Returns a list of (rel_offset, rel_end, symbol, comment, as_opquads) segments covering the
    body region gap-free, or None when the body must stay a single data var (no geometry, no
    detectable NOP section, or an unexpectedly short body). Shared by the define and verify
    stages so both agree on the exact addresses."""
    if parsed.geometry is None or not parsed.quads:
        return None
    sections = zen5_detect_body_sections(parsed.quads, region.offset)
    nop = next((s for s in sections if s["name"] == "nop_section"), None)
    if nop is None:
        return None
    opquad_bytes = parsed.geometry.quad_count * ZEN5_OPQUAD_SIZE
    if len(region.raw) < opquad_bytes:
        return None  # unexpected short body; leave it whole
    fin = next((s for s in sections if s["name"] == "finalization_section"), None)

    body_start = region.offset
    opquad_end = region.offset + opquad_bytes          # end of the decoded op-quad array
    body_end = region.offset + len(region.raw)          # may include folded data_words (loader layout)
    fin_start = fin["offset"] if fin is not None else nop["end"]
    fin_end = fin["end"] if fin is not None else nop["end"]

    nop_note = ("Zenella.section: NOP section: dense run of NOP words (opcode 0xFF) before the "
                "finalization sequence; op-quads still decoded")
    if not nop["aligned"]:
        nop_note += ("\nZenella.section: NOTE: at this register boundary the NOP words are shifted "
                     "off the uop slots, so they do not decode as opcode 0xFF NOP")
        hint = zen5_nop_alignment_hint(parsed.patch_bytes, region.offset, parsed.geometry.patch_size)
        split = parsed.geometry.register_split
        if hint is not None and split is not None:
            nop_note += (f"; a match+mask total of {sum(split) + hint['register_total_delta']} "
                         f"(op-quads at 0x{hint['suggested_quad_offset']:x}) puts them on the slots")
    plan = [
        (body_start, nop["offset"], SYM_ZEN5_BODY, base_comment, True),
        (nop["offset"], nop["end"], "amd_mc_nop_section", nop_note, True),
        (nop["end"], fin_start, "amd_mc_nop_sparse_opquads",
         "Zenella.section: single ops interleaved with NOPs between the NOP section and the "
         "finalization sequence; op-quads still decoded", True),
        (fin_start, fin_end, "amd_mc_finalization_section",
         "Zenella.section: Finalization sequence: op-quads after the last NOP of the NOP "
         "section's sparse tail, up to the trailing zero padding; op-quads still decoded", True),
        # Any op-quads after the finalization sequence (e.g. trailing zero op-quads when the
        # trailing zero padding is not carved into its own region, as in the loader/auto layout).
        (fin_end, opquad_end, SYM_ZEN5_OPQUADS,
         "Zenella.section: trailing op-quads after the finalization sequence (often zero-filled)", True),
        # Folded stored data words after the op-quad array (loader/auto layout keeps them inside body).
        (opquad_end, body_end, "amd_mc_body_data_words",
         "Zenella.layout: stored DWORD data after the op-quad array (purpose unverified)", False),
    ]
    return [seg for seg in plan if seg[1] > seg[0]]


def _define_zen5_body_sections(bv, parsed: ParsedZen5Patch, base: int, region, base_comment: str) -> bool:
    """Carve the op-quad body into named AMD_Zen5_OpQuad[] data vars: main code, the NOP section,
    the sparse NOP/op quads, and the finalization sequence, so the sections appear as distinct
    labelled blocks in the linear view (like amd_mc_zero_padding) while still decoding as op-quads.

    Returns True when it defined the segmented data vars; False to let the caller define the body
    as a single data var (see _zen5_body_carve_plan)."""
    plan = _zen5_body_carve_plan(parsed, region, base_comment)
    if plan is None:
        return False
    opquad_t = _named_type(bv, T_ZEN5_OPQUAD)
    for off_rel, end_rel, symbol, note, as_opquads in plan:
        length = end_rel - off_rel
        if as_opquads and opquad_t is not None and length % ZEN5_OPQUAD_SIZE == 0:
            value_type = Type.array(opquad_t, length // ZEN5_OPQUAD_SIZE)
        elif not as_opquads and length % 4 == 0:
            value_type = Type.array(u32(), length // 4)
        else:
            value_type = Type.array(u8(), length)
        address = base + off_rel
        bv.define_user_data_var(address, value_type)
        bv.define_user_symbol(Symbol(SymbolType.DataSymbol, address, symbol))
        bv.set_comment_at(address, note)
    return True


def _verify_carved_zen5_body(bv, base: int, plan) -> None:
    """Read back every carved body segment: exact width, the planned symbol, and (for op-quad
    segments) an AMD_Zen5_OpQuad[] whose element still has four uint64 operations + the
    uint32 sequence word with the supplied opcode enum."""
    for off_rel, end_rel, symbol, _note, as_opquads in plan:
        address = base + off_rel
        length = end_rel - off_rel
        actual = _data_var_type_at(bv, address)
        if actual is None or len(actual) != length:
            raise RuntimeError(f"Applied body section {symbol} at +0x{off_rel:x} has wrong width")
        found = bv.get_symbol_at(address)
        if found is None or found.name != symbol:
            raise RuntimeError(f"Expected visible symbol {symbol} at +0x{off_rel:x}; a competing symbol remains")
        if as_opquads and length % ZEN5_OPQUAD_SIZE == 0:
            array = _resolve_registered_type(bv, actual)
            element = getattr(array, "element_type", None)
            count = getattr(array, "count", None)
            if element is None or count != length // ZEN5_OPQUAD_SIZE:
                raise RuntimeError(f"Body section {symbol} at +0x{off_rel:x} is not an op-quad array")
            if _member_signature(bv, element) != _ZEN5_OPQUAD_MEMBERS:
                raise RuntimeError("Expected four uint64 operations and a uint32 sequence word at +32")
            quad_type = _resolve_registered_type(bv, element)
            for member in quad_type.members[:4]:
                _verify_opcode_types(bv, _resolve_registered_type(bv, member.type))


def _apply_zen5_regions(bv, base: int, parsed: ParsedZen5Patch) -> None:
    """Apply the parsed regions and annotations after types have been rebuilt."""
    scoped = _zen5_layout_type_names(parsed.geometry)
    mapping = {
        "header": (T_HEADER, "amd_mc_header"),
        "options": (T_OPTIONS, "amd_mc_options"),
        "revision_copy": (None, "amd_mc_rev"),
        "register_table": (scoped.get("register_table"), SYM_ZEN5_PRECODE),
        "match_registers": (scoped.get("match_registers"), "amd_mc_match_regs"),
        "mask_registers": (scoped.get("mask_registers"), "amd_mc_mask_regs"),
        "prefix_metadata": (scoped.get("prefix_metadata"), SYM_ZEN5_METADATA),
        "match_mask_table": (scoped.get("match_mask_table"), SYM_ZEN5_MATCHMASK),
        "body": (scoped.get("body"), SYM_ZEN5_BODY),
        "opaque_payload": (None, "amd_mc_payload_raw"),
    }
    for region in zen5_display_regions(parsed):
        type_name, symbol = mapping.get(region.name, (None, "amd_mc_" + region.name))
        value_type = _named_type(bv, type_name) if type_name else None
        if region.name == "revision_copy" and len(region.raw) == 4:
            value_type = u32()
        if value_type is None or len(value_type) != len(region.raw):
            value_type = Type.array(u8(), len(region.raw))
        address = base + region.offset
        old_comment = _get_comment_at_compat(bv, address)
        # Replace only generated layout text, not independent researcher comments.
        old_comment = "\n".join(line for line in old_comment.splitlines() if not (
            line.startswith("Zenella.layout:")
            or ("layout=" in line and "confidence=" in line)
        ))
        comment = "Zenella.layout: " + region.interpretation
        if old_comment:
            comment += "\n" + old_comment
        # The op-quad body is carved into named op-quad-array data vars (main / NOP / finalization)
        # so the NOP and finalization sections appear as distinct labelled blocks in linear view,
        # exactly like amd_mc_zero_padding but typed as AMD_Zen5_OpQuad[] so op-quads still decode.
        if region.name == "body" and _define_zen5_body_sections(bv, parsed, base, region, comment):
            continue
        bv.define_user_data_var(address, value_type)
        bv.define_user_symbol(Symbol(SymbolType.DataSymbol, address, symbol))
        bv.set_comment_at(address, comment)
    _apply_common_comments(bv, base, ZEN5)
    has_zero_padding = any(r.name == "zero_padding" for r in parsed.regions)
    if parsed.quads and parsed.geometry.auxiliary_size and not has_zero_padding:
        if zen5_tail_holds_registers(parsed.geometry):
            _append_comment_at(bv, base + parsed.geometry.code_end,
                "Zenella.layout: match/mask registers after the op-quads, two equal halves "
                "(13-bit ROM match addresses + control, then masks); trailing slots zero-filled")
        else:
            _append_comment_at(bv, base + parsed.geometry.code_end,
                f"Zenella.layout: {parsed.geometry.auxiliary_size}-byte remainder after the op-quads "
                "(unavoidable: a valid-sequence op-quad offset cannot tile the patch to the exact end); "
                "not opquads, not registers")
    # Do not generate a second copy of the renderer's output as address comments.
    # The fallback still provides opcode names when a BN build has no DataRenderer.
    if not _register_zen5_renderer():
        for index, quad in enumerate(parsed.quads):
            for slot, tag in enumerate(quad.uops):
                _append_comment_at(bv, base + tag.offset,
                    f"Zenella.uop[{index}.{slot}]: " + zen5_uop_field_text(tag, _ZEN5_TAG_NAMES))

    # Sequence words stay plain uint32_t. Annotate the upstream interpretation
    # once, regardless of whether the micro-op renderer is installed.
    for index, quad in enumerate(parsed.quads):
        _append_comment_at(bv, base + quad.offset + 32,
            f"Zenella.seq[{index}]: " + decode_zentool_sequence_word(quad.sequence_word).text)
    stats = zen5_sequence_statistics(parsed.quads)
    log_info(f"Zenella: stored sequence_word==1: {stats['exact_one_count']}/{stats['count']}; "
             "zentool interpretation is relative +1, not a sequence counter")
    for warning in parsed.warnings:
        log_warn("Zenella: " + warning)


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


# --- Auto-detect -------------------------------------------------------------
def cmd_auto_start(bv):
    return _auto_detect_and_apply(bv, 0)


def cmd_auto_cursor(bv, address):
    return _auto_detect_and_apply(bv, address)


# --- Zen1 / Zen2 disassembly + LLIL/HLIL lifting -----------------------------
def cmd_zen1_start(bv):
    return _apply_profile(bv, 0, ZEN1, map_hlil=True)


def cmd_zen1_cursor(bv, address):
    return _apply_profile(bv, address, ZEN1, map_hlil=True)


def cmd_zen2_start(bv):
    return _apply_profile(bv, 0, ZEN2, map_hlil=True)


def cmd_zen2_cursor(bv, address):
    return _apply_profile(bv, address, ZEN2, map_hlil=True)


def cmd_zen12_report_start(bv):
    return _show_zen12_report(bv, 0)


def cmd_zen12_report_cursor(bv, address):
    return _show_zen12_report(bv, address)


# --- Zen5 structural layout ---------------------------------------------------
def cmd_zen5_start(bv):
    """Normal file-start Apply path: the confirmed loader-0x8015 geometry with
    match[31]/mask[31] registers at 0x328 and op-quads from 0x420 up to the
    trailing zero padding (ZEN5_8015_REGISTER_SPLIT in zenella_core)."""
    return _apply_zen5_layout(bv, 0, layout="loader")


def cmd_zen5_cursor(bv, address):
    """Same implementation for an embedded patch."""
    return _apply_zen5_layout(bv, address, layout="loader")


def cmd_zen5_exactfit_start(bv):
    """Experimental: force the exact-fit 0x418/370 view (no tail).

    The normal Zen5 apply auto-detects 0x420 vs 0x418 from the op-quad/sequence
    content; this forces the exact-fit alternative for comparison. Note it may
    misalign sequence words (0x0 instead of the documented +1) on updates whose
    real body is at 0x420 -- that is exactly what auto-detect avoids.
    """
    return _apply_zen5_layout(bv, 0, layout="exact")


def cmd_zen5_scan_start(bv):
    """Experimental: scan candidate body offsets (register-area sizes) and apply
    the one whose sequence words look most reasonable. No documented evidence
    backs any particular size; this is an empirical alignment search.
    """
    return _apply_zen5_layout(bv, 0, layout="scan")


def cmd_zen5_tail_start(bv):
    """Experimental: metadata before the op-quads, equal match/mask registers AFTER
    them. Op-quads at 0x420 (valid sequences) and the 0x2820 region is the register
    table, so this has no trailer AND no 0x0 sequence words at the same time.
    """
    return _apply_zen5_layout(bv, 0, layout="tail")


def cmd_zen5_manual_registers(bv):
    """Experimental: manually set the match and mask register DWORD counts.

    The op-quad body boundary moves to 0x328 + 4*(match+mask), so this brute-forces
    where the register area ends and the microcode begins. No documented evidence
    backs any particular size; it is an interactive alignment probe.
    """
    from binaryninja.interaction import get_int_input
    title = "Zenella: manual register boundary"
    match_count = get_int_input("Match register DWORDs", title)
    if match_count is None:
        log_info("Zenella: manual register boundary cancelled")
        return False
    mask_count = get_int_input("Mask register DWORDs", title)
    if mask_count is None:
        log_info("Zenella: manual register boundary cancelled")
        return False
    if match_count <= 0 or mask_count <= 0:
        log_error("Zenella: match and mask register counts must both be positive")
        return False
    blob = bv.read(0, _core_module.ZEN5_PATCH_SIZE)
    fit = _core_module.zen5_manual_fit(match_count, mask_count, blob)
    # Warn when this match+mask total misaligns the op-quads: the NOP section is still found
    # and framed at this boundary, but its NOP words are shifted off the uop slots (so they do
    # not decode as opcode 0xFF NOP) while a nearby 4/8-byte shift puts them on the slots.
    quad_offset = _core_module.EXTENDED_HEADER_SIZE + 4 * (match_count + mask_count)
    hint = zen5_nop_alignment_hint(blob, quad_offset, _core_module.ZEN5_PATCH_SIZE)
    if hint is not None:
        total = match_count + mask_count
        want_total = total + hint["register_total_delta"]
        shift = abs(hint["delta"])
        msg = (f"match+mask total {total} puts the op-quads at 0x{quad_offset:x}. The NOP section "
               f"is found there (framed as amd_mc_nop_section), but its NOP words are shifted "
               f"{shift} bytes off the uop slots, so they do not decode as opcode 0xFF NOP. "
               f"A total of {want_total} (op-quads at 0x{hint['suggested_quad_offset']:x}) puts the "
               f"{hint['nop_quads']}-quad NOP run on the slots.")
        other = _core_module.zen5_manual_fit(match_count, mask_count + hint["register_total_delta"], blob)
        if fit["tail_bytes"] == 0 and fit["padding_bytes"] and other["tail_bytes"]:
            msg += (f" Note: {total} is the total that meets the zero padding exactly; "
                    f"{want_total} leaves a {other['tail_bytes']}-byte tail before it.")
        log_warn("Zenella: " + msg)
        _show_notice("op-quad alignment", msg)
    boundary = (f"the zero padding at 0x{fit['padding_start']:x}"
                if fit["padding_bytes"] else "the patch end")
    if fit["tail_bytes"]:
        notice = (
            f"match[{match_count}]/mask[{mask_count}] (total {match_count + mask_count}) "
            f"leaves {fit['tail_bytes']} bytes between the op-quad body and {boundary}.\n"
            f"For a clean body|padding split use a match+mask total of "
            f"{fit['exact_fit_totals']} (any split summing to that).\nApplying anyway.")
        log_warn("Zenella: " + notice.replace("\n", " "))
        _show_notice("trailing bytes", notice)
    elif fit["padding_bytes"]:
        log_info(
            f"Zenella: manual match[{match_count}]/mask[{mask_count}]: {fit['quad_count']} "
            f"op-quads meet the zero padding at 0x{fit['padding_start']:x} exactly "
            f"({fit['padding_bytes']} padding bytes)")
    else:
        log_info(
            f"Zenella: manual match[{match_count}]/mask[{mask_count}] is exact-fit to the "
            f"patch end ({fit['quad_count']} op-quads, no trailing bytes)")
    return _apply_zen5_layout(bv, 0, layout="manual",
                              register_split=(match_count, mask_count))


#####################################################################################################
# Zen5 enum-token DataRenderer. Restores the user's opcode names and fields.
# No per-word raw/projection/uncertainty paragraphs are inserted into Linear view.
#####################################################################################################
_ZEN5_RENDER_STRUCT_NAMES = (T_ZEN5_MICROOP64, T_ZEN5_TAG, T_LEGACY_UOP)
_ZEN5_RENDERER_INSTANCE = None
_ZEN5_RENDERER_REGISTERED = False


def _safe_is_type_of_struct_name(type_obj, name, context) -> bool:
    if DataRenderer is None:
        return False
    try:
        return bool(DataRenderer.is_type_of_struct_name(type_obj, name, context))
    except Exception:
        return False


def _zen5_render_tokens(word: int, prefix):
    """Tokens for one micro-op: 'opcode = <NAME>  rd=.. rs=.. ... unit=..'."""
    text_type = _instruction_token_type("TextToken")
    enum_type = _instruction_token_type("EnumerationMemberToken", "TypeNameToken", "TextToken")
    tag = decode_zen5_tag(word.to_bytes(8, "little"))
    class_name = OPCLASS_NAMES.get(tag.exec_unit, f"0b{tag.exec_unit:03b}")
    is_ldstop = zen5_is_ldstop(tag)
    tokens = list(prefix)
    tokens.append(_token(text_type, "opcode = "))
    if is_ldstop:
        # A LdStOp resolves to a concrete LD/ST by the ldst bit (bit 45): 1 -> LD, 0 -> ST.
        # The [47:55] slice is not a LdStOp's type, so it is not used for the name.
        name, value = ("AMD_ZEN_LD", 0x100) if tag.load else ("AMD_ZEN_ST", 0x101)
        tokens.append(_token(enum_type, name, value))
    elif tag.opcode == 0x00:
        # Non-LdStOp with a zero opcode slice: the legacy AMD_ZEN_UOP_LD_ST_00 name implied
        # load/store, which this is not. Label it by class (all-zero words are class=0 -> SPEC).
        tokens.append(_token(text_type, f"{class_name.upper()}.0x00"))
    else:
        name = _ZEN5_TAG_NAMES.get(tag.opcode)
        if name is not None:
            tokens.append(_token(enum_type, name, tag.opcode))
        else:
            tokens.append(_token(text_type, f"0x{tag.opcode:02x}"))
    tokens.append(_token(
        text_type,
        f"  rd=r{tag.rd} rs=r{tag.rs} rt=r{tag.rt} imm16=0x{tag.imm16:04x} "
        f"size={tag.size} ld={tag.load} st={tag.store} "
        f"class={tag.exec_unit} ({class_name})",
    ))
    # Flag op-quad framing artifacts (top 32 bits zero, low 32 bits real data): not a real op.
    # The single-record renderer has no patch-wide sequence-word set, so it flags on top32==0.
    if zen5_is_alignment_artifact(tag):
        tokens.append(_token(text_type, "  (align?)"))
        return tokens
    # Append the inferred per-opcode operand decode for nonzero words only; the
    # single-record renderer has no previous word, so imm32 shows its low half.
    if tag.word != 0:
        tokens.append(_token(text_type, "  asm=" + zen5_uop_operand_text(tag)))
    return tokens


if DataRenderer is not None:

    class _Zen5MicroOpRenderer(DataRenderer):
        """Type-specific renderer for AMD_Zen5_MicroOp64 / AMD_Zen5_MicroOpTag / AMD_Zen_MicroOp."""

        def perform_is_valid_for_data(self, ctxt, view, addr, type_obj, context):
            return any(
                _safe_is_type_of_struct_name(type_obj, name, context)
                for name in _ZEN5_RENDER_STRUCT_NAMES
            )

        def _render(self, view, addr, prefix):
            try:
                raw = view.read(addr, ZEN5_RECORD_SIZE)
            except Exception:
                raw = None
            if not raw or len(raw) != ZEN5_RECORD_SIZE:
                return []
            word = int.from_bytes(raw, "little")
            tokens = _zen5_render_tokens(word, prefix)
            if DisassemblyTextLine is None:
                return []
            try:
                return [DisassemblyTextLine(tokens, addr)]
            except Exception:
                try:
                    return [DisassemblyTextLine(tokens)]
                except Exception:
                    return []

        # The documented API exposes both entry points; implement both.
        def perform_get_lines_for_data(self, ctxt, view, addr, type_obj, prefix, width, context):
            return self._render(view, addr, prefix)

        def perform_get_lines_for_data_with_language(
            self, ctxt, view, addr, type_obj, prefix, width, context, language
        ):
            return self._render(view, addr, prefix)

else:  # pragma: no cover - depends on Binary Ninja build
    _Zen5MicroOpRenderer = None


def _register_zen5_renderer() -> bool:
    global _ZEN5_RENDERER_INSTANCE, _ZEN5_RENDERER_REGISTERED
    if _ZEN5_RENDERER_REGISTERED:
        return True
    if _Zen5MicroOpRenderer is None or DisassemblyTextLine is None:
        log_warn("Zenella: Binary Ninja DataRenderer API unavailable; opcode names remain in comments and reports")
        return False
    try:
        renderer = _Zen5MicroOpRenderer()
        renderer.register_type_specific()
        _ZEN5_RENDERER_INSTANCE = renderer
        _ZEN5_RENDERER_REGISTERED = True
        return True
    except Exception as exc:  # pragma: no cover - depends on Binary Ninja build
        log_warn(f"Zenella: could not register the Zen5 micro-op renderer: {exc}")
        return False


#####################################################################################################
# Plugin registration
#####################################################################################################
_PLUGIN_COMMANDS_REGISTERED = False


def _register_plugin_commands() -> None:
    """Only file-start and cursor Apply; reports remain available through the CLI.

    Remove old installed Zenella copies before restarting. A plugin cannot
    safely unregister another module's native renderers by dropping Python refs.
    """
    global _PLUGIN_COMMANDS_REGISTERED
    if _PLUGIN_COMMANDS_REGISTERED:
        return
    R = MENU_ROOT

    # Auto-detect the architecture from the header, then apply the right layout.
    PluginCommand.register(
        R + r"\Auto-detect and apply at file start",
        "Detect Zen1/Zen2/Zen5 from the header and apply the matching layout",
        cmd_auto_start,
    )
    PluginCommand.register_for_address(
        R + r"\Auto-detect and apply at cursor",
        "Detect and apply the matching layout for a patch beginning at the cursor",
        cmd_auto_cursor,
    )

    # Zen1: full disassembly + LLIL/HLIL lifting.
    PluginCommand.register(
        R + r"\Zen1\Apply layout + LLIL/HLIL at file start",
        "Apply the Zen1 layout and lift micro-ops to LLIL/HLIL",
        cmd_zen1_start,
    )
    PluginCommand.register_for_address(
        R + r"\Zen1\Apply layout + LLIL/HLIL at cursor",
        "Apply the Zen1 layout and lift micro-ops at the cursor",
        cmd_zen1_cursor,
    )

    # Zen2: full disassembly + LLIL/HLIL lifting.
    PluginCommand.register(
        R + r"\Zen2\Apply layout + LLIL/HLIL at file start",
        "Apply the Zen2 layout and lift micro-ops to LLIL/HLIL",
        cmd_zen2_start,
    )
    PluginCommand.register_for_address(
        R + r"\Zen2\Apply layout + LLIL/HLIL at cursor",
        "Apply the Zen2 layout and lift micro-ops at the cursor",
        cmd_zen2_cursor,
    )

    # Shared Zen1/Zen2 text disassembly report (ZenUtils style).
    PluginCommand.register(
        R + r"\Zen1-Zen2\Show ZenUtils-style disassembly at file start",
        "Print a ZenUtils-style disassembly of the Zen1/Zen2 payload",
        cmd_zen12_report_start,
    )
    PluginCommand.register_for_address(
        R + r"\Zen1-Zen2\Show ZenUtils-style disassembly at cursor",
        "Print a ZenUtils-style disassembly for a patch at the cursor",
        cmd_zen12_report_cursor,
    )

    # Zen5: structural layout (confirmed 0x8015 geometry: match[31]/mask[31], op-quads at 0x420).
    PluginCommand.register(
        R + r"\Zen5\Apply structural layout at file start",
        "Apply the confirmed 0x8015 layout: match[31]/mask[31] registers at 0x328, op-quads from "
        "0x420 to the zero padding, opcode tags and sequence words",
        cmd_zen5_start,
    )
    PluginCommand.register_for_address(
        R + r"\Zen5\Apply structural layout at cursor",
        "Apply the same confirmed match[31]/mask[31] layout to a patch beginning at the cursor",
        cmd_zen5_cursor,
    )
    PluginCommand.register(
        R + r"\Zen5\Experimental\Apply exact-fit 0x418/370 (no tail) at file start",
        "Force the exact-fit body (370 opquads, no trailing tail) instead of the auto-detected offset",
        cmd_zen5_exactfit_start,
    )
    PluginCommand.register(
        R + r"\Zen5\Experimental\Apply best-scoring body offset (scan) at file start",
        "Scan register-area sizes and apply the offset whose sequence words look most reasonable (no documented evidence)",
        cmd_zen5_scan_start,
    )
    PluginCommand.register(
        R + r"\Zen5\Experimental\Apply tail match-mask model (no trailer, valid sequences) at file start",
        "Metadata before the op-quads; equal match/mask registers after them (op-quads at 0x420, no trailer, no 0x0 sequences)",
        cmd_zen5_tail_start,
    )
    PluginCommand.register(
        R + r"\Zen5\Experimental\Set match/mask register counts (move boundary) at file start",
        "Manually set match and mask register DWORD counts; the op-quad body boundary moves to "
        "0x328 + 4*(match+mask). Experimental; no documented evidence backs any particular size.",
        cmd_zen5_manual_registers,
    )
    _PLUGIN_COMMANDS_REGISTERED = True


_register_zen5_renderer()
_register_plugin_commands()
log_info(
    f"Zenella {PLUGIN_VERSION}: loaded from {os.path.abspath(__file__)}; "
    f"menu root '{MENU_ROOT}' with Auto-detect, Zen1, Zen2, Zen1-Zen2 and Zen5 commands; "
    f"Zen5 default layout is the confirmed 0x8015 geometry: match[31]/mask[31] at 0x328, op-quads at 0x420"
)
