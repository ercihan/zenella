#####################################################################################################
#####################################################################################################
#####################################################################################################
# Author: Kaya Ercihan
# Version: 2.2.0
# Description: Pre-Zen (K8/K10, families 0x0F-0x12) AMD microcode layout and disassembly for Binary Ninja
# Self-containment: structural types, raw-file layout, executable triad mirror, architecture and menu commands
# License: GPL-3.0-only
#####################################################################################################
#####################################################################################################
#####################################################################################################
"""Zenella pre-Zen support: menu group "AMD Microcode\\Pre-Zen (K8/K10)".

The patch file keeps its obfuscated triads.  "Apply layout + disassembly" annotates the raw file
(header, match registers, obfuscated triad array) and mirrors the triad array into a file-backed
executable segment at ``region + 0x15000`` (triad 0xC00 * 28 bytes) with the
``amd_prezen_ucode`` architecture.  That architecture de-obfuscates each micro-op from its own eight
bytes plus the triad index derived from the address, so no cache is needed and a saved BNDB keeps
disassembling after reopening.  The decoder itself lives in :mod:`prezen_core` and renders the same
text as the GhidraAmdMicrocode SLEIGH specification.
"""
from __future__ import annotations

import threading
from typing import Dict, List, Optional, Set, Tuple

from binaryninja import (
    Architecture,
    BranchType,
    Endianness,
    FlagRole,
    InstructionInfo,
    InstructionTextToken,
    InstructionTextTokenType,
    LowLevelILLabel,
    PluginCommand,
    RegisterInfo,
    SectionSemantics,
    SegmentFlag,
    SymbolType,
    Type,
    log_error,
    log_info,
    log_warn,
    show_plain_text_report,
)

if __package__:
    from . import prezen_core as _prezen_module
    from . import amd_zen_ucode as _zen_module
else:  # Direct import for manual development use
    import prezen_core as _prezen_module
    import amd_zen_ucode as _zen_module

DecodedPreZenOp = _prezen_module.DecodedPreZenOp
DecodedPreZenSequence = _prezen_module.DecodedPreZenSequence
ParsedPreZenPatch = _prezen_module.ParsedPreZenPatch
PREZEN_MATCH_OFFSET = _prezen_module.PREZEN_MATCH_OFFSET
PREZEN_MATCH_COUNT = _prezen_module.PREZEN_MATCH_COUNT
PREZEN_TRIADS_OFFSET = _prezen_module.PREZEN_TRIADS_OFFSET
PREZEN_TRIAD_SIZE = _prezen_module.PREZEN_TRIAD_SIZE
PREZEN_OP_SIZE = _prezen_module.PREZEN_OP_SIZE
PREZEN_SEQ_SIZE = _prezen_module.PREZEN_SEQ_SIZE
PREZEN_SEQ_OFFSET = _prezen_module.PREZEN_SEQ_OFFSET
PREZEN_MAX_TRIADS = _prezen_module.PREZEN_MAX_TRIADS
PREZEN_MAX_PATCH_SIZE = _prezen_module.PREZEN_MAX_PATCH_SIZE
PREZEN_PATCH_RAM_TRIAD = _prezen_module.PREZEN_PATCH_RAM_TRIAD
PREZEN_PATCH_RAM_BYTE_OFFSET = _prezen_module.PREZEN_PATCH_RAM_BYTE_OFFSET
PREZEN_ROM_TRIADS = _prezen_module.PREZEN_ROM_TRIADS
PREZEN_REGISTERS = _prezen_module.PREZEN_REGISTERS
decode_prezen_op = _prezen_module.decode_prezen_op
decode_prezen_sequence = _prezen_module.decode_prezen_sequence
deobfuscate_op_word = _prezen_module.deobfuscate_op_word
deobfuscate_sequence_word = _prezen_module.deobfuscate_sequence_word
detect_prezen = _prezen_module.detect_prezen
parse_prezen_patch = _prezen_module.parse_prezen_patch
prezen_triad_byte_offset = _prezen_module.prezen_triad_byte_offset
render_prezen_listing = _prezen_module.render_prezen_listing
render_prezen_header_lines = _prezen_module.render_prezen_header_lines

MENU_ROOT = _zen_module.MENU_ROOT
PLUGIN_VERSION = _zen_module.PLUGIN_VERSION
CODE_LABEL_SYMBOL = _zen_module.CODE_LABEL_SYMBOL
_qn = _zen_module._qn
u8 = _zen_module.u8
u16 = _zen_module.u16
u32 = _zen_module.u32
u64 = _zen_module.u64
_new_structure_builder = _zen_module._new_structure_builder
_type_structure = _zen_module._type_structure
_named_type = _zen_module._named_type
_make_enum_type = _zen_module._make_enum_type
_define_data_var = _zen_module._define_data_var
_add_symbol = _zen_module._add_symbol
_append_comment_at = _zen_module._append_comment_at
_update_analysis_compat = _zen_module._update_analysis_compat
_align_up = _zen_module._align_up
_source_data_offset = _zen_module._source_data_offset
_create_user_function_compat = _zen_module._create_user_function_compat
_show_apply_error = _zen_module._show_apply_error
_show_notice = _zen_module._show_notice
_token = _zen_module._token
_comma = _zen_module._comma
_register_token = _zen_module._register_token
_integer_token = _zen_module._integer_token

#####################################################################################################
# Constants
#####################################################################################################

PREZEN_MENU = MENU_ROOT + r"\Pre-Zen (K8/K10)"
# The whole K8/K10 microcode address space is 0x1000 triads * 28 bytes = 0x1C000 bytes; keep each
# synthetic region 128 KiB aligned so 'address & mask' recovers the region base for any triad address.
PREZEN_REGION_ALIGNMENT = 0x20000
PREZEN_REGION_MASK = ~(PREZEN_REGION_ALIGNMENT - 1)
PREZEN_ADDRESS_SPACE_SIZE = PREZEN_ROM_TRIADS * PREZEN_TRIAD_SIZE

T_PREZEN_LOADER_ENUM = "AMD_PreZen_LoaderIdTag"
T_PREZEN_HEADER = "AMD_PreZen_Header"
T_PREZEN_MATCH = "AMD_PreZen_MatchRegister"
T_PREZEN_TRIAD_RAW = "AMD_PreZen_TriadObfuscated"
T_PREZEN_TRIAD = "AMD_PreZen_Triad"
SYM_PREZEN_HEADER = "amd_prezen_header"
SYM_PREZEN_MATCH = "amd_prezen_match_regs"
SYM_PREZEN_TRIADS = "amd_prezen_triads_raw"

PREZEN_LOADER_ID_ENUM: Dict[str, int] = {
    "PREZEN_K8_K10_0x8000": 0x8000,
    "PREZEN_FAMILY12_0x8003": 0x8003,
}

#####################################################################################################
# Mapping registry: synthetic region base -> number of mapped triads (decode bound)
#####################################################################################################

_PREZEN_MAPPING_LOCK = threading.RLock()
_PREZEN_MAPPINGS: Dict[Tuple[str, int], int] = {}


def _register_prezen_mapping(architecture_name: str, region_base: int, triad_count: int) -> None:
    with _PREZEN_MAPPING_LOCK:
        _PREZEN_MAPPINGS[(architecture_name, region_base)] = int(triad_count)


def _prezen_triad_bound(architecture_name: str, region_base: int) -> int:
    """Mapped triad count for a region; the maximum when unknown (for example after a BNDB reopen)."""
    with _PREZEN_MAPPING_LOCK:
        return _PREZEN_MAPPINGS.get((architecture_name, region_base), PREZEN_MAX_TRIADS)


def _prezen_location(architecture_name: str, address: int) -> Optional[Tuple[str, int, int, int]]:
    """Return ``(kind, triad_index, slot, length)`` for a synthetic address, or ``None``.

    ``triad_index`` counts from the first patch triad (uc_0c00); ``slot`` is 0..2 for micro-ops and
    3 for the sequence word.
    """
    region = address & PREZEN_REGION_MASK
    relative = address - region - PREZEN_PATCH_RAM_BYTE_OFFSET
    if relative < 0:
        return None
    triad_index, within = divmod(relative, PREZEN_TRIAD_SIZE)
    if triad_index >= _prezen_triad_bound(architecture_name, region):
        return None
    if within in (0, PREZEN_OP_SIZE, 2 * PREZEN_OP_SIZE):
        return "op", triad_index, within // PREZEN_OP_SIZE, PREZEN_OP_SIZE
    if within == PREZEN_SEQ_OFFSET:
        return "sequence", triad_index, 3, PREZEN_SEQ_SIZE
    return None


def _prezen_mapped_target(address: int, triad_address: int) -> Optional[int]:
    """Synthetic address of a patch-RAM triad target; ``None`` for ROM or beyond the mapped triads."""
    region = address & PREZEN_REGION_MASK
    index = triad_address - PREZEN_PATCH_RAM_TRIAD
    if 0 <= index < _prezen_triad_bound(PreZenUcodeArchitecture.name, region):
        return region + prezen_triad_byte_offset(triad_address)
    return None


#####################################################################################################
# Tokens
#####################################################################################################


def _prezen_target_token(address: int, triad_address: int) -> InstructionTextToken:
    mapped = _prezen_mapped_target(address, triad_address)
    byte_offset = prezen_triad_byte_offset(triad_address)
    return _token(
        InstructionTextTokenType.PossibleAddressToken,
        hex(byte_offset),
        mapped if mapped is not None else byte_offset,
    )


def _prezen_op_tokens(decoded: DecodedPreZenOp, address: int) -> List[InstructionTextToken]:
    tokens: List[InstructionTextToken] = [
        _token(InstructionTextTokenType.InstructionToken, decoded.display_mnemonic),
        _token(InstructionTextTokenType.TextToken, " "),
    ]
    if decoded.is_jcc:
        tokens.append(_token(InstructionTextTokenType.TextToken, decoded.cc_name))
        _comma(tokens)
        tokens.append(_prezen_target_token(address, decoded.braddr))
        return tokens
    if not decoded.known:
        tokens.append(_integer_token(decoded.operation))
        _comma(tokens)
    tokens.append(_register_token(decoded.dst_name))
    _comma(tokens)
    if decoded.three_op:
        tokens.append(_register_token(decoded.src1_name))
        _comma(tokens)
    if decoded.src_is_register:
        tokens.append(_register_token(decoded.src2_name))
    else:
        tokens.append(_integer_token(decoded.imm))
    return tokens


def _prezen_sequence_tokens(decoded: DecodedPreZenSequence, address: int) -> List[InstructionTextToken]:
    if decoded.action == "branch":
        return [
            _token(InstructionTextTokenType.InstructionToken, "sw_branch"),
            _token(InstructionTextTokenType.TextToken, " "),
            _prezen_target_token(address, decoded.target or 0),
        ]
    if decoded.action == "complete":
        return [_token(InstructionTextTokenType.InstructionToken, "sw_complete")]
    if decoded.action == "next":
        return [_token(InstructionTextTokenType.InstructionToken, "sw_next")]
    return [
        _token(InstructionTextTokenType.InstructionToken, "sw_raw"),
        _token(InstructionTextTokenType.TextToken, " "),
        _integer_token(decoded.word),
    ]


#####################################################################################################
# Architecture
#####################################################################################################


def _build_prezen_registers() -> Dict[str, RegisterInfo]:
    result = {name: RegisterInfo(name, 8) for name in PREZEN_REGISTERS}
    result["ucode_sp"] = RegisterInfo("ucode_sp", 8)
    result["ucode_ra"] = RegisterInfo("ucode_ra", 8)
    return result


PREZEN_UCODE_REGS = _build_prezen_registers()


class PreZenUcodeArchitecture(Architecture):
    """K8/K10 microcode: three 64-bit micro-ops and a 32-bit sequence word per 28-byte triad.

    Instructions are decoded from their own bytes: the triad index comes from the address and the
    de-obfuscation of each word only needs that index and the word position.
    """

    name = "amd_prezen_ucode"
    profile_name = "Pre-Zen"
    endianness = Endianness.LittleEndian
    address_size = 8
    default_int_size = 4
    instr_alignment = 1
    max_instr_length = PREZEN_OP_SIZE
    opcode_display_length = PREZEN_OP_SIZE
    regs = PREZEN_UCODE_REGS
    stack_pointer = "ucode_sp"
    link_reg = "ucode_ra"
    flags = ["ucond"]
    flag_roles = {"ucond": FlagRole.SpecialFlagRole}

    def _decode(self, data: bytes, address: int):
        location = _prezen_location(self.name, address)
        if location is None:
            return None
        kind, triad_index, slot, length = location
        if len(data) < length:
            return None
        if kind == "sequence":
            word = deobfuscate_sequence_word(data[:PREZEN_SEQ_SIZE], triad_index)
            return kind, decode_prezen_sequence(word), length
        word = deobfuscate_op_word(data[:PREZEN_OP_SIZE], triad_index, slot)
        return kind, decode_prezen_op(word), length

    def get_instruction_info(self, data: bytes, address: int):
        decoded_tuple = self._decode(data, address)
        if decoded_tuple is None:
            return None
        kind, decoded, length = decoded_tuple
        info = InstructionInfo()
        info.length = length
        if kind == "sequence":
            if decoded.action == "branch":
                target = _prezen_mapped_target(address, decoded.target or 0)
                if target is None:
                    info.add_branch(BranchType.UnresolvedBranch)
                else:
                    info.add_branch(BranchType.UnconditionalBranch, target)
            elif decoded.action == "complete":
                info.add_branch(BranchType.FunctionReturn)
            return info
        if decoded.is_jcc:
            target = _prezen_mapped_target(address, decoded.braddr)
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
            return _prezen_sequence_tokens(decoded, address), length
        return _prezen_op_tokens(decoded, address), length

    def _lift_conditional(self, il, address: int, length: int, target: int) -> None:
        fallthrough = address + length
        true_label = il.get_label_for_address(self, target)
        false_label = il.get_label_for_address(self, fallthrough)
        new_true = true_label is None
        new_false = false_label is None
        if new_true:
            true_label = LowLevelILLabel()
        if new_false:
            false_label = LowLevelILLabel()
        il.append(il.if_expr(il.flag("ucond"), true_label, false_label))
        if new_true:
            il.mark_label(true_label)
            il.append(il.jump(il.const_pointer(self.address_size, target)))
        if new_false:
            il.mark_label(false_label)
            il.append(il.jump(il.const_pointer(self.address_size, fallthrough)))

    def get_instruction_low_level_il(self, data: bytes, address: int, il):
        decoded_tuple = self._decode(data, address)
        if decoded_tuple is None:
            return None
        kind, decoded, length = decoded_tuple
        try:
            if kind == "sequence":
                if decoded.action == "branch":
                    target = _prezen_mapped_target(address, decoded.target or 0)
                    if target is None:
                        il.append(il.unimplemented())
                        il.append(il.no_ret())
                    else:
                        il.append(il.jump(il.const_pointer(self.address_size, target)))
                elif decoded.action == "complete":
                    il.append(il.ret(il.reg(self.address_size, "ucode_ra")))
                elif decoded.action == "next":
                    il.append(il.nop())
                else:
                    il.append(il.unimplemented())
                return length
            if decoded.is_jcc:
                target = _prezen_mapped_target(address, decoded.braddr)
                if target is None:
                    # Conditional branch into ROM or beyond the patch: keep the fall-through only.
                    il.append(il.unimplemented())
                else:
                    self._lift_conditional(il, address, length, target)
                return length
            # Micro-op semantics are not modelled (the Ghidra specification has none either).
            il.append(il.unimplemented())
        except Exception as exc:  # pragma: no cover - depends on Binary Ninja build
            log_warn(f"Zenella: pre-Zen LLIL at 0x{address:x} failed: {exc}")
            il.append(il.unimplemented())
        return length


try:
    Architecture[PreZenUcodeArchitecture.name]
except Exception:
    PreZenUcodeArchitecture.register()


#####################################################################################################
# Structural types on the raw file
#####################################################################################################


def _ensure_prezen_types(bv) -> None:
    if bv.get_type_by_name(T_PREZEN_LOADER_ENUM) is None:
        enum_type = _make_enum_type(PREZEN_LOADER_ID_ENUM, 2)
        if enum_type is not None:
            bv.define_user_type(_qn(T_PREZEN_LOADER_ENUM), enum_type)
    loader_type = (
        _named_type(bv, T_PREZEN_LOADER_ENUM) if bv.get_type_by_name(T_PREZEN_LOADER_ENUM) else u16()
    )

    if bv.get_type_by_name(T_PREZEN_HEADER) is None:
        header = _new_structure_builder()
        header.packed = True
        header.append(u32(), "date")
        header.append(u32(), "patch_level")
        header.append(loader_type, "loader_id")
        header.append(u8(), "op_triad_count")
        header.append(u8(), "init_flag")
        header.append(u32(), "op_triad_checksum")
        header.append(u32(), "nb_dev_id")
        header.append(Type.array(u8(), 4), "unknown0")
        header.append(u16(), "cpuid")
        header.append(Type.array(u8(), 6), "unknown1")
        bv.define_user_type(_qn(T_PREZEN_HEADER), _type_structure(header))

    if bv.get_type_by_name(T_PREZEN_MATCH) is None:
        match = _new_structure_builder()
        match.packed = True
        match.append(u32(), "raw")
        bv.define_user_type(_qn(T_PREZEN_MATCH), _type_structure(match))

    if bv.get_type_by_name(T_PREZEN_TRIAD_RAW) is None:
        triad_raw = _new_structure_builder()
        triad_raw.packed = True
        triad_raw.append(Type.array(u32(), 7), "obfuscated_word")
        bv.define_user_type(_qn(T_PREZEN_TRIAD_RAW), _type_structure(triad_raw))

    if bv.get_type_by_name(T_PREZEN_TRIAD) is None:
        triad = _new_structure_builder()
        triad.packed = True
        triad.append(u64(), "op0")
        triad.append(u64(), "op1")
        triad.append(u64(), "op2")
        triad.append(u32(), "sequence_word")
        bv.define_user_type(_qn(T_PREZEN_TRIAD), _type_structure(triad))


def _prezen_header_comment(parsed: ParsedPreZenPatch) -> str:
    header = parsed.header
    lines = [
        f"AMD pre-Zen microcode patch: {header.microarch} (family 0x{header.family:02x}, "
        f"{header.family_name}); loader 0x{header.loader_id:04x} ({header.loader_name})",
    ]
    lines.extend(render_prezen_header_lines(header)[1:])
    if parsed.checksum_ok:
        lines.append(f"checksum OK (0x{parsed.computed_checksum:08x}); {parsed.triad_count} triads")
    elif not parsed.complete:
        lines.append(
            f"truncated patch: {parsed.triad_count}/{header.op_triad_count} triads available; "
            "checksum not verifiable"
        )
    else:
        lines.append(
            f"CHECKSUM MISMATCH: header 0x{header.op_triad_checksum:08x}, computed 0x{parsed.computed_checksum:08x}"
        )
    for warning in parsed.warnings:
        if "truncated" in warning or "checksum" in warning:
            continue
        lines.append(f"warning: {warning}")
    return "\n".join(lines)


def _triad_comment(triad) -> str:
    ops = " | ".join(op.text() for op in triad.ops)
    return f"{triad.label} (obfuscated): {ops} ; {triad.sequence.text}"


def _apply_prezen_layout(bv, base: int, parsed: ParsedPreZenPatch) -> bool:
    """Annotate the raw patch bytes: header, match registers and the obfuscated triad array."""
    _ensure_prezen_types(bv)
    header_type = bv.get_type_by_name(T_PREZEN_HEADER)
    match_type = bv.get_type_by_name(T_PREZEN_MATCH)
    triad_raw_type = bv.get_type_by_name(T_PREZEN_TRIAD_RAW)
    if not all((header_type, match_type, triad_raw_type)):
        log_error("Zenella: required pre-Zen types are missing after type creation")
        return False

    _define_data_var(bv, base, header_type, SYM_PREZEN_HEADER, _prezen_header_comment(parsed))
    family, model, stepping = parsed.header.cpuid_family_model_stepping
    _append_comment_at(
        bv,
        base + 0x18,
        f"cpuid equivalence id 0x{parsed.header.cpuid:04x}: family 0x{family:02x} model 0x{model:02x} "
        f"stepping {stepping}",
    )

    _define_data_var(
        bv,
        base + PREZEN_MATCH_OFFSET,
        Type.array(_named_type(bv, T_PREZEN_MATCH), PREZEN_MATCH_COUNT),
        SYM_PREZEN_MATCH,
        "Match registers: low 16 bits = ROM triad replaced by patch triad 0xC00 + 2*i; 0xFFFF = unused",
    )
    for register in parsed.match_registers:
        _append_comment_at(bv, base + PREZEN_MATCH_OFFSET + 4 * register.index, register.text)

    triad_count = parsed.triad_count
    if triad_count:
        comment = (
            f"{triad_count} obfuscated micro-op triads (28 bytes: 3 x u64 micro-op + u32 sequence word); "
            "decoded mirror in the executable section"
        )
        if not parsed.complete:
            comment += f" (partial: {triad_count}/{parsed.header.op_triad_count} triads)"
        _define_data_var(
            bv,
            base + PREZEN_TRIADS_OFFSET,
            Type.array(_named_type(bv, T_PREZEN_TRIAD_RAW), triad_count),
            SYM_PREZEN_TRIADS,
            comment,
        )
        for triad in parsed.triads:
            raw_address = base + PREZEN_TRIADS_OFFSET + triad.index * PREZEN_TRIAD_SIZE
            _append_comment_at(bv, raw_address, _triad_comment(triad))
            if triad.index:
                _add_symbol(bv, SymbolType.DataSymbol, raw_address, f"prezen_triad_raw_{triad.address:04x}", warn=False)
    return True


#####################################################################################################
# Executable mirror
#####################################################################################################


def _prezen_section_name(patch_base: int) -> str:
    return f".zenella_prezen_ucode_{patch_base:x}"


def _find_free_prezen_region(bv) -> int:
    """A free 128 KiB-aligned region able to hold the whole 0x1C000-byte microcode address space."""
    highest = int(getattr(bv, "end", 0))
    try:
        for segment in bv.segments:
            highest = max(highest, int(segment.end))
    except Exception:
        pass
    candidate = _align_up(highest + PREZEN_REGION_ALIGNMENT, PREZEN_REGION_ALIGNMENT)
    while True:
        collision = False
        try:
            for probe in (candidate, candidate + PREZEN_PATCH_RAM_BYTE_OFFSET, candidate + PREZEN_ADDRESS_SPACE_SIZE - 1):
                if bv.get_segment_at(probe) is not None:
                    collision = True
                    break
        except Exception:
            pass
        if not collision:
            return candidate
        candidate += PREZEN_REGION_ALIGNMENT


def _prezen_function_roots(parsed: ParsedPreZenPatch) -> Set[int]:
    """Triad indexes that start an analysis chain: entry, match-register handlers and branch targets."""
    count = parsed.triad_count
    roots: Set[int] = {0}
    for register in parsed.match_registers:
        index = register.handler_triad - PREZEN_PATCH_RAM_TRIAD
        if register.used and index < count:
            roots.add(index)
    for triad in parsed.triads:
        for op in triad.ops:
            if op.is_jcc and 0 <= op.braddr - PREZEN_PATCH_RAM_TRIAD < count:
                roots.add(op.braddr - PREZEN_PATCH_RAM_TRIAD)
        sequence = triad.sequence
        if sequence.action == "branch" and sequence.target is not None:
            if 0 <= sequence.target - PREZEN_PATCH_RAM_TRIAD < count:
                roots.add(sequence.target - PREZEN_PATCH_RAM_TRIAD)
        # Only sw_next has a guaranteed fall-through; keep later triads reachable
        if sequence.action != "next" and triad.index + 1 < count:
            roots.add(triad.index + 1)
    return roots


def _target_note(parsed: ParsedPreZenPatch, triad_address: int) -> str:
    if triad_address < PREZEN_PATCH_RAM_TRIAD:
        return f" -> ROM uc_{triad_address:04x} (not in patch)"
    if triad_address - PREZEN_PATCH_RAM_TRIAD >= parsed.triad_count:
        return f" -> uc_{triad_address:04x} beyond the mapped triads"
    return f" -> uc_{triad_address:04x}"


def _map_prezen_triads(bv, patch_base: int, parsed: ParsedPreZenPatch) -> Optional[int]:
    """Mirror the triad array into an executable segment at region + 0x15000 and seed functions."""
    size = parsed.mapped_size
    if size <= 0:
        log_error("Zenella: no complete pre-Zen triad to map")
        return None
    name = _prezen_section_name(patch_base)
    section = None
    try:
        section = bv.get_section_by_name(name)
    except Exception:
        pass
    if section is not None:
        synthetic_base = int(section.start)
    else:
        region = _find_free_prezen_region(bv)
        synthetic_base = region + PREZEN_PATCH_RAM_BYTE_OFFSET
        data_offset = _source_data_offset(bv, patch_base + PREZEN_TRIADS_OFFSET)
        if data_offset is None:
            log_error(
                "Zenella: BinaryView cannot translate the triad address to a backing-file offset; "
                "open the raw patch or apply the command in the Raw view"
            )
            return None
        try:
            bv.add_user_segment(
                synthetic_base,
                size,
                data_offset,
                size,
                SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable,
            )
            bv.add_user_section(name, synthetic_base, size, SectionSemantics.ReadOnlyCodeSectionSemantics)
        except Exception as exc:
            log_error(f"Zenella: could not map the pre-Zen triads: {exc}")
            return None

    region = synthetic_base & PREZEN_REGION_MASK
    architecture = Architecture[PreZenUcodeArchitecture.name]
    _register_prezen_mapping(architecture.name, region, parsed.triad_count)

    roots = _prezen_function_roots(parsed)
    for triad in parsed.triads:
        address = synthetic_base + triad.index * PREZEN_TRIAD_SIZE
        symbol_type = SymbolType.FunctionSymbol if triad.index in roots else CODE_LABEL_SYMBOL
        _add_symbol(bv, symbol_type, address, triad.label)
        for slot, op in enumerate(triad.ops):
            note = _target_note(parsed, op.braddr) if op.is_jcc else ""
            _append_comment_at(
                bv,
                address + slot * PREZEN_OP_SIZE,
                f"{op.text()}{note} [op=0x{op.operation:03x} class={op.op_class} seg={op.seg} "
                f"3op={op.three_op} swap={op.swap} pzs={op.pzs} cflag={op.cflag} zx={op.sizezx} "
                f"raw=0x{op.word:016x}]",
            )
        sequence = triad.sequence
        note = _target_note(parsed, sequence.target) if sequence.target is not None else ""
        _append_comment_at(
            bv,
            address + PREZEN_SEQ_OFFSET,
            f"{sequence.text}{note} [raw=0x{sequence.word:08x}]",
        )

    created = 0
    for index in sorted(roots):
        if _create_user_function_compat(bv, synthetic_base + index * PREZEN_TRIAD_SIZE, architecture.standalone_platform):
            created += 1
    for register in parsed.match_registers:
        if register.used:
            handler_index = register.handler_triad - PREZEN_PATCH_RAM_TRIAD
            if handler_index < parsed.triad_count:
                _append_comment_at(
                    bv,
                    patch_base + PREZEN_MATCH_OFFSET + 4 * register.index,
                    f"handler uc_{register.handler_triad:04x} @ 0x{synthetic_base + handler_index * PREZEN_TRIAD_SIZE:x}",
                )

    _append_comment_at(
        bv,
        patch_base + PREZEN_TRIADS_OFFSET,
        f"pre-Zen executable mirror: section {name} at 0x{synthetic_base:x}; architecture {architecture.name}; "
        f"{created}/{len(roots)} triad functions",
    )
    _append_comment_at(
        bv,
        synthetic_base,
        f"Mapped from obfuscated triads at 0x{patch_base + PREZEN_TRIADS_OFFSET:x}; patch RAM uc_0c00-"
        f"uc_{PREZEN_PATCH_RAM_TRIAD + parsed.triad_count - 1:04x} (byte address = triad * 28, region 0x{region:x})",
    )
    _update_analysis_compat(bv, wait=True)
    log_info(
        f"Zenella: mapped {parsed.triad_count} pre-Zen {parsed.header.microarch} triads from "
        f"0x{patch_base + PREZEN_TRIADS_OFFSET:x} to executable 0x{synthetic_base:x}; "
        f"architecture={architecture.name}; functions={created}/{len(roots)}"
    )
    return synthetic_base


#####################################################################################################
# Drivers and reports
#####################################################################################################


def _read_prezen_blob(bv, base: int) -> bytes:
    try:
        return bv.read(base, PREZEN_MAX_PATCH_SIZE)
    except Exception:
        return b""


def _parse_prezen_at(bv, base: int) -> Optional[ParsedPreZenPatch]:
    blob = _read_prezen_blob(bv, base)
    detection = detect_prezen(blob)
    if not detection.matched:
        message = f"not a pre-Zen K8/K10 patch at 0x{base:x}: {detection.reason}"
        log_error(f"Zenella: {message}")
        _show_apply_error(message)
        return None
    try:
        return parse_prezen_patch(blob)
    except ValueError as exc:
        log_error(f"Zenella: pre-Zen parse failed at 0x{base:x}: {exc}")
        _show_apply_error(str(exc))
        return None


def _apply_prezen(bv, base: int, map_code: bool = True) -> Optional[int]:
    """Apply the pre-Zen layout at ``base``; returns the synthetic code address or ``None``."""
    try:
        _zen_module._check_loaded_plugin_copies()
    except Exception as exc:
        log_error(f"Zenella: {exc}")
        _show_apply_error(str(exc))
        return None
    parsed = _parse_prezen_at(bv, base)
    if parsed is None:
        return None
    header = parsed.header
    log_info(
        f"Zenella: pre-Zen {header.microarch} patch (family 0x{header.family:02x}, loader 0x{header.loader_id:04x}, "
        f"{header.op_triad_count} triads, level 0x{header.patch_level:08x}) at 0x{base:x}"
    )
    for warning in parsed.warnings:
        log_warn(f"Zenella: pre-Zen: {warning}")
    if not parsed.complete:
        _show_notice(
            "partial pre-Zen patch",
            f"Only {parsed.triad_count} of {header.op_triad_count} triads are available at 0x{base:x}; "
            "the layout covers the complete triads only.",
        )
    elif not parsed.checksum_ok:
        _show_notice(
            "pre-Zen checksum mismatch",
            f"Header checksum 0x{header.op_triad_checksum:08x} differs from the computed "
            f"0x{parsed.computed_checksum:08x}; the layout is applied anyway.",
        )
    if not _apply_prezen_layout(bv, base, parsed):
        return None
    if not map_code:
        return None
    return _map_prezen_triads(bv, base, parsed)


def _show_prezen_report(bv, base: int) -> None:
    parsed = _parse_prezen_at(bv, base)
    if parsed is None:
        return
    try:
        text = "\n".join(render_prezen_listing(parsed))
        show_plain_text_report(
            f"Zenella Pre-Zen {parsed.header.microarch} triad listing @ 0x{base:x}", text
        )
    except Exception as exc:
        log_error(f"Zenella: pre-Zen listing failed: {exc}")


#####################################################################################################
# Plugin command callbacks and registration
#####################################################################################################


def cmd_prezen_start(bv):
    return _apply_prezen(bv, 0)


def cmd_prezen_cursor(bv, address):
    return _apply_prezen(bv, address)


def cmd_prezen_report_start(bv):
    return _show_prezen_report(bv, 0)


def cmd_prezen_report_cursor(bv, address):
    return _show_prezen_report(bv, address)


_PREZEN_COMMANDS_REGISTERED = False


def _register_prezen_commands() -> None:
    global _PREZEN_COMMANDS_REGISTERED
    if _PREZEN_COMMANDS_REGISTERED:
        return
    PluginCommand.register(
        PREZEN_MENU + r"\Apply layout + disassembly at file start",
        "K8/K10 (families 0x0F-0x12): annotate header, match registers and obfuscated triads, "
        "then mirror the de-obfuscated triads into an executable section with the amd_prezen_ucode architecture",
        cmd_prezen_start,
    )
    PluginCommand.register_for_address(
        PREZEN_MENU + r"\Apply layout + disassembly at cursor",
        "Apply the pre-Zen K8/K10 layout and disassembly to a patch beginning at the cursor",
        cmd_prezen_cursor,
    )
    PluginCommand.register(
        PREZEN_MENU + r"\Show decoded triad listing at file start",
        "Print the de-obfuscated K8/K10 triads (Ghidra AMDuCode text) for the patch at the file start",
        cmd_prezen_report_start,
    )
    PluginCommand.register_for_address(
        PREZEN_MENU + r"\Show decoded triad listing at cursor",
        "Print the de-obfuscated K8/K10 triads for a patch beginning at the cursor",
        cmd_prezen_report_cursor,
    )
    _PREZEN_COMMANDS_REGISTERED = True


_register_prezen_commands()
log_info(
    f"Zenella {PLUGIN_VERSION}: pre-Zen (K8/K10) menu group '{PREZEN_MENU}' registered; "
    f"architecture {PreZenUcodeArchitecture.name}"
)
