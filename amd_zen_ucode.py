#####################################################################################################
#####################################################################################################
#####################################################################################################
# Author: Kaya Ercihan
# Version: 1.2
# Description: Define and apply AMD Zen microcode layout in Binary Ninja.
# Self-containment: define types + apply AMD microcode layout (works across older BN Python API variants)
# License: GPL
#####################################################################################################
#####################################################################################################
#####################################################################################################

from binaryninja import (
    PluginCommand, log_info, log_warn, log_error,
    Type, StructureBuilder, EnumerationBuilder, QualifiedName,
    Symbol, SymbolType
)

#############################
# Layout constants
#############################
PATCH_SIZE = 0x3820

HDR_OFF         = 0x0000
HDR_SIZE        = 0x0020

SIGNATURE_OFF   = 0x0020
SIGNATURE_SIZE  = 0x0100

MODULUS_OFF     = 0x0120
MODULUS_SIZE    = 0x0100

CHECK_OFF       = 0x0220
CHECK_SIZE      = 0x0100

OPTIONS_OFF     = 0x0320
OPTIONS_SIZE    = 0x0004

REV_OFF         = 0x0324
REV_SIZE        = 0x0004

MATCH_OFF       = 0x0328
MATCH_SIZE      = 0x0028

MASK_OFF        = 0x0350
MASK_SIZE       = 0x0030

MICROCODE_OFF   = 0x0380
MICROCODE_SIZE  = PATCH_SIZE - MICROCODE_OFF

UOP_SIZE        = 4
UOP_COUNT       = MICROCODE_SIZE // UOP_SIZE

#############################
# Names to define
#############################
T_LOADER_ENUM   = "AMD_MC_LoaderIdTag"
T_OPCODE_ENUM   = "AMD_Zen_Opcode"

T_CPUID         = "AMD_MC_CpuId"
T_HDR           = "AMD_MC_Header"
T_OPTS          = "AMD_MC_UcodeOptions"
T_MATCH         = "AMD_MC_MatchRegisterBlock"
T_MASK          = "AMD_MC_MaskRegisterBlock"

T_UOP           = "AMD_Zen_MicroOp"
T_MICROCODE     = "AMD_Zen_MicrocodeRegion"
T_PATCH         = "AMD_MC_Patch"

#############################
# Enum values
#############################
LOADER_ID_ENUM = {
    "AMD_MC_LOADER_8004": 0x8004,
    "AMD_MC_LOADER_8005": 0x8005,
    "AMD_MC_LOADER_8010": 0x8010,
    "AMD_MC_LOADER_8015": 0x8015,
    "AMD_MC_LOADER_8016": 0x8016,
}

# Important: the byte alone is not a full micro-op decode. Several meanings are
# opclass-dependent, e.g. 0x00 is OP_LD/OP_ST, 0xA0 is OP_MOV/OP_SREG, and
# 0xFF is OP_NOP only for OPCLASS_SPEC.
ZEN_OPCODE_ENUM = {
    # Class-dependent / non-RegOp opcodes
    "AMD_ZEN_UOP_LD_ST_00":        0x00,
    "AMD_ZEN_BR_JMP":              0x05,

    # RegOp / RegX opcodes
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
    "AMD_ZEN_REG_SRC_CF_CANDIDATE": 0x47, # Research-ToDo: CF-candidate / target-like imm -> not confirmed as branch opcode yet

    # SpecOp opcode
    "AMD_ZEN_SPEC_NOP":             0xFF,

    "AMD_ZEN_TYPE5_READ":           0xDE,
}

#############################
# Helpers for old Type.int() signatures
#############################
def _qn(s: str) -> QualifiedName:
    return QualifiedName(s)

def _uint(width: int):
    """
    Create an unsigned integer type of size "width" bytes across BN API variants.
    Tries several positional signatures.
    """
    try:
        return Type.int(width, False)
    except TypeError:
        pass
    try:
        return Type.int(width, 0)
    except TypeError:
        pass
    try:
        return Type.int(width)
    except Exception as e:
        raise RuntimeError(f"Cannot construct Type.int({width}): {e}")

def u8():
    return _uint(1)

def u16():
    return _uint(2)

def u32():
    return _uint(4)

def _type_structure(sb):
    if hasattr(Type, "structure"):
        try:
            return Type.structure(sb)
        except Exception:
            pass
    if hasattr(Type, "structure_type"):
        return Type.structure_type(sb)
    raise RuntimeError("No Type.structure / Type.structure_type available on this BN build")

def _make_enum_type_best_effort(values: dict, width: int = 1):
    """
    Try to create an enum Type across BN API variants.
    If it cannot be created, return None (caller will fall back to plain uint).
    """
    eb = None
    try:
        eb = EnumerationBuilder.create()
    except Exception:
        try:
            eb = EnumerationBuilder()
        except Exception:
            eb = None

    if eb is None:
        return None

    try:
        eb.width = width
    except Exception:
        pass

    if hasattr(eb, "signed"):
        try:
            eb.signed = False
        except Exception:
            pass

    for k, v in values.items():
        try:
            eb.append(k, v)
        except Exception:
            return None

    if hasattr(Type, "enumeration"):
        try:
            return Type.enumeration(eb)
        except Exception:
            pass

    if hasattr(Type, "enumeration_type"):
        try:
            return Type.enumeration_type(width, eb)
        except Exception:
            pass
        try:
            return Type.enumeration_type(eb, width)
        except Exception:
            pass
        try:
            return Type.enumeration_type(eb)
        except Exception:
            pass

    return None

#############################
# BinaryView helpers
#############################
def _safe_undef_var(bv, addr: int):
    try:
        bv.undefine_user_data_var(addr)
    except Exception:
        pass

def _define_var(bv, addr: int, t, sym=None, comment=None):
    _safe_undef_var(bv, addr)
    bv.define_user_data_var(addr, t)
    if sym:
        bv.define_user_symbol(Symbol(SymbolType.DataSymbol, addr, sym))
    if comment:
        bv.set_comment_at(addr, comment)

def _check_size(bv, base: int):
    try:
        got = len(bv.read(base, PATCH_SIZE))
        if got < PATCH_SIZE:
            log_warn(
                f"Only {got} bytes available from 0x{base:x}, expected 0x{PATCH_SIZE:x}. "
                "Layout may be partial."
            )
    except Exception:
        pass

def _named_or_plain(bv, type_name: str, fallback):
    try:
        t = bv.get_type_by_name(type_name)
        if t is not None:
            return Type.named_type_from_type(_qn(type_name), t)
    except Exception:
        pass
    return fallback

#############################
# Define ALL types
#############################
def _ensure_types(bv):
    if bv.get_type_by_name(T_PATCH) is not None:
        return

    # LoaderId enum (u16) best effort
    loader_enum_t = _make_enum_type_best_effort(LOADER_ID_ENUM, width=2)
    if loader_enum_t is not None:
        bv.define_user_type(_qn(T_LOADER_ENUM), loader_enum_t)
        loader_field_t = Type.named_type_from_type(_qn(T_LOADER_ENUM), loader_enum_t)
        log_info("AMD_MC_LoaderIdTag enum created (u16).")
    else:
        loader_field_t = u16()
        log_warn("Could not create AMD_MC_LoaderIdTag enum; loader_id will be uint16.")

    # Zen opcode enum (u8) best effort
    opcode_enum_t = _make_enum_type_best_effort(ZEN_OPCODE_ENUM, width=1)
    if opcode_enum_t is not None:
        bv.define_user_type(_qn(T_OPCODE_ENUM), opcode_enum_t)
        opcode_field_t = Type.named_type_from_type(_qn(T_OPCODE_ENUM), opcode_enum_t)
        log_info("AMD_Zen_Opcode enum created (u8).")
    else:
        opcode_field_t = u8()
        log_warn("Could not create AMD_Zen_Opcode enum; opcode will be uint8.")

    # CpuId { u32 proc_sig; }
    sb_cpuid = StructureBuilder.create()
    sb_cpuid.packed = True
    sb_cpuid.append(u32(), "proc_sig")
    cpuid_t = _type_structure(sb_cpuid)
    bv.define_user_type(_qn(T_CPUID), cpuid_t)
    cpuid_named = Type.named_type_from_type(_qn(T_CPUID), cpuid_t)

    # Header (0x20)
    sb_hdr = StructureBuilder.create()
    sb_hdr.packed = True
    sb_hdr.append(u16(),           "year")              # 0x000
    sb_hdr.append(u8(),            "day")               # 0x002
    sb_hdr.append(u8(),            "month")             # 0x003
    sb_hdr.append(u32(),           "update_revision")   # 0x004
    sb_hdr.append(loader_field_t,  "loader_id")         # 0x008
    sb_hdr.append(u8(),            "data_size")         # 0x00A
    sb_hdr.append(u8(),            "init_flag")         # 0x00B
    sb_hdr.append(u32(),           "data_checksum")     # 0x00C
    sb_hdr.append(u16(),           "nb_ven")            # 0x010
    sb_hdr.append(u16(),           "nb_dev")            # 0x012
    sb_hdr.append(u16(),           "sb_ven")            # 0x014
    sb_hdr.append(u16(),           "sb_dev")            # 0x016
    sb_hdr.append(cpuid_named,     "proc_sig")          # 0x018
    sb_hdr.append(u8(),            "bios_revision")     # 0x01C
    sb_hdr.append(u8(),            "flags")             # 0x01D
    sb_hdr.append(u8(),            "reserved")          # 0x01E
    sb_hdr.append(u8(),            "reserved2")         # 0x01F
    hdr_t = _type_structure(sb_hdr)
    bv.define_user_type(_qn(T_HDR), hdr_t)
    hdr_named = Type.named_type_from_type(_qn(T_HDR), hdr_t)

    # UcodeOptions { u8 autorun; u8 encrypted; u16 loaderid; }
    sb_opts = StructureBuilder.create()
    sb_opts.packed = True
    sb_opts.append(u8(), "autorun")
    sb_opts.append(u8(), "encrypted")
    sb_opts.append(u16(), "loaderid")
    opts_t = _type_structure(sb_opts)
    bv.define_user_type(_qn(T_OPTS), opts_t)
    opts_named = Type.named_type_from_type(_qn(T_OPTS), opts_t)

    # MatchRegisterBlock { u32 match_reg[10]; }
    sb_match = StructureBuilder.create()
    sb_match.packed = True
    sb_match.append(Type.array(u32(), 10), "match_reg")
    match_t = _type_structure(sb_match)
    bv.define_user_type(_qn(T_MATCH), match_t)
    match_named = Type.named_type_from_type(_qn(T_MATCH), match_t)

    # MaskRegisterBlock { u32 mask_reg[12]; }
    sb_mask = StructureBuilder.create()
    sb_mask.packed = True
    sb_mask.append(Type.array(u32(), 12), "mask_reg")
    mask_t = _type_structure(sb_mask)
    bv.define_user_type(_qn(T_MASK), mask_t)
    mask_named = Type.named_type_from_type(_qn(T_MASK), mask_t)

    # AMD_Zen_MicroOp (packed 4 bytes)
    sb_uop = StructureBuilder.create()
    sb_uop.packed = True
    sb_uop.append(opcode_field_t, "opcode")
    sb_uop.append(u8(), "b1")
    sb_uop.append(u16(), "imm16")
    uop_t = _type_structure(sb_uop)
    bv.define_user_type(_qn(T_UOP), uop_t)
    uop_named = Type.named_type_from_type(_qn(T_UOP), uop_t)

    # AMD_Zen_MicrocodeRegion
    sb_microcode = StructureBuilder.create()
    sb_microcode.packed = True
    sb_microcode.append(Type.array(uop_named, UOP_COUNT), "uops")
    microcode_t = _type_structure(sb_microcode)
    bv.define_user_type(_qn(T_MICROCODE), microcode_t)
    microcode_named = Type.named_type_from_type(_qn(T_MICROCODE), microcode_t)

    # AMD_MC_Patch
    sb_patch = StructureBuilder.create()
    sb_patch.packed = True
    sb_patch.append(hdr_named, "header")
    sb_patch.append(Type.array(u8(), SIGNATURE_SIZE), "signature")
    sb_patch.append(Type.array(u8(), MODULUS_SIZE), "modulus")
    sb_patch.append(Type.array(u8(), CHECK_SIZE), "check")
    sb_patch.append(opts_named, "options")
    sb_patch.append(u32(), "rev")
    sb_patch.append(match_named, "match_regs")
    sb_patch.append(mask_named, "mask_regs")
    sb_patch.append(microcode_named, "microcode")
    patch_t = _type_structure(sb_patch)
    bv.define_user_type(_qn(T_PATCH), patch_t)

    log_info("AMD microcode structs defined in this database.")

#############################
# Apply layout
#############################
def apply_layout_at(bv, base: int):
    _ensure_types(bv)
    _check_size(bv, base)

    patch_t     = bv.get_type_by_name(T_PATCH)
    hdr_t       = bv.get_type_by_name(T_HDR)
    opts_t      = bv.get_type_by_name(T_OPTS)
    match_t     = bv.get_type_by_name(T_MATCH)
    mask_t      = bv.get_type_by_name(T_MASK)
    microcode_t = bv.get_type_by_name(T_MICROCODE)

    if not all([patch_t, hdr_t, opts_t, match_t, mask_t, microcode_t]):
        log_error("Types missing after definition; type creation failed on this build.")
        return

    _define_var(
        bv, base + 0x0, patch_t,
        "amd_mc_patch",
        "AMD microcode patch container (header/signature/modulus/check/options/rev/match/mask/microcode)"
    )

    _define_var(bv, base + HDR_OFF, hdr_t, "amd_mc_header", "AMD microcode patch header")
    _define_var(
        bv, base + SIGNATURE_OFF, Type.array(u8(), SIGNATURE_SIZE),
        "amd_mc_signature", "0x100-byte signature block"
    )
    _define_var(
        bv, base + MODULUS_OFF, Type.array(u8(), MODULUS_SIZE),
        "amd_mc_modulus", "0x100-byte modulus block"
    )
    _define_var(
        bv, base + CHECK_OFF, Type.array(u8(), CHECK_SIZE),
        "amd_mc_check", "0x100-byte check block"
    )
    _define_var(
        bv, base + OPTIONS_OFF, opts_t,
        "amd_mc_options", "autorun/encrypted/loaderid option bytes"
    )
    _define_var(
        bv, base + REV_OFF, u32(),
        "amd_mc_rev", "Revision copy from the extended header area"
    )
    _define_var(
        bv, base + MATCH_OFF, match_t,
        "amd_mc_match_regs", "Match register block"
    )
    _define_var(
        bv, base + MASK_OFF, mask_t,
        "amd_mc_mask_regs", "Mask register block"
    )

    # Microcode region (auto-size if partial)
    file_end = bv.end
    microcode_base = base + MICROCODE_OFF
    if microcode_base >= file_end:
        log_warn("No bytes available for microcode region at this base.")
        return

    available = file_end - microcode_base
    microcode_size = min(available, MICROCODE_SIZE)
    microcode_size -= (microcode_size % UOP_SIZE)
    uops_count = microcode_size // UOP_SIZE

    if microcode_size == MICROCODE_SIZE:
        _define_var(
            bv, microcode_base, microcode_t,
            "amd_ucode_region", "Decoded microcode uop region"
        )
    else:
        type_str = f"struct AMD_Zen_MicrocodeRegion_auto {{ {T_UOP} uops[{uops_count}]; }};"
        auto_t, _ = bv.parse_type_string(type_str)
        _define_var(
            bv, microcode_base, auto_t,
            "amd_ucode_region", "Decoded microcode uop region (auto-sized)"
        )

    try:
        bv.update_analysis()
    except Exception:
        pass

    log_info(
        f"Applied AMD microcode layout at 0x{base:x} "
        f"(microcode_off=0x{MICROCODE_OFF:x}, uops={uops_count:#x})."
    )

#############################
# Commands
#############################
def cmd_define_types(bv):
    _ensure_types(bv)

def cmd_apply_at_zero(bv):
    apply_layout_at(bv, 0)

def cmd_apply_at_cursor(bv, addr):
    apply_layout_at(bv, addr)

PluginCommand.register(
    "AMD Microcode\\Define types (self-contained)",
    "Define AMD microcode structs (+ enums best-effort) in this database",
    cmd_define_types
)

PluginCommand.register(
    "AMD Microcode\\Apply layout at file start (0x0)",
    "Define types (if needed) and apply AMD microcode layout at 0",
    cmd_apply_at_zero
)

PluginCommand.register_for_address(
    "AMD Microcode\\Apply layout at cursor",
    "Define types (if needed) and apply AMD microcode layout at cursor address",
    cmd_apply_at_cursor
)
