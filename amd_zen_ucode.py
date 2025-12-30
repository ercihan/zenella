
#####################################################################################################
#####################################################################################################
#####################################################################################################
# Author: Kaya Ercihan
# Version: 1.0
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
# Layout constants (0x3820 blobs)
#############################
PATCH_SIZE = 0x3820

HDR_OFF      = 0x0000
HDR_SIZE     = 0x0020

RANDOM_OFF   = 0x0020
RANDOM_SIZE  = 0x0300

UCREG_OFF    = 0x0320
UCREG_SIZE   = 0x3500

BODY_SIZE    = 0x3800
UOP_SIZE     = 4
UOP_COUNT    = UCREG_SIZE // UOP_SIZE # 0xD40

#############################
# Names to define
#############################
T_HDR   = "AMD_MC_Header"
T_RAND  = "AMD_MC_RandomBlocks"
T_PATCH = "AMD_MC_Patch"

T_ENUM  = "AMD_Zen_Opcode"
T_UOP   = "AMD_Zen_MicroOp"
T_REG   = "AMD_Zen_MicrocodeRegion"

#############################
# Enum values (and complements to avoid "~NAME" rendering)
#############################
ZEN_OPCODE_ENUM = {
    "AMD_ZEN_UOP_UNKNOWN":    0x00,
    "AMD_ZEN_TYPE5_READ":     0xDE,
    "AMD_ZEN_TYPE7_ALU_OR":   0xBE,
    "AMD_ZEN_TYPE3_WRITE":    0xA0,
    "AMD_ZEN_TYPE_REG_NOP":   0xFF,

    "AMD_ZEN_UOP_21":         0x21, # ~0xDE & 0xFF
    "AMD_ZEN_UOP_41":         0x41, # ~0xBE & 0xFF
    "AMD_ZEN_UOP_5F":         0x5F, # ~0xA0 & 0xFF
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
    Most common older forms:
        Type.int(width, False)
        Type.int(width, signedBool)
    Some builds: Type.int(width) defaults signed -> we'll fallback.
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
        # last resort: no signed control
        return Type.int(width)
    except Exception as e:
        raise RuntimeError(f"Cannot construct Type.int({width}): {e}")

def u8():  return _uint(1)
def u16(): return _uint(2)
def u32(): return _uint(4)

def _type_structure(sb):
    # BN builds differ between Type.structure and Type.structure_type
    if hasattr(Type, "structure"):
        try:
            return Type.structure(sb)
        except Exception:
            pass
    if hasattr(Type, "structure_type"):
        return Type.structure_type(sb)
    raise RuntimeError("No Type.structure / Type.structure_type available on this BN build")

#############################
# Enum construction (feel free to extend)
#############################
def _make_enum_type_best_effort():
    """
    Try to create a uint8 enum Type for AMD_Zen_Opcode across BN API variants.
    If it cannot be created, return None (caller will fall back to opcode=u8).
    """
    # builder constructor varies: some builds require create()
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

    # set width if available
    try:
        eb.width = 1
    except Exception:
        pass
    # signed flag may not exist
    if hasattr(eb, "signed"):
        try:
            eb.signed = False
        except Exception:
            pass

    for k, v in ZEN_OPCODE_ENUM.items():
        try:
            eb.append(k, v)
        except Exception:
            # if append fails, enum API is unusable here
            return None

    # Convert builder -> Type
    # Known variants seen in the wild:
    #   Type.enumeration(builder)
    #   Type.enumeration_type(width, builder)
    #   Type.enumeration_type(builder, width)
    if hasattr(Type, "enumeration"):
        try:
            return Type.enumeration(eb)
        except Exception:
            pass

    if hasattr(Type, "enumeration_type"):
        try:
            return Type.enumeration_type(1, eb)
        except Exception:
            pass
        try:
            return Type.enumeration_type(eb, 1)
        except Exception:
            pass
        try:
            return Type.enumeration_type(eb)
        except Exception:
            pass

    return None

#############################
# BinaryView var helpers
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
            log_warn(f"Only {got} bytes available from 0x{base:x}, expected 0x{PATCH_SIZE:x}. Layout may be partial.")
    except Exception:
        pass

#############################
# Define ALL types
#############################
def _ensure_types(bv):
    # Already defined?
    if bv.get_type_by_name(T_PATCH) is not None:
        return

    # Enum: AMD_Zen_Opcode
    enum_t = _make_enum_type_best_effort()
    if enum_t is not None:
        bv.define_user_type(_qn(T_ENUM), enum_t)
        opcode_field_t = Type.named_type_from_type(_qn(T_ENUM), enum_t)
        log_info("AMD_Zen_Opcode enum created (u8).")
    else:
        # Fallback: opcode is plain u8
        opcode_field_t = u8()
        log_warn("Could not create AMD_Zen_Opcode enum on this BN build; opcode will be uint8.")

    # AMD_Zen_MicroOp (packed 4 bytes)
    sb_uop = StructureBuilder.create()
    sb_uop.packed = True
    sb_uop.append(opcode_field_t, "opcode") # enum(u8) or u8 fallback
    sb_uop.append(u8(), "b1")
    sb_uop.append(u16(), "imm16")
    uop_t = _type_structure(sb_uop)
    bv.define_user_type(_qn(T_UOP), uop_t)

    uop_named = Type.named_type_from_type(_qn(T_UOP), uop_t)

    # AMD_Zen_MicrocodeRegion (0x3500 bytes)
    sb_reg = StructureBuilder.create()
    sb_reg.packed = True
    sb_reg.append(Type.array(uop_named, UOP_COUNT), "uops")
    reg_t = _type_structure(sb_reg)
    bv.define_user_type(_qn(T_REG), reg_t)

    # AMD_MC_Header (packed 0x20 bytes)
    sb_hdr = StructureBuilder.create()
    sb_hdr.packed = True
    sb_hdr.append(u16(), "Year")                 # 0x00
    sb_hdr.append(u8(),  "Day")                  # 0x02
    sb_hdr.append(u8(),  "Month")                # 0x03
    sb_hdr.append(u32(), "UpdateRevision")       # 0x04
    sb_hdr.append(u16(), "LoaderID")             # 0x08
    sb_hdr.append(u8(),  "DataSize")             # 0x0A
    sb_hdr.append(u8(),  "InitializationFlag")   # 0x0B
    sb_hdr.append(u32(), "DataChecksum")         # 0x0C
    sb_hdr.append(u16(), "NorthBridgeVEN_ID")    # 0x10
    sb_hdr.append(u16(), "NorthBridgeDEV_ID")    # 0x12
    sb_hdr.append(u16(), "SouthBridgeVEN_ID")    # 0x14
    sb_hdr.append(u16(), "SouthBridgeDEV_ID")    # 0x16
    sb_hdr.append(u16(), "ProcessorSignature")   # 0x18
    sb_hdr.append(u8(),  "NorthBridgeREV_ID")    # 0x1A
    sb_hdr.append(u8(),  "SouthBridgeREV_ID")    # 0x1B
    sb_hdr.append(u8(),  "BiosApiRevision")      # 0x1C
    sb_hdr.append(u8(),  "LoadControl")          # 0x1D
    sb_hdr.append(u8(),  "Reserved_1E")          # 0x1E
    sb_hdr.append(u8(),  "Reserved_1F")          # 0x1F
    hdr_t = _type_structure(sb_hdr)
    bv.define_user_type(_qn(T_HDR), hdr_t)
    hdr_named = Type.named_type_from_type(_qn(T_HDR), hdr_t)

    # AMD_MC_RandomBlocks (packed 0x300)
    sb_rand = StructureBuilder.create()
    sb_rand.packed = True
    sb_rand.append(Type.array(u8(), 0x100), "block1")
    sb_rand.append(Type.array(u8(), 0x100), "block2")
    sb_rand.append(Type.array(u8(), 0x100), "block3")
    rand_t = _type_structure(sb_rand)
    bv.define_user_type(_qn(T_RAND), rand_t)
    rand_named = Type.named_type_from_type(_qn(T_RAND), rand_t)

    # AMD_MC_Patch (0x3820)
    sb_patch = StructureBuilder.create()
    sb_patch.packed = True
    sb_patch.append(hdr_named, "hdr")
    sb_patch.append(Type.array(u8(), 0x3800), "body")
    patch_t = _type_structure(sb_patch)
    bv.define_user_type(_qn(T_PATCH), patch_t)

    log_info("AMD microcode structs defined in this database.")

#############################
# Apply layout
#############################
def apply_layout_at(bv, base: int):
    _ensure_types(bv)
    _check_size(bv, base)

    patch_t = bv.get_type_by_name(T_PATCH)
    hdr_t   = bv.get_type_by_name(T_HDR)
    rand_t  = bv.get_type_by_name(T_RAND)
    reg_t   = bv.get_type_by_name(T_REG)

    if not all([patch_t, hdr_t, rand_t, reg_t]):
        log_error("Types missing after definition; type creation failed on this build.")
        return

    _define_var(bv, base + 0x0, patch_t, "amd_mc_patch", "AMD microcode patch container")
    _define_var(bv, base + HDR_OFF, hdr_t, "amd_mc_header")
    _define_var(bv, base + RANDOM_OFF, rand_t, "amd_mc_random_blocks")

    # microcode region (auto-size if partial)
    file_end = bv.end
    reg_base = base + UCREG_OFF
    if reg_base >= file_end:
        log_warn("No bytes available for ucode region at this base.")
        return

    available = file_end - reg_base
    ucode_size = min(available, UCREG_SIZE)
    ucode_size -= (ucode_size % UOP_SIZE)
    uops_count = ucode_size // UOP_SIZE

    if ucode_size == UCREG_SIZE:
        _define_var(bv, reg_base, reg_t, "amd_ucode_region")
    else:
        # auto region type sized to what exists (no global type churn)
        type_str = f"struct AMD_Zen_MicrocodeRegion_auto {{ {T_UOP} uops[{uops_count}]; }};"
        auto_t, _ = bv.parse_type_string(type_str)
        _define_var(bv, reg_base, auto_t, "amd_ucode_region")

    # UI-thread safe
    try:
        bv.update_analysis()
    except Exception:
        pass

    log_info(f"Applied AMD microcode layout at 0x{base:x} (uops={uops_count:#x}).")

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
    "Define AMD microcode structs (+ enum best-effort) in this database",
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