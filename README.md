<p align="center">
  <img alt="zenella" src="media/zenellaLogo.png" width="160">
</p>

# AMD Zen Microcode Update Reversing (call it `Zenella`) (Binary Ninja Plugin)

**Version 2.2.0** · Binary Ninja, Python 3 · Targets K8, K10, Zen 1, Zen 2, Zen 5 · GPL-3.0

Zenella is a Binary Ninja plugin for AMD Zen microcode update `.bin` blobs. Open an update, run one command, and the container is typed and labelled: header, RSA material, options, match registers and the microcode body. The plugin reads the header, picks the matching profile and applies it to the bytes in front of you. Pre-Zen K8 and K10 patches (families 0x0F–0x12) are covered too: their obfuscated 28-byte triads are decoded and disassembled.

- **K8 / K10** (families 0x0F–0x12, loader `0x8000` / `0x8003`): a 0x20-byte header, 8 match registers at `0x20` and the triads from `0x40`. Each triad is three 64-bit micro-ops plus a 32-bit sequence word, stored obfuscated (per-word rotate, invert, pair swap). The plugin annotates the stored bytes and mirrors the de-obfuscated triads into an executable section under the `amd_prezen_ucode` architecture, labelled `uc_0c00 …` (patch RAM starts at triad `0xC00`), with a function at every match-register handler (`0xC00 + 2N`). The disassembly text is identical to Ghidra's AMDuCode K8/K10 SLEIGH languages, verified instruction for instruction. Only control flow is lifted. The decoder lives in `prezen_core.py` and has no Binary Ninja dependency.
- **Zen 1 / Zen 2** (`0xC80`-byte updates): the container is typed and the 64 instruction packages are mapped as code under a Binary Ninja architecture (`amd_zen1_ucode` / `amd_zen2_ucode`). Micro-ops are disassembled in the ZenUtils style and **lifted to LLIL**; Binary Ninja derives MLIL/HLIL, so graph view, cross-references and decompilation work as for any other target.
- **Zen 5** (`0x3820`-byte updates): the loader ID selects the geometry. For loader `0x8015` the register area holds **31 match and 31 mask words** at `0x328`, so the op-quads start at **`0x420`** and run up to the trailing zero padding. Each op-quad is four 64-bit micro-ops (`AMD_Zen5_MicroOp64`) plus a 32-bit `sequence_word` (36 bytes, `AMD_Zen5_OpQuad`). A type-specific **DataRenderer** shows every micro-op in Linear view as `opcode = AMD_ZEN_… rd=.. rs=.. rt=.. imm16=.. size=.. ld=.. st=.. class=N (name) asm=…`. The NOP run and the finalization sequence inside the body are carved out as their own labelled sections. Nothing is lifted or executed for Zen 5; the sequence word is annotated, not interpreted as control flow. An **experimental, read-only report** follows the sequence words and lists the micro-ops in execution order (assembly, or raw hex when undecodable) without changing the layout.
- The Zen 5 apply runs in **one undoable transaction** and verifies the applied types against the bytes before the transaction commits, so a wrong guess costs you a Ctrl‑Z.
- The decoders live in `zenella_core.py` (Zen) and `prezen_core.py` (K8/K10) and have **no Binary Ninja dependency**. The same code drives `zenella_inspect.py` and the `prezen_core.py` command line, which print the structural report, the sequence-ordered listing or JSON for a file without opening the GUI.

> **Zen 5 note:** the micro-op field layout (opcode at bits 47..54, registers, immediate, size, load/store, execution unit) is an **empirical inference**, not a vendor-confirmed ISA. Opcode and field names come from the published ZenUtils / zentool research. The bit groups `imm_flags`, `flags`, `mid` and `hi` are not yet understood, and the `asm=` operand projection is marked as inferred. The Experimental submenu exists precisely because some of the geometry is still being worked out.

## Zen 5 update layout (loader `0x8015`)

| Symbol | Offset | Size | Type | Contents |
|---|---|---|---|---|
| `amd_mc_header` | `0x0000` | `0x20` | `AMD_MC_Header` | Date, revision, loader ID, patch size, CPUID, flags |
| `amd_mc_signature` | `0x0020` | `0x100` | `u8[256]` | RSA signature |
| `amd_mc_modulus` | `0x0120` | `0x100` | `u8[256]` | Public key modulus |
| `amd_mc_check` | `0x0220` | `0x100` | `u8[256]` | Check block |
| `amd_mc_options` | `0x0320` | `0x04` | `AMD_MC_UcodeOptions` | autorun, encrypted flag, loader ID (this copy at `+0x322` selects the layout) |
| `amd_mc_rev` | `0x0324` | `0x04` | `u32` | Second copy of the update revision |
| `amd_mc_match_regs` | `0x0328` | `0x7C` | `AMD_MC_MatchRegisterBlock` | 31 match registers |
| `amd_mc_mask_regs` | `0x03A4` | `0x7C` | `AMD_MC_MaskRegisterBlock` | 31 mask registers |
| `amd_ucode_body` | `0x0420` | to padding | `AMD_Zen5_OpQuad[]` | Op-quads; NOP run and finalization carved out as `amd_mc_nop_section` / `amd_mc_finalization_section` |
| `amd_mc_zero_padding` | after body | to `0x3820` | `u8[]` | Trailing zeros |

The op-quad count follows the padding, so it can differ between updates; the two reference updates (revisions `0x0B10104E` and `0x0B101054`) contain 300. Loader `0x8010` keeps a searched equal match/mask split; `0x8004` and `0x8005` use zentool's fixed tables. Other loader IDs get scoped block types of their own width.

### Micro-op bitfield (`AMD_Zen5_MicroOp64`, 8 bytes)

| Bits | Field |
|---|---|
| `0–15` | `imm16` |
| `16–20` | `imm_flags` |
| `21–25` | `rt` |
| `26–30` | `rs` |
| `31–35` | `rd` |
| `36–41` | `flags` |
| `42–44` | `size` |
| `45` | `load` |
| `46` | `store` |
| `47–54` | `opcode` (`AMD_Zen_Opcode`) |
| `55–58` | `mid` |
| `59–61` | `exec_unit` (`spec`, `br`, `ld`, `stn`, `st`, `regx`, `reg`) |
| `62–63` | `hi` |

For comparison, Zen 1 / Zen 2 updates place 22 packed match entries (`AMD_Zen12_MatchEntry[22]`) at `0x328` and 64 packages (`AMD_Zen12_InstructionPackage[64]`, four 64-bit instructions plus a sequence word each) at `0x380`.

## K8 / K10 patch layout (pre-Zen, families 0x0F–0x12)

| Symbol | Offset | Size | Type | Contents |
|---|---|---|---|---|
| `amd_prezen_header` | `0x0000` | `0x20` | `AMD_PreZen_Header` | BCD date, patch level, loader ID (`0x8000` K8/K10, `0x8003` family 0x12), triad count, init flag, triad checksum, CPUID equivalence ID |
| `amd_prezen_match_regs` | `0x0020` | `0x20` | `AMD_PreZen_MatchRegister[8]` | Low 16 bits: hooked ROM triad address (`0xFFFF` = unused); register N redirects to handler triad `0xC00 + 2N` |
| `amd_prezen_triads` | `0x0040` | `28 × count` | `AMD_PreZen_TriadObfuscated[]` | Triads as stored: 3 × u64 ops + u32 sequence word, obfuscated |
| `.zenella_prezen_ucode_<base>` | region `+ 0x15000` | `28 × count` | `AMD_PreZen_Triad[]` | De-obfuscated mirror, mapped as code at byte address `triad × 28` (triad `0xC00` = `0x15000`) |

The family is `0x0F + (patch_level >> 24)`; two known patch levels (`0x02000008`, `0xC0012102`) are K8 despite their top byte and are special-cased. The de-obfuscation rotates each 32-bit word by `(triad × 7 + word) & 31`, inverts it and swaps word pairs.

### Pre-Zen micro-op (64-bit word, bit 0 = LSB)

| Bits | Field |
|---|---|
| `0–15` | `imm` (`braddr` = bits `0–11` for branches) |
| `9–14` | `src2reg` (register mode) |
| `23` | `regmode` (register vs immediate second source) |
| `24–29` | `src1` |
| `30–31` | `size` (`b`, `w`, `d`, `q`) |
| `46–51` | `dst` |
| `52` | three-operand form |
| `54–62` | `operation`; when bits `59–62` = 5 it is a `jcc` with condition code in `54–58` |

The sequence word uses bits `14–16` as the action (`0` next triad, `1` complete, `2` branch to bits `0–11`); other values are shown raw.

## Requirements

- **Binary Ninja** (Desktop) with Python scripting enabled (standard)
- **Python**: the Python 3 runtime embedded in Binary Ninja, no extra packages
- For the command-line tool only: any Python 3.8 or newer, standard library only

## Installation / Setup

Zenella is a **plugin folder**, not a single file. It consists of `__init__.py`, `amd_zen_ucode.py`, `amd_prezen_ucode.py`, `zenella_core.py`, `prezen_core.py`, `zenella_inspect.py` and the optional `cpuid_descriptions.json`.

### 1) Locate the plugin directory
In Binary Ninja: `Plugins` -> `Open Plugin Folder...`, or go straight there:

```
~/Library/Application Support/Binary Ninja/plugins/   # macOS
%APPDATA%\Binary Ninja\plugins\                       # Windows
~/.binaryninja/plugins/                               # Linux
```

### 2) Copy the whole directory into it
Clone or download the repository and place the entire directory inside the plugin folder:

```
cd ~/Library/Application\ Support/Binary\ Ninja/plugins/
git clone https://github.com/ercihan/zenella.git
```

Remove any older single-file copy of `amd_zen_ucode.py` first. The plugin refuses to apply a layout when it finds a second Zenella module loaded, or when the modules carry different versions or live in different directories.

### 3) Restart Binary Ninja
The **AMD Microcode** submenu appears under **Plugins**. The log shows the loaded version and the path it was loaded from, which is handy if a stale copy is still around.<br>
![pluginOverview](media/pluginOverview.png)

## Menu Commands and What They Do

All commands live under **`Plugins` -> `AMD Microcode`**. Each apply command comes in two forms: **at file start** for a standalone update and **at cursor** for an update embedded in a larger image, where the cursor marks the header. Partial blobs are applied partially or warned about.

- **`Auto-detect and apply at file start` / `at cursor`**: reads the header, decides between K8/K10 (checked first, from the loader ID and triad geometry), Zen 1, Zen 2 and Zen 5 from the processor signature (with a size fallback for Zen 5), and runs the matching apply. This is the one to start with. The log tells you which profile was chosen and why.
- **`Pre-Zen (K8/K10) > Apply layout + disassembly at file start` / `at cursor`**: types the header, the 8 match registers (commented with the hooked ROM triad and the handler label) and the obfuscated triads, then mirrors the de-obfuscated triads into an executable section under the `amd_prezen_ucode` architecture with `uc_XXXX` labels and a function at every handler. Disassembly is decoded from the stored bytes on every read, so it survives a database reopen.
- **`Pre-Zen (K8/K10) > Show decoded triad listing at file start` / `at cursor`**: prints the header, match registers and every de-obfuscated triad in the Ghidra AMDuCode text format as a report tab.
- **`Zen1 > Apply layout + LLIL/HLIL at file start` / `at cursor`** and **`Zen2 > …`**: type the container, map the 64 packages as executable code under the Zen 1 or Zen 2 architecture and let Binary Ninja lift them. Pick the generation yourself if auto-detect has no opinion (a `0xC80` blob with an unknown CPUID cannot be told apart by size).
- **`Zen1-Zen2 > Show ZenUtils-style disassembly at file start` / `at cursor`**: prints a plain-text listing of the header directives, the 44 logical match registers and all packages in the format ZenUtils users know, as a report tab.
- **`Zen5 > Apply structural layout at file start` / `at cursor`**: applies the confirmed loader `0x8015` layout (31 match and 31 mask registers at `0x328`, op-quads from `0x420` to the zero padding). Defines the types, creates the data variables and symbols from the table above, annotates sequence words, and verifies the result before the transaction commits. Other loader IDs get their own geometry.
- **`Zen5 > Experimental > …`**: four alternative Zen 5 geometries for research (file start only) plus two read-only reports. None of the geometries is the default and none carries documented evidence; they exist so a hypothesis can be applied and compared quickly.
  - **`Apply exact-fit 0x418/370 (no tail) at file start`**: zentool's boundary, 60 register words and 370 op-quads.
  - **`Apply best-scoring body offset (scan) at file start`**: tries register-area sizes and keeps the one whose sequence words look most reasonable.
  - **`Apply tail match-mask model (no trailer, valid sequences) at file start`**: metadata before the op-quads, equal match/mask registers after them.
  - **`Set match/mask register counts (move boundary) at file start`**: type the DWORD counts yourself; the body boundary moves to `0x328 + 4 * (match + mask)`.
  - **`Show sequence-ordered op-quad listing at file start` / `at cursor`**: one flat stream, one line per micro-op in execution order, assembly when the operand model applies and the raw 64-bit word otherwise. Sequence word `1` continues with the next op-quad, `7` returns, a 13-bit target inside `0x1f00 … 0x1f00 + quads` continues in the patch (patch RAM base observed in every decrypted update), a target equal to a match-register address re-enters at that hook's quad (m1 -> quad `2N`, m2 -> quad `2N+1`), and any other ROM target ends the run. Every op-quad is printed once. Expect many short runs: a Zen 5 update is a set of hooks that return into ROM microcode, which is not in the file. Needs a decrypted update; nothing is written to the database.
  - **`Show sequence-ordered op-quad chains (detailed) at file start` / `at cursor`**: the same order grouped per hook, with quad headers, the rule table and the reason each chain ends.

All Zenella comments are prefixed (`Zenella.layout:`, `Zenella.section:`, `Zenella.uop[...]:`, `Zenella.seq[...]:`) so your own notes survive a re-apply. The CPUID in the header is expanded and commented with the matching processor description from `cpuid_descriptions.json`; a small built-in table is used if the file is missing.

## Command-line tool (without Binary Ninja)

`zenella_inspect.py` prints the same Zen 5 regions, body sections, op-quads, sequence words and alignment diagnostics as text or JSON, and with `--flow` the experimental sequence-ordered micro-op stream. It is read-only (never writes the input), uses only the standard library and is useful for diffing updates or checking a layout before touching a database. It handles Zen 5 (Family 1Ah) updates; `prezen_core.py` does the same for K8/K10 patches.

```
python3 zenella_inspect.py update.bin                  # regions, op-quads, sequence words
python3 zenella_inspect.py update.bin --json           # everything as JSON
python3 zenella_inspect.py update.bin --layout exact   # force an alternative geometry
python3 zenella_inspect.py image.bin --base 0x1000     # embedded update
python3 zenella_inspect.py update_dec.bin --flow        # experimental: micro-ops in sequence-word order (decrypted Zen 5)
python3 zenella_inspect.py update_dec.bin --flow-detail # same order as chains with headers and end reasons
python3 zenella_inspect.py update_dec.bin --flow --patch-base none   # or auto / 0x1f00
python3 prezen_core.py k10_patch.bin                   # K8/K10: header, match registers, decoded triads
```

| Option | Meaning |
|---|---|
| `--base OFFSET` | offset of an embedded update inside a larger file |
| `--layout {auto,loader,exact,scan,tail,sample-420,zentool,raw}` | geometry to apply (`auto`/`loader` follow the loader ID at `+0x322`) |
| `--register-split MATCH:MASK` | override the match/mask DWORD counts (default for `0x8015` is `31:31`) |
| `--scan-boundary` | print a ranked scan of candidate body offsets |
| `--json` | emit JSON with all region bytes and records |
| `--output PATH` | write the report to a file instead of stdout |
| `--no-diagnostics` | omit the alignment comparisons |
| `--flow` | experimental: print the flat sequence-ordered micro-op stream instead of the structural report (needs decoded op-quads); with `--json` adds `flow_patch_base` and `flow_chains` |
| `--flow-detail` | experimental: the same order as chains with quad headers, rule table and end reasons |
| `--patch-base ADDR\|auto\|none` | ROM address of quad 0 for the flow listing (default `0x1f00`); `auto` picks the best-scoring base, `none` makes every ROM target end a run |

Exit status is `0` on success and `2` on an I/O or parse error. `prezen_core.py <patch.bin>` prints the K8/K10 listing and exits `1` when the file is not a pre-Zen patch.

## Types the plugin defines

All structures are packed. Names from Zenella 1.2 are kept, so scripts and existing databases keep working; new names are prefixed with the generation.

- Shared: `AMD_MC_Header`, `AMD_MC_CpuId`, `AMD_MC_LoaderIdTag` (`0x8004`, `0x8005`, `0x8010`, `0x8015`, `0x8016`), `AMD_MC_UcodeOptions`.
- Zen 5: `AMD_Zen5_MicroOp64`, `AMD_Zen5_OpQuad`, `AMD_MC_MatchRegisterBlock`, `AMD_MC_MaskRegisterBlock`, `AMD_MC_Patch` (also registered as `AMD_Zen5_Patch`), and the `AMD_Zen_Opcode` enum. Opcode values above `0xFF` (`AMD_ZEN_LD`, `AMD_ZEN_ST`) are synthetic: a load/store op is identified by its class, not by the opcode bits.
- Zen 1 / Zen 2: `AMD_Zen12_UcodeOptions`, `AMD_Zen12_MatchEntry`, `AMD_Zen12_InstructionPackage`, `AMD_Zen12_ExecutablePayload`, `AMD_Zen12_Patch`.
- K8 / K10: `AMD_PreZen_Header`, `AMD_PreZen_LoaderIdTag` (`0x8000`, `0x8003`), `AMD_PreZen_MatchRegister`, `AMD_PreZen_TriadObfuscated` (as stored), `AMD_PreZen_Triad` (decoded mirror).

## Common Workflow
1) Place the plugin directory in the `plugins/` folder
2) Restart Binary Ninja
3) Open a microcode `.bin` as a raw file (for an update inside a firmware image, open the image and put the cursor on the update header)
4) Run `AMD Microcode` -> `Auto-detect and apply at file start` (or the cursor variant)
5) Read `amd_mc_header` in Linear view: date, revision, loader ID and the expanded CPUID with the processor name as a comment
6) K8 / K10: jump to `uc_0c00` or follow the handler labels in the match-register comments and read the triads in Disassembly or graph view (only control flow is lifted, so HLIL shows micro-ops as unimplemented). Zen 1 / Zen 2: jump into the lifted packages and use graph or HLIL view. Zen 5: scroll `amd_ucode_body`; every op-quad is decoded, and the NOP run and finalization sequence are labelled so you can skip them. For execution order on a decrypted Zen 5 update, run `Zen5 > Experimental > Show sequence-ordered op-quad listing`

## Common workflow in action (video)
Applying the layout to a Zen 5 update:

<video controls width="720">
  <source src="media/workflowExample.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

https://github.com/user-attachments/assets/ee68d1ea-b8fb-478a-8a3e-c21d8ae99a45

Earlier Zen 1 / Zen 2 demo (Zenella 1.2):

https://github.com/user-attachments/assets/d15d805b-866c-4494-bcf9-918ed7bc2ea7
