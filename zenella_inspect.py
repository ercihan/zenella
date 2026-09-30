#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Read-only, standard-library CLI for Zenella's Zen5 opcode-tag analysis.

No Binary Ninja, network access, signing, loading, decryption, or update writing.
Run `python zenella_inspect.py --help` for usage.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys
from typing import Dict, Optional, Sequence

if __package__:
    from .zenella_core import (
        ParsedZen5Patch, ZEN5_PATCH_SIZE, ZEN5_OPQUAD_SIZE, OPCLASS_NAMES,
        header_date_iso, parse_zen5_patch, render_zen5_opquad_lines,
        zen5_alignment_diagnostics, load_zen5_opcode_names,
        decode_zentool_sequence_word, zen5_sequence_statistics,
        analyze_zen5_tail, zen5_scan_body_offsets, decode_zen5_operands,
        zen5_detect_body_sections,
    )
else:
    from zenella_core import (
        ParsedZen5Patch, ZEN5_PATCH_SIZE, ZEN5_OPQUAD_SIZE, OPCLASS_NAMES,
        header_date_iso, parse_zen5_patch, render_zen5_opquad_lines,
        zen5_alignment_diagnostics, load_zen5_opcode_names,
        decode_zentool_sequence_word, zen5_sequence_statistics,
        analyze_zen5_tail, zen5_scan_body_offsets, decode_zen5_operands,
        zen5_detect_body_sections,
    )

VERSION = "2.2.0"


def parsed_to_dict(parsed: ParsedZen5Patch, diagnostics: Optional[dict] = None,
                   tag_names: Optional[Dict[int, str]] = None) -> dict:
    names = load_zen5_opcode_names() if tag_names is None else tag_names
    header = asdict(parsed.header)
    header["expanded_cpuid"] = f"0x{parsed.header.expanded_cpuid:08x}"
    family, model, stepping = parsed.header.effective_family_model
    header.update(family=family, model=model, stepping=stepping)
    try:
        header["date_iso"] = header_date_iso(parsed.header)
    except ValueError:
        header["date_iso"] = None
    options_region = next((r for r in parsed.regions if r.name == "options" and len(r.raw) == 4), None)
    return {
        "zenella_version": VERSION,
        "analysis_kind": "opcode tags and original Zenella bitfields; no hardware execution",
        "patch_sha256": parsed.sha256,
        "base": parsed.base,
        "bytes_accounted_for": len(parsed.patch_bytes),
        "layout": parsed.layout,
        "confidence": parsed.confidence,
        "warnings": list(parsed.warnings),
        "header": header,
        "geometry": (dict(asdict(parsed.geometry),
                          register_dwords=parsed.geometry.register_dwords,
                          register_size=parsed.geometry.register_size,
                          code_end=parsed.geometry.code_end,
                          auxiliary_size=parsed.geometry.auxiliary_size)
                     if parsed.geometry is not None else None),
        "options": ({
            "autorun": options_region.raw[0], "encrypted": options_region.raw[1],
            "loaderid": int.from_bytes(options_region.raw[2:4], "little"),
            "loaderid_interpretation": "stored LE16 at +0x322; Zenella research-profile selector",
        } if options_region is not None else None),
        "layout_selector": {
            "patch_offset": parsed.selector_offset,
            "loaderid": (parsed.geometry.format_id if parsed.geometry else None),
            "basis": ("native zentool first-header comparison" if parsed.selector_offset == 8
                      else "Zenella second-header research profile" if parsed.options is not None
                      else "missing second header; raw extent only"),
        },
        "body_sections": (
            [{"name": s["name"], "label": s["label"], "offset": s["offset"], "end": s["end"],
              "quad_count": s["quad_count"], "interpretation": s["interpretation"]}
             for s in zen5_detect_body_sections(parsed.quads, parsed.geometry.quad_offset)]
            if parsed.geometry is not None and parsed.quads else []),
        "sequences": zen5_sequence_statistics(parsed.quads),
        "code_remainder": ({
            "offset": parsed.base + parsed.geometry.code_end,
            "size": parsed.geometry.auxiliary_size,
            "dword_count": parsed.geometry.auxiliary_size // 4,
            "interpretation": "bytes left after the op-quads; a valid-sequence op-quad offset cannot "
                              "tile the patch to the exact end, so a small remainder is unavoidable",
        } if parsed.geometry is not None and parsed.quads
             and parsed.geometry.auxiliary_size else None),
        "regions": [
            {"name": r.name, "offset": r.offset, "end": r.end, "size": len(r.raw),
             "interpretation": r.interpretation, "sha256": hashlib.sha256(r.raw).hexdigest(),
             "data_hex": r.raw.hex()}
            for r in parsed.regions
        ],
        "tagging": {
            "uops": len(parsed.quads) * 4,
            "named": sum(u.opcode in names for q in parsed.quads for u in q.uops),
            "numeric_unknown": sum(u.opcode not in names for q in parsed.quads for u in q.uops),
            "table": "ZEN_OPCODE_ENUM in amd_zen_ucode.py",
        },
        "opquads": [
            {"index": i, "offset": q.offset,
             "uops": [
                  {"offset": u.offset, "raw": f"0x{u.word:016x}",
                   "opcode": u.opcode, "opcode_tag": names.get(u.opcode),
                   "fields": {
                       "rd": u.rd, "rs": u.rs, "rt": u.rt, "imm16": u.imm16,
                       "imm_flags": u.imm_flags, "flags": u.flags,
                       "size": u.size, "load": u.load, "store": u.store,
                       "mid": u.mid, "exec_unit": u.exec_unit, "hi": u.hi,
                       "opclass": u.exec_unit,
                       "opclass_name": OPCLASS_NAMES.get(u.exec_unit),
                   },
                   "operands": asdict(decode_zen5_operands(
                       u, prev_word=q.uops[slot - 1].word if slot else None))}
                  for slot, u in enumerate(q.uops)],
              "sequence_offset": q.offset + 32,
              "sequence_word": f"0x{q.sequence_word:08x}",
              "zentool_sequence_fields": asdict(decode_zentool_sequence_word(q.sequence_word)),
              "sequence_annotation": decode_zentool_sequence_word(q.sequence_word).text}
            for i, q in enumerate(parsed.quads)
        ],
        "alignment_diagnostics": diagnostics,
    }


def render_patch_report(
    parsed: ParsedZen5Patch,
    diagnostics: Optional[dict] = None,
    tag_names: Optional[Dict[int, str]] = None,
) -> str:
    """Text report shared by the CLI and Binary Ninja. All offsets are file/view offsets."""
    tag_names = load_zen5_opcode_names() if tag_names is None else tag_names
    family, model, stepping = parsed.header.effective_family_model
    try:
        date_text = header_date_iso(parsed.header)
    except ValueError as exc:
        date_text = f"invalid date: {exc}"
    lines = [
        f"Zenella {VERSION} | Zen5 opcode tags",
        "Original ZEN_OPCODE_ENUM and bitfields; no microcode was loaded or executed.",
        f"Patch SHA-256: {parsed.sha256}",
        f"Base: 0x{parsed.base:x}",
        f"Layout: {parsed.layout} ({parsed.confidence})",
        f"Header date: {date_text}; revision: 0x{parsed.header.revision:08x}",
        f"First-header format +0x08: 0x{parsed.header.loader_id:04x}; raw patch_length: 0x{parsed.header.patch_length:02x}",
        (f"Second-header loaderid +0x322: 0x{parsed.options.loaderid:04x}" if parsed.options else
         "Second-header loaderid: unavailable"),
        (f"Layout selector: +0x{parsed.selector_offset:x}" if parsed.selector_offset is not None
         else "Layout selector: unavailable; raw extent only"),
        f"Compact processor revision: 0x{parsed.header.processor_signature:08x}",
        f"Expanded CPUID: 0x{parsed.header.expanded_cpuid:08x}; family 0x{family:x}, model 0x{model:x}, stepping {stepping}",
        "", "WARNINGS",
        *[f"- {w}" for w in parsed.warnings],
        "", "REGIONS (half-open intervals; each input byte accounted for exactly once)",
    ]
    for r in parsed.regions:
        lines.append(f"0x{r.offset:04x}..0x{r.end:04x}  size=0x{len(r.raw):x}  {r.name}")
        lines.append(f"    {r.interpretation}")
        if r.name in ("auxiliary_raw", "prefix_metadata", "opaque_payload", "appended_data"):
            lines.append(f"    sha256={hashlib.sha256(r.raw).hexdigest()}")
            lines.append(f"    nonzero_bytes={sum(v != 0 for v in r.raw)}, trailing_zero_bytes={len(r.raw) - len(r.raw.rstrip(bytes([0])))}")
    body_sections = (zen5_detect_body_sections(parsed.quads, parsed.geometry.quad_offset)
                     if parsed.geometry is not None and parsed.quads else [])
    if body_sections:
        lines.extend(("", "BODY SECTIONS (named overlays inside the op-quad body; op-quads still decoded)"))
        for s in body_sections:
            lines.append(f"0x{s['offset']:04x}..0x{s['end']:04x}  size=0x{s['end'] - s['offset']:x}  "
                         f"{s['quad_count']} op-quads  {s['label']}")
            lines.append(f"    {s['interpretation']}")
            lines.append(f"    raw byte boundaries 0x{s['raw_offset']:04x}..0x{s['raw_end']:04x}; "
                         f"NOP words on uop slots of this grid: {'yes' if s['aligned'] else 'NO (op-quads shifted)'}")
    if parsed.geometry is not None and parsed.geometry.auxiliary_size:
        s = analyze_zen5_tail(parsed.patch_bytes, parsed.geometry.code_end,
                              parsed.geometry.auxiliary_size)["stats"]
        lines.extend((
            "", "CODE REMAINDER (bytes after the op-quads; unavoidable at a valid-sequence offset)",
            f"0x{parsed.base + s['offset']:04x}..0x{parsed.base + s['end']:04x}  size=0x{s['size']:x} "
            f"({s['dword_count']} DWORDs, {s['nonzero_bytes']} nonzero bytes)",
        ))
    if diagnostics:
        lines.extend(("", "ALIGNMENT COMPARISON (descriptive, not an ISA-validity score)"))
        for key in ("zentool_418_first_256", "sample_420_256", "zentool_418_all_370", "post_2820_first_32_quads"):
            d = diagnostics[key]
            lines.append(
                f"{key}: words={d['word_count']} exact_NOP={d['exact_zentool_nop_words']} "
                f"class0_other={d['class0_other_than_exact_nop']} "
                f"nonzero_seq={d['nonzero_sequences']}/{d['records']} seq_one={d['sequence_one_count']}"
            )
        for label in ("quads_256_by_phase", "triads_256_by_phase"):
            lines.append(label + ":")
            for d in diagnostics[label]:
                lines.append(f"    start=0x{d['start']:x} stride={d['stride']} NOP={d['exact_zentool_nop_words']} "
                             f"class0_other={d['class0_other_than_exact_nop']} nonzero_seq={d['nonzero_sequences']} "
                             f"seq_one={d['sequence_one_count']}")
    for r in parsed.regions:
        if r.name in ("register_table", "match_registers", "mask_registers"):
            field = {"register_table": "register_word", "match_registers": "match_reg",
                     "mask_registers": "mask_reg"}[r.name]
            count = len(r.raw) // 4
            values = [int.from_bytes(r.raw[4 * i:4 * i + 4], "little") for i in range(count)]
            nonzero = sum(v != 0 for v in values)
            lines.extend(("", f"{r.name.upper()}: {count} DWORDs ({nonzero} nonzero)"))
            # Large blocks (post-code register area) are mostly zero-padded slots;
            # print the nonzero entries only, capped, to keep the report readable.
            shown = 0
            for i, value in enumerate(values):
                if count > 64 and value == 0:
                    continue
                if shown >= 256:
                    lines.append(f"    ... {nonzero - shown} more nonzero entries (use --json for all)")
                    break
                lines.append(f"0x{r.offset + i * 4:04x}: {field}[{i}] = 0x{value:08x}")
                shown += 1
    if parsed.quads:
        seqstats = zen5_sequence_statistics(parsed.quads)
        lines.extend(("", "SEQUENCE WORDS (stored DWORDs, not synthesized)",
                      f"exactly 0x00000001: {seqstats['exact_one_count']}/{seqstats['count']}; "
                      f"of these, {seqstats['exact_one_all_nop_quads']} accompany four NOP words",
                      "zentool projects 1 as relative +1 (next quad); remaining flags are retained"))
        named = sum(u.opcode in tag_names for q in parsed.quads for u in q.uops)
        total = len(parsed.quads) * 4
        lines.extend(("", f"OPCODE TAGS: {named}/{total} named; {total - named} numeric unknowns",
                      "OPQUADS (indices are file record indices, not hardware addresses)"))
        payload = b"".join(q.raw for q in parsed.quads)
        lines.extend(render_zen5_opquad_lines(payload, tag_names, parsed.quads[0].offset))
    else:
        lines.extend(("", "No instruction layout selected; payload remains raw."))
    lines.extend(("", "No bytes changed; no signature/checksum validation; no hardware execution."))
    return "\n".join(lines) + "\n"


def render_boundary_scan(scan: dict) -> str:
    """Human-readable ranked table of candidate body offsets."""
    lines = ["BODY-OFFSET SCAN (register-area size vs sequence-word reasonableness)",
             scan["note"],
             f"records window: {scan['records_window']}",
             "  offset  regdw  match/mask  tail    nonzeroSeq  seq==1  topNibbleJunk  exactNOP  reasonable"]
    for c in scan["candidates"]:
        mm = f"{c['match_mask'][0]}/{c['match_mask'][1]}" if c["match_mask"] else "odd"
        lines.append(
            f"  0x{c['offset']:04x}  {c['register_dwords']:5d}  {mm:>9}  0x{c['tail_bytes']:04x}  "
            f"{c['nonzero_sequences']:9d}/{c['records_scored']:<3d} {c['sequence_one_count']:6d}  "
            f"{c['sequence_top_nibble_nonzero']:12d}  {c['exact_nop_words']:8d}  "
            f"{'YES' if c['reasonable'] else 'no'}")
    if scan["best"]:
        b = scan["best"]
        mm = f"{b['match_mask'][0]}/{b['match_mask'][1]}" if b["match_mask"] else "odd"
        lines.append(f"best: 0x{b['offset']:04x} (regdw={b['register_dwords']}, match/mask={mm}); "
                     "empirical alignment pick, not documented hardware geometry")
    return "\n".join(lines) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="decrypted update or a containing binary")
    parser.add_argument("--base", type=lambda s: int(s, 0), default=0, help="embedded-patch offset")
    parser.add_argument("--layout", choices=("auto", "loader", "exact", "scan", "tail", "sample-420", "zentool", "raw"), default="auto",
                        help="auto/loader: +0x322 selects the loader; for 8015 the confirmed match[31]/mask[31] "
                             "registers put the op-quads at 0x420 and the body ends at the zero padding; for "
                             "8010 the body offset is searched from op-quad/sequence content. exact: force "
                             "0x418/370 no-tail. scan: pick the best-scoring body offset. sample-420: force "
                             "0x420/256. zentool: 0x418/370 unsplit")
    parser.add_argument("--register-split", metavar="MATCH:MASK",
                        help="override the match/mask display (8015 default 31:31, confirmed); "
                             "the mask half is a Zenella extension, not hardware capacity validation")
    parser.add_argument("--scan-boundary", action="store_true",
                        help="print a ranked scan of candidate body offsets (register-area sizes) by "
                             "sequence-word reasonableness; for loader 0x8010/0x8015; no documented evidence")
    parser.add_argument("--json", action="store_true", help="emit JSON with all region bytes and records")
    parser.add_argument("--output", type=Path, help="write report instead of stdout (never overwrite the input)")
    parser.add_argument("--no-diagnostics", action="store_true", help="omit alignment comparisons")
    args = parser.parse_args(argv)
    try:
        if args.output and (args.output.resolve() == args.input.resolve()
                            or (args.output.exists() and args.input.exists()
                                and args.output.samefile(args.input))):
            raise ValueError("The report output must not overwrite the input microcode file")
        data = args.input.read_bytes()
        split = None
        if args.register_split is not None:
            parts = args.register_split.split(":")
            if len(parts) != 2:
                raise ValueError("--register-split must be MATCH:MASK DWORD counts")
            split = tuple(int(n, 0) for n in parts)
        parsed = parse_zen5_patch(data, args.base, args.layout, register_split=split)
        diagnostics = None
        # Do not report ciphertext alignment statistics as plaintext evidence.
        if (not args.no_diagnostics and len(data) - args.base >= ZEN5_PATCH_SIZE
                and data[args.base + 0x321] == 0):
            diagnostics = zen5_alignment_diagnostics(data, args.base)
        scan = None
        if args.scan_boundary and len(data) - args.base >= ZEN5_PATCH_SIZE:
            scan = zen5_scan_body_offsets(data, args.base)
        if args.json:
            payload = parsed_to_dict(parsed, diagnostics)
            if scan is not None:
                payload["boundary_scan"] = scan
            text = json.dumps(payload, indent=2) + "\n"
        else:
            text = render_patch_report(parsed, diagnostics)
            if scan is not None:
                text += "\n" + render_boundary_scan(scan)
        if args.output:
            args.output.write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
    except (OSError, ValueError) as exc:
        print(f"zenella_inspect: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
