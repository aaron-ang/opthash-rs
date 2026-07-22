#!/usr/bin/env python3
"""Extract checked, normalized metadata for named hot text symbols."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


NM_LINE = re.compile(
    r"^(?P<start>[0-9A-Fa-f]+)\s+(?P<size>[0-9A-Fa-f]+)\s+"
    r"(?P<kind>\S)\s+(?P<name>.+)$"
)
NM_NO_SIZE_LINE = re.compile(r"^(?P<start>[0-9A-Fa-f]+)\s+(?P<kind>\S)\s+(?P<name>.+)$")
SECTION_LINE = re.compile(
    r"^\s*(?P<index>\d+)\s+(?P<name>\S+)\s+(?P<size>[0-9A-Fa-f]+)\s+"
    r"(?P<vma>[0-9A-Fa-f]+)\s+[0-9A-Fa-f]+\s+"
    r"(?P<offset>[0-9A-Fa-f]+)\s+2\*\*(?P<align>\d+)\s*$"
)
INSTRUCTION_LINE = re.compile(
    r"^\s*(?P<address>[0-9A-Fa-f]+):\s+"
    r"(?P<bytes>(?:(?:[0-9A-Fa-f]{2}|[0-9A-Fa-f]{8})\s+)+)"
    r"(?P<assembly>\S.*)$"
)
RELOCATION_LINE = re.compile(
    r"^\s*(?P<address>[0-9A-Fa-f]+):\s+"
    r"(?P<kind>R_\S+)\s+(?P<target>\S.*)$"
)
SYMBOL_HEADER = re.compile(r"^\s*[0-9A-Fa-f]+\s+<.*>:\s*$")
FILE_HEADER = re.compile(r"^\S.*:\s+file format\s+\S+\s*$")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_checked(command: list[str]) -> str:
    completed = subprocess.run(command, check=False, text=True, capture_output=True)
    if completed.returncode != 0:
        raise ValueError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stderr.strip()}"
        )
    return completed.stdout


def parse_nm(text: str) -> list[dict[str, Any]]:
    symbols: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        match = NM_LINE.fullmatch(line)
        if match is None:
            no_size = NM_NO_SIZE_LINE.fullmatch(line)
            if no_size is None:
                raise ValueError(f"unknown nm line: {line!r}")
            start = int(no_size.group("start"), 16)
            symbols.append(
                {
                    "start": start,
                    "end": start,
                    "size": 0,
                    "kind": no_size.group("kind"),
                    "name": no_size.group("name"),
                }
            )
            continue
        start = int(match.group("start"), 16)
        size = int(match.group("size"), 16)
        symbols.append(
            {
                "start": start,
                "end": start + size,
                "size": size,
                "kind": match.group("kind"),
                "name": match.group("name"),
            }
        )
    return symbols


def select_symbol(symbols: list[dict[str, Any]], pattern: str) -> dict[str, Any]:
    try:
        matcher = re.compile(pattern)
    except re.error as error:
        raise ValueError(f"invalid symbol regex {pattern!r}: {error}") from error
    matches = [
        symbol
        for symbol in symbols
        if symbol["kind"] in {"t", "T"} and matcher.search(symbol["name"])
    ]
    if len(matches) != 1:
        names = ", ".join(symbol["name"] for symbol in matches) or "none"
        raise ValueError(
            f"expected exactly one text symbol matching {pattern!r}; "
            f"found {len(matches)}: {names}"
        )
    symbol = dict(matches[0])
    if symbol["size"] <= 0:
        raise ValueError(f"symbol has zero size: {symbol['name']}")
    symbol["pattern"] = pattern
    return symbol


def validate_non_overlapping(symbols: list[dict[str, Any]]) -> None:
    ordered = sorted(symbols, key=lambda symbol: (symbol["start"], symbol["end"]))
    for left, right in zip(ordered, ordered[1:], strict=False):
        if right["start"] < left["end"]:
            raise ValueError(
                f"symbol ranges overlap: {left['name']} and {right['name']}"
            )


def inventory_linker_generated_symbols(
    symbols: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    marker = re.compile(r"(?:veneer|thunk)", re.IGNORECASE)
    return [dict(symbol) for symbol in symbols if marker.search(symbol["name"])]


def _normalize_relocation_target(target: str) -> str:
    target = re.sub(r"(?<=\S)[+-]0x[0-9A-Fa-f]+(?=\s|$)", "", target)
    return f"{target} <pc-rel>"


def _normalize_assembly(assembly: str, arch: str) -> str:
    assembly = re.sub(r"\s+", " ", assembly.strip())
    relocation = re.search(r"\s+[0-9A-Fa-f]+:\s+(R_\S+)\s+(\S.*)$", assembly)
    relocation_suffix = ""
    if relocation is not None:
        target = _normalize_relocation_target(relocation.group(2))
        relocation_suffix = f" | relocation {relocation.group(1)} {target}"
        assembly = assembly[: relocation.start()].rstrip()

    parts = assembly.split(" ", 1)
    opcode = parts[0].lower()
    operands = parts[1] if len(parts) == 2 else ""
    if arch == "x86_64":
        operands = re.sub(
            r"[-+]?(?:0x)?[0-9A-Fa-f]+\(%rip\)", "<pc-rel>(%rip)", operands
        )
        if opcode.startswith(("call", "j")):
            operands = re.sub(
                r"(?<![#%$\w])(?:0x)?[0-9A-Fa-f]+(?=\s*<)",
                "<pc-rel>",
                operands,
                count=1,
            )
        operands = re.sub(
            r"(?<=#)\s*(?:0x)?[0-9A-Fa-f]+(?=\s*<)", " <pc-rel>", operands
        )
    elif arch == "aarch64":
        pc_relative = opcode in {
            "adr",
            "adrp",
            "b",
            "bl",
            "cbz",
            "cbnz",
            "tbz",
            "tbnz",
        } or opcode.startswith("b.")
        if pc_relative:
            operands = re.sub(
                r"(?<![#\w])(?:0x)?[0-9A-Fa-f]+(?=\s*<)",
                "<pc-rel>",
                operands,
                count=1,
            )
        if opcode == "adrp":
            operands = re.sub(
                r"(<GCC_except_table\d+)[+-]0x[0-9A-Fa-f]+>", r"\1>", operands
            )
    else:
        raise ValueError(f"unsupported architecture: {arch}")
    return f"{opcode}{(' ' + operands) if operands else ''}{relocation_suffix}"


_AARCH64_NO_DESTINATION = {
    "b",
    "br",
    "brk",
    "cbnz",
    "cbz",
    "ccmn",
    "ccmp",
    "cmn",
    "cmp",
    "dmb",
    "dsb",
    "hint",
    "isb",
    "nop",
    "prfm",
    "ret",
    "retaa",
    "retab",
    "smc",
    "svc",
    "tbnz",
    "tbz",
    "tst",
    "udf",
}
_AARCH64_SINGLE_DESTINATION = {
    "adc",
    "adcs",
    "add",
    "adds",
    "adr",
    "adrp",
    "and",
    "ands",
    "asr",
    "bic",
    "bics",
    "cls",
    "clz",
    "csel",
    "cset",
    "csetm",
    "csinc",
    "csinv",
    "csneg",
    "eon",
    "eor",
    "extr",
    "lsl",
    "lsr",
    "madd",
    "mneg",
    "mov",
    "movk",
    "movn",
    "movz",
    "msub",
    "mul",
    "mvn",
    "neg",
    "negs",
    "orn",
    "orr",
    "rbit",
    "rev",
    "rev16",
    "rev32",
    "ror",
    "sbc",
    "sbcs",
    "sdiv",
    "smaddl",
    "smulh",
    "smull",
    "sub",
    "subs",
    "sxtb",
    "sxth",
    "sxtw",
    "ubfiz",
    "ubfx",
    "udiv",
    "umaddl",
    "umulh",
    "umull",
    "uxtb",
    "uxth",
    "uxtw",
}
_AARCH64_ATOMIC_DESTINATION_SECOND = (
    "ldadd",
    "ldclr",
    "ldeor",
    "ldset",
    "ldsmax",
    "ldsmin",
    "ldumax",
    "ldumin",
    "swp",
)
_AARCH64_MEMORY_ADDRESS = re.compile(
    r"\[(?P<base>x(?:[12]?\d|30)|sp)(?:,\s*[^\]]+)?\]"
    r"(?P<pre>!)?(?P<post>,\s*(?:#[+-]?(?:0x)?[0-9A-Fa-f]+|x(?:[12]?\d|30)))?"
)
_AARCH64_CALLER_SAVED = {f"x{register}" for register in range(19)} | {"x30"}


def _aarch64_registers(value: str) -> list[str]:
    registers = re.findall(r"(?<!\w)([wx](?:[12]?\d|30))(?!\w)", value)
    return [f"x{register[1:]}" for register in registers]


def _aarch64_written_registers(instruction: str) -> set[str]:
    opcode, _, operands = instruction.partition(" ")
    opcode = opcode.lower()
    written: set[str] = set()
    memory = _AARCH64_MEMORY_ADDRESS.search(operands)
    before_memory = operands if memory is None else operands[: memory.start()]
    data_registers = _aarch64_registers(before_memory)
    if memory is not None:
        if memory.group("pre") or memory.group("post"):
            base = memory.group("base")
            if base != "sp":
                written.add(base)
        if opcode.startswith(("ldp", "ldnp", "ldxp", "ldaxp")):
            written.update(data_registers[:2])
        elif opcode.startswith(_AARCH64_ATOMIC_DESTINATION_SECOND):
            written.update(data_registers[1:2])
        elif opcode.startswith("casp"):
            written.update(data_registers[:2])
        elif opcode.startswith("cas"):
            written.update(data_registers[:1])
        elif opcode.startswith(("stxr", "stlxr", "stxp", "stlxp")):
            written.update(data_registers[:1])
        elif opcode.startswith("ld"):
            written.update(data_registers[:1])
        elif not (opcode.startswith("st") or opcode == "prfm"):
            raise ValueError(f"unsupported AArch64 memory definition: {instruction}")
        return written
    if opcode == "bl" or opcode.startswith("blr"):
        return set(_AARCH64_CALLER_SAVED)
    if opcode in _AARCH64_NO_DESTINATION or opcode.startswith("b."):
        return set()
    if opcode.startswith(("ldp", "ldnp")):
        return set(data_registers[:2])
    if opcode.startswith("ld") or opcode in _AARCH64_SINGLE_DESTINATION:
        return set(data_registers[:1])
    if opcode.startswith("st"):
        return set()
    raise ValueError(f"unsupported AArch64 instruction definition: {instruction}")


def _normalize_aarch64_sequence(
    assembly: str,
    pending_adrp: dict[str, str],
    resolved_addresses: dict[str, str],
) -> str:
    instruction, separator, relocation = assembly.partition(" | relocation ")
    adrp = re.fullmatch(r"adrp (x\d+), <pc-rel> (<[^>]+>)", instruction)
    if adrp:
        destination = adrp.group(1)
        pending_adrp[destination] = adrp.group(2)
        resolved_addresses.pop(destination, None)
        return assembly

    add = re.fullmatch(r"add (x\d+), (x\d+), #(0x[0-9A-Fa-f]+|\d+)", instruction)
    resolved_destination = None
    if add and add.group(2) in pending_adrp:
        target = pending_adrp.pop(add.group(2))
        instruction = f"add {add.group(1)}, {add.group(2)}, <pc-rel> {target}"
        resolved_destination = (add.group(1), target)

    memory = re.fullmatch(
        r"((?:ldr|ldrsw|str)\w*) ([^,]+), \[(x\d+), #(0x[0-9A-Fa-f]+|\d+)\]",
        instruction,
    )
    if memory and memory.group(3) in pending_adrp:
        target = pending_adrp.pop(memory.group(3))
        instruction = (
            f"{memory.group(1)} {memory.group(2)}, "
            f"[{memory.group(3)}, <pc-rel>] {target}"
        )
    elif memory_use := _AARCH64_MEMORY_ADDRESS.search(instruction):
        if memory_use.group("base") != "sp":
            pending_adrp.pop(memory_use.group("base"), None)

    literal = re.fullmatch(
        r"(ldr\w*) ([^,]+), (?:0x)?[0-9A-Fa-f]+ (<[^>]+>)", instruction
    )
    if literal:
        instruction = (
            f"{literal.group(1)} {literal.group(2)}, <pc-rel> {literal.group(3)}"
        )

    if separator and "AARCH64" in relocation and "LO12" in relocation:
        target = relocation.rsplit(" ", 1)[-1]
        instruction = re.sub(
            r"#(?:0x)?[0-9A-Fa-f]+", f"<pc-rel> {target}", instruction, count=1
        )
    for register in _aarch64_written_registers(instruction):
        pending_adrp.pop(register, None)
        resolved_addresses.pop(register, None)
    if resolved_destination is not None:
        resolved_addresses[resolved_destination[0]] = resolved_destination[1]
    return f"{instruction}{separator}{relocation}"


def normalize_objdump(text: str, arch: str) -> dict[str, Any]:
    if arch not in {"aarch64", "x86_64"}:
        raise ValueError(f"unsupported architecture: {arch}")
    normalized: list[str] = []
    direct_calls: list[str] = []
    indirect_calls: list[str] = []
    spills: list[str] = []
    frame_adjustment = 0
    saw_header = False
    pending_adrp: dict[str, str] = {}
    resolved_addresses: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if (
            SYMBOL_HEADER.fullmatch(line)
            or FILE_HEADER.fullmatch(line)
            or stripped.startswith("Disassembly of section ")
        ):
            saw_header = saw_header or SYMBOL_HEADER.fullmatch(line) is not None
            continue
        relocation = RELOCATION_LINE.fullmatch(line)
        if relocation is not None:
            target = _normalize_relocation_target(relocation.group("target"))
            normalized.append(f"relocation {relocation.group('kind')} {target}")
            continue
        instruction = INSTRUCTION_LINE.fullmatch(line)
        if instruction is None:
            raise ValueError(f"unknown objdump line: {line!r}")
        assembly = _normalize_assembly(instruction.group("assembly"), arch)
        if arch == "aarch64":
            assembly = _normalize_aarch64_sequence(
                assembly, pending_adrp, resolved_addresses
            )
        normalized.append(assembly)
        opcode, _, operands = assembly.partition(" ")
        if (
            arch == "x86_64"
            and opcode.startswith("call")
            and not operands.startswith("*")
        ):
            direct_calls.append(operands)
        elif arch == "x86_64" and opcode.startswith("call"):
            indirect_calls.append(operands)
        elif arch == "aarch64" and opcode == "bl":
            direct_calls.append(operands)
        elif arch == "aarch64" and opcode.startswith("blr"):
            indirect_calls.append(operands)
        if arch == "x86_64":
            frame = re.search(r"^sub\w* \$0x([0-9A-Fa-f]+),%rsp(?:\s|$)", assembly)
            if frame:
                frame_adjustment = max(frame_adjustment, int(frame.group(1), 16))
            if opcode.startswith("push") or (
                opcode.startswith("mov")
                and re.search(r"%[a-z0-9]+,[-+]?(?:0x[0-9a-f]+|\d+)?\(%rsp\)", operands)
            ):
                spills.append(assembly)
        else:
            frame = re.search(r"^sub sp, sp, #(0x[0-9A-Fa-f]+|\d+)(?:\s|$)", assembly)
            if frame:
                frame_adjustment = max(frame_adjustment, int(frame.group(1), 0))
            if opcode in {"stp", "str"} and re.search(r"\[sp(?:,|\])", operands):
                spills.append(assembly)
    if not saw_header:
        raise ValueError("objdump output contains no symbol header")
    if not normalized:
        raise ValueError("objdump output contains no instructions")
    normalized_text = "\n".join(normalized) + "\n"
    return {
        "instructions": normalized,
        "hash": sha256_bytes(normalized_text.encode()),
        "direct_calls": direct_calls,
        "indirect_calls": indirect_calls,
        "frame_adjustment": frame_adjustment,
        "spills": spills,
    }


def parse_sections(text: str) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = SECTION_LINE.fullmatch(line)
        if match is None:
            continue
        sections.append(
            {
                # GNU objdump numbers displayed sections from zero because it
                # omits ELF's null section. Record the real ELF shndx used by
                # readelf and the symbol table.
                "index": int(match.group("index")) + 1,
                "name": match.group("name"),
                "size": int(match.group("size"), 16),
                "vma": int(match.group("vma"), 16),
                "file_offset": int(match.group("offset"), 16),
                "alignment": 1 << int(match.group("align")),
            }
        )
    if not sections:
        raise ValueError("objdump section table contained no sections")
    return sections


def locate_symbol_bytes(
    symbol: dict[str, Any], sections: list[dict[str, Any]], binary_size: int
) -> tuple[dict[str, Any], int]:
    matches = [
        section
        for section in sections
        if section["vma"] <= symbol["start"]
        and symbol["end"] <= section["vma"] + section["size"]
    ]
    if len(matches) != 1:
        raise ValueError(
            f"symbol {symbol['name']} range is not wholly in exactly one file section"
        )
    section = matches[0]
    offset = section["file_offset"] + symbol["start"] - section["vma"]
    if offset < 0 or offset + symbol["size"] > binary_size:
        raise ValueError(f"symbol {symbol['name']} range is outside binary file")
    return section, offset


def validate_architecture(file_output: str, requested: str) -> None:
    match = re.search(r"^architecture:\s*([^,\s]+)", file_output, re.MULTILINE)
    if match is None:
        raise ValueError("objdump did not report binary architecture")
    actual = match.group(1)
    valid = (
        actual == "aarch64"
        if requested == "aarch64"
        else actual
        in {
            "i386:x86-64",
            "i386:x64-32",
        }
    )
    if not valid:
        raise ValueError(
            f"architecture mismatch: requested {requested}, binary is {actual}"
        )


def extract(binary: Path, arch: str, patterns: list[str]) -> dict[str, Any]:
    binary_bytes = binary.read_bytes()
    validate_architecture(run_checked(["objdump", "-f", str(binary)]), arch)
    symbols = parse_nm(
        run_checked(["nm", "-S", "-n", "--defined-only", "-C", str(binary)])
    )
    selected = [select_symbol(symbols, pattern) for pattern in patterns]
    validate_non_overlapping(selected)
    sections = parse_sections(run_checked(["objdump", "-h", str(binary)]))
    extracted: list[dict[str, Any]] = []
    for symbol in selected:
        section, file_offset = locate_symbol_bytes(symbol, sections, len(binary_bytes))
        raw = binary_bytes[file_offset : file_offset + symbol["size"]]
        dump = run_checked(
            [
                "objdump",
                "-drwC",
                f"--start-address=0x{symbol['start']:x}",
                f"--stop-address=0x{symbol['end']:x}",
                str(binary),
            ]
        )
        normalized = normalize_objdump(dump, arch)
        extracted.append(
            {
                **symbol,
                "section": section["name"],
                "section_index": section["index"],
                "section_name": section["name"],
                "section_alignment": section["alignment"],
                "file_offset": file_offset,
                "page_offset": symbol["start"] % 4096,
                "raw_sha256": sha256_bytes(raw),
                "normalized_instructions_sha256": normalized["hash"],
                "normalized_instructions": normalized["instructions"],
                "direct_calls": normalized["direct_calls"],
                "indirect_calls": normalized["indirect_calls"],
                "frame_adjustment": normalized["frame_adjustment"],
                "spills": normalized["spills"],
            }
        )
    return {
        "binary": str(binary),
        "binary_sha256": sha256_bytes(binary_bytes),
        "architecture": arch,
        "linker_generated_veneer_thunks": inventory_linker_generated_symbols(symbols),
        "symbols": extracted,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--arch", choices=("aarch64", "x86_64"), required=True)
    parser.add_argument("--symbol", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.binary.is_absolute() or not args.output.is_absolute():
        parser.error("--binary and --output must be absolute paths")
    if not args.binary.is_file():
        parser.error(f"binary does not exist: {args.binary}")
    result = extract(args.binary.resolve(), args.arch, args.symbol)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    temporary.replace(args.output)


if __name__ == "__main__":
    main()
