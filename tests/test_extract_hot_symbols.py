import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "extract-hot-symbols.py"
SPEC = importlib.util.spec_from_file_location("extract_hot_symbols", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
extractor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(extractor)


X86_A = """
0000000000001000 <crate::kernel>:
 1000:\t55                   \tpush   %rbp
 1001:\t48 8d 05 34 12 00 00 \tlea    0x1234(%rip),%rax # 223c <crate::data>
 1008:\te8 00 00 00 00       \tcall   100d <crate::helper>\t1009: R_X86_64_PLT32\tcrate::helper-0x4
 100d:\t48 89 44 24 08       \tmov    %rax,0x8(%rsp)
"""

X86_RELOCATED = """
0000000000005000 <crate::kernel>:
 5000:\t55                   \tpush   %rbp
 5001:\t48 8d 05 78 56 00 00 \tlea    0x5678(%rip),%rax # a680 <crate::data>
 5008:\te8 00 00 00 00       \tcall   500d <crate::helper>\t5009: R_X86_64_PLT32\tcrate::helper-0x8
 500d:\t48 89 44 24 08       \tmov    %rax,0x8(%rsp)
"""

AARCH64_A = """
0000000000001000 <crate::kernel>:
 1000:\td10083ff \tsub\tsp, sp, #0x20
 1004:\ta9017bfd \tstp\tx29, x30, [sp, #16]
 1008:\t90000000 \tadrp\tx0, 2000 <crate::data>
 100c:\t94000000 \tbl\t1010 <crate::helper>\t100c: R_AARCH64_CALL26\tcrate::helper
"""

AARCH64_RELOCATED = """
0000000000009000 <crate::kernel>:
 9000:\td10083ff \tsub\tsp, sp, #0x20
 9004:\ta9017bfd \tstp\tx29, x30, [sp, #16]
 9008:\t90000000 \tadrp\tx0, f000 <crate::data>
 900c:\t94000000 \tbl\t9010 <crate::helper>\t900c: R_AARCH64_CALL26\tcrate::helper+0x10
"""


@pytest.mark.parametrize(
    ("arch", "left", "right"),
    [("x86_64", X86_A, X86_RELOCATED), ("aarch64", AARCH64_A, AARCH64_RELOCATED)],
)
def test_address_and_relocation_changes_normalize_identically(arch, left, right):
    assert (
        extractor.normalize_objdump(left, arch)["hash"]
        == extractor.normalize_objdump(right, arch)["hash"]
    )


@pytest.mark.parametrize(
    ("arch", "original", "changed"),
    [
        ("x86_64", X86_A, X86_A.replace("%rax,0x8", "%rcx,0x8")),
        ("x86_64", X86_A, X86_A.replace("0x8(%rsp)", "0x10(%rsp)")),
        ("aarch64", AARCH64_A, AARCH64_A.replace("sub\tsp", "add\tsp")),
        ("aarch64", AARCH64_A, AARCH64_A.replace("[sp, #16]", "[sp, #24]")),
    ],
)
def test_opcode_register_and_stack_offset_changes_hash_differently(
    arch, original, changed
):
    assert (
        extractor.normalize_objdump(original, arch)["hash"]
        != extractor.normalize_objdump(changed, arch)["hash"]
    )


def test_symbol_selection_rejects_zero_and_multiple_matches():
    symbols = extractor.parse_nm(
        "0000000000001000 0000000000000010 t crate::one\n"
        "0000000000002000 0000000000000020 T crate::two\n"
    )
    with pytest.raises(ValueError, match="exactly one text symbol.*missing"):
        extractor.select_symbol(symbols, "missing$")
    with pytest.raises(ValueError, match="exactly one text symbol.*crate"):
        extractor.select_symbol(symbols, "crate::")


def test_unknown_objdump_line_is_fatal():
    with pytest.raises(ValueError, match="unknown objdump line"):
        extractor.normalize_objdump(X86_A + "THIS FORM IS NOT UNDERSTOOD\n", "x86_64")


def test_overlap_is_fatal():
    with pytest.raises(ValueError, match="overlap"):
        extractor.validate_non_overlapping(
            [
                {"name": "one", "start": 0x1000, "end": 0x1020},
                {"name": "two", "start": 0x1010, "end": 0x1030},
            ]
        )


@pytest.mark.parametrize(
    ("left", "right"),
    [
        (
            """0000000000001000 <crate::kernel>:\n 1000:\t90000000 \tadrp\tx0, 2000 <crate::data>\n 1004:\t91000000 \tadd\tx0, x0, #0x120\n""",
            """0000000000009000 <crate::kernel>:\n 9000:\t90000000 \tadrp\tx0, a000 <crate::data>\n 9004:\t91000000 \tadd\tx0, x0, #0x560\n""",
        ),
        (
            """0000000000001000 <crate::kernel>:\n 1000:\t90000000 \tadrp\tx1, 2000 <crate::data>\n 1004:\tf9400020 \tldr\tx0, [x1, #0x120]\n 1008:\tf9000420 \tstr\tx0, [x1, #0x8]\n""",
            """0000000000009000 <crate::kernel>:\n 9000:\t90000000 \tadrp\tx1, a000 <crate::data>\n 9004:\tf9400020 \tldr\tx0, [x1, #0x560]\n 9008:\tf9000420 \tstr\tx0, [x1, #0x8]\n""",
        ),
        (
            """0000000000001000 <crate::kernel>:\n 1000:\t58000000 \tldr\tx0, 1800 <crate::literal>\n""",
            """0000000000009000 <crate::kernel>:\n 9000:\t58000000 \tldr\tx0, 9800 <crate::literal>\n""",
        ),
    ],
)
def test_aarch64_complete_pc_relative_materialization_normalizes(left, right):
    assert (
        extractor.normalize_objdump(left, "aarch64")["hash"]
        == extractor.normalize_objdump(right, "aarch64")["hash"]
    )


def test_aarch64_adrp_nearest_symbol_addend_is_not_semantic():
    left = """0000000000001000 <crate::kernel>:
 1000:\t90000000 \tadrp\tx0, 2000 <GCC_except_table0+0x16720>
 1004:\t91000000 \tadd\tx0, x0, #0x120
"""
    right = left.replace("<GCC_except_table0+0x16720>", "<GCC_except_table0+0x166b0>")
    assert (
        extractor.normalize_objdump(left, "aarch64")["hash"]
        == extractor.normalize_objdump(right, "aarch64")["hash"]
    )


def test_aarch64_adrp_data_symbol_addend_remains_significant():
    original = """0000000000001000 <crate::kernel>:
 1000:\t90000000 \tadrp\tx0, 2000 <crate::data+0x1000>
 1004:\t91000000 \tadd\tx0, x0, #0x120
"""
    changed = original.replace("<crate::data+0x1000>", "<crate::data+0x2000>")
    assert (
        extractor.normalize_objdump(original, "aarch64")["hash"]
        != extractor.normalize_objdump(changed, "aarch64")["hash"]
    )


def test_aarch64_adr_exact_symbol_addend_remains_significant():
    original = """0000000000001000 <crate::kernel>:
 1000:\t10000000 \tadr\tx0, 1100 <crate::data+0x4>
"""
    changed = original.replace("<crate::data+0x4>", "<crate::data+0x8>")
    assert (
        extractor.normalize_objdump(original, "aarch64")["hash"]
        != extractor.normalize_objdump(changed, "aarch64")["hash"]
    )


def test_aarch64_branch_symbol_addend_remains_significant():
    original = """0000000000001000 <crate::kernel>:
 1000:\t14000000 \tb\t1100 <crate::kernel+0x100>
"""
    changed = original.replace("<crate::kernel+0x100>", "<crate::kernel+0x104>")
    assert (
        extractor.normalize_objdump(original, "aarch64")["hash"]
        != extractor.normalize_objdump(changed, "aarch64")["hash"]
    )


def test_aarch64_non_pc_relative_immediate_remains_significant():
    original = (
        """0000000000001000 <crate::kernel>:\n 1000:\t91004000 \tadd\tx0, x0, #0x10\n"""
    )
    changed = original.replace("#0x10", "#0x20")
    assert (
        extractor.normalize_objdump(original, "aarch64")["hash"]
        != extractor.normalize_objdump(changed, "aarch64")["hash"]
    )


def test_aarch64_overwrite_kills_consumed_adrp_state():
    original = """0000000000001000 <crate::kernel>:
 1000:\t90000001 \tadrp\tx1, 2000 <crate::data>
 1004:\tf9400020 \tldr\tx0, [x1, #0x120]
 1008:\td2800001 \tmov\tx1, #0x0
 100c:\t91002022 \tadd\tx2, x1, #0x8
"""
    changed = original.replace("#0x8\n", "#0x10\n")
    assert (
        extractor.normalize_objdump(original, "aarch64")["hash"]
        != extractor.normalize_objdump(changed, "aarch64")["hash"]
    )


def test_aarch64_resolved_address_field_offset_remains_significant():
    original = """0000000000001000 <crate::kernel>:
 1000:\t90000001 \tadrp\tx1, 2000 <crate::data>
 1004:\t91048021 \tadd\tx1, x1, #0x120
 1008:\tf9400420 \tldr\tx0, [x1, #0x8]
"""
    changed = original.replace("#0x8]", "#0x10]")
    assert (
        extractor.normalize_objdump(original, "aarch64")["hash"]
        != extractor.normalize_objdump(changed, "aarch64")["hash"]
    )


@pytest.mark.parametrize(
    "writeback",
    [
        "str x0, [x1], #0x8",
        "ldr x0, [x1, #0x8]!",
        "stp x0, x3, [x1], #0x10",
        "ldp x0, x3, [x1, #0x10]!",
    ],
)
def test_aarch64_memory_writeback_kills_pending_adrp(writeback):
    original = (
        "0000000000001000 <crate::kernel>:\n"
        " 1000:\t90000001 \tadrp\tx1, 2000 <crate::data>\n"
        f" 1004:\tf8008420 \t{writeback}\n"
        " 1008:\t91002022 \tadd\tx2, x1, #0x8\n"
    )
    changed = original.replace("add\tx2, x1, #0x8", "add\tx2, x1, #0x10")
    assert (
        extractor.normalize_objdump(original, "aarch64")["hash"]
        != extractor.normalize_objdump(changed, "aarch64")["hash"]
    )


@pytest.mark.parametrize(
    ("original_writeback", "changed_writeback"),
    [
        ("str x0, [x1], #0x8", "str x0, [x1], #0x10"),
        ("ldr x0, [x1, #0x8]!", "ldr x0, [x1, #0x10]!"),
        ("stp x0, x3, [x1], #0x10", "stp x0, x3, [x1], #0x20"),
        ("ldp x0, x3, [x1, #0x10]!", "ldp x0, x3, [x1, #0x20]!"),
    ],
)
def test_aarch64_memory_writeback_offset_remains_significant(
    original_writeback, changed_writeback
):
    original = (
        f"0000000000001000 <crate::kernel>:\n 1000:\tf8008420 \t{original_writeback}\n"
    )
    changed = original.replace(original_writeback, changed_writeback)
    assert (
        extractor.normalize_objdump(original, "aarch64")["hash"]
        != extractor.normalize_objdump(changed, "aarch64")["hash"]
    )


@pytest.mark.parametrize(
    ("call_instruction", "direct_calls", "indirect_calls"),
    [
        (
            "bl\t1100 <crate::helper>",
            ["<pc-rel> <crate::helper>"],
            [],
        ),
        ("blr\tx9", [], ["x9"]),
    ],
)
def test_aarch64_calls_kill_caller_saved_adrp_state(
    call_instruction, direct_calls, indirect_calls
):
    original = (
        "0000000000001000 <crate::kernel>:\n"
        " 1000:\t90000001 \tadrp\tx1, 2000 <crate::data>\n"
        f" 1004:\t94000000 \t{call_instruction}\n"
        " 1008:\t91002022 \tadd\tx2, x1, #0x8\n"
    )
    changed = original.replace("add\tx2, x1, #0x8", "add\tx2, x1, #0x10")
    normalized = extractor.normalize_objdump(original, "aarch64")
    assert normalized["direct_calls"] == direct_calls
    assert normalized["indirect_calls"] == indirect_calls
    assert normalized["hash"] != extractor.normalize_objdump(changed, "aarch64")["hash"]


@pytest.mark.parametrize(
    ("instruction", "operand"),
    [
        ("blr x9", "x9"),
        ("blraa x9, x10", "x9, x10"),
        ("blrab x9, x10", "x9, x10"),
        ("blraaz x9", "x9"),
        ("blrabz x9", "x9"),
    ],
)
def test_aarch64_blr_variants_are_indirect_calls(instruction, operand):
    original = (
        "0000000000001000 <crate::kernel>:\n"
        " 1000:\t90000001 \tadrp\tx1, 2000 <crate::data>\n"
        f" 1004:\td63f0120 \t{instruction}\n"
        " 1008:\t91002022 \tadd\tx2, x1, #0x8\n"
    )
    changed = original.replace("add\tx2, x1, #0x8", "add\tx2, x1, #0x10")
    normalized = extractor.normalize_objdump(original, "aarch64")
    assert normalized["direct_calls"] == []
    assert normalized["indirect_calls"] == [operand]
    assert normalized["hash"] != extractor.normalize_objdump(changed, "aarch64")["hash"]


@pytest.mark.parametrize(
    ("arch", "snippet", "direct", "indirect"),
    [
        (
            "aarch64",
            """0000000000001000 <crate::kernel>:\n 1000:\t94000000 \tbl\t1100 <crate::direct>\n 1004:\td63f0000 \tblr\tx0\n""",
            ["<pc-rel> <crate::direct>"],
            ["x0"],
        ),
        (
            "x86_64",
            """0000000000001000 <crate::kernel>:\n 1000:\te8 00 00 00 00 \tcall\t1100 <crate::direct>\n 1005:\tff d0 \tcall\t*%rax\n""",
            ["<pc-rel> <crate::direct>"],
            ["*%rax"],
        ),
    ],
)
def test_direct_and_indirect_calls_are_separate(arch, snippet, direct, indirect):
    normalized = extractor.normalize_objdump(snippet, arch)
    assert normalized["direct_calls"] == direct
    assert normalized["indirect_calls"] == indirect


def test_section_parser_records_index_name_and_actual_alignment():
    sections = extractor.parse_sections(
        "  3 .text.kernel  00000020  0000000000001000  0000000000001000  00001000  2**12\n"
    )
    assert sections == [
        {
            "index": 4,
            "name": ".text.kernel",
            "size": 0x20,
            "vma": 0x1000,
            "file_offset": 0x1000,
            "alignment": 4096,
        }
    ]


def test_linker_generated_veneer_and_thunk_inventory_is_explicit():
    symbols = extractor.parse_nm(
        "0000000000001000 0000000000000010 t crate::kernel\n"
        "0000000000002000 0000000000000008 t __AArch64AbsLongThunk_target\n"
        "0000000000003000 0000000000000008 t helper.veneer\n"
    )
    inventory = extractor.inventory_linker_generated_symbols(symbols)
    assert [item["name"] for item in inventory] == [
        "__AArch64AbsLongThunk_target",
        "helper.veneer",
    ]
