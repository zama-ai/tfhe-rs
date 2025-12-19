"""
All tables are named after their label in the whitepaper.
"""

from benchmark_specs import (
    AtomicPattern,
    ErrorFailureProbability,
    GroupingFactor,
    OperandSize,
    Precision,
)
from formatters.common import (
    ElementType,
    LatexArraySection,
    LatexColumnElement,
    LatexRowElement,
    LatexTable,
)

# Table 2 is core crypto KS/KS-PBS/PBS for 2_2_128  and 2_2_64
# Table 3 is  core crypto KS/KS-PBS/PBS in the multibit case for V1_4_PARAM_MULTI_BIT_GROUP_X_MESSAGE_Y_CARRY_Y_KS_PBS_GAUSSIAN_2MZ  for X in [2,3,4], Y in [1,2,3,4] and Z in [64, 128]
# Table 5 is special case with 1_1_64, 2_2_64, 4_4_64
# Table 6 is special case with 1_1_128, 2_2_128, 4_4_128
# Table 7 is the multibit special case with V1_4_PARAM_MULTI_BIT_GROUP_X_MESSAGE_Y_CARRY_Y_KS_PBS_GAUSSIAN_2MZ  for X in [2,3,4], Y = 2, Z = 64.
# Table 8 is special case for 2_2_128 and 2_2_128 KS_32 <--- changed
# Table 9, 10, 11, 12 are the integer ops for 2_2_64_KS32 and 2_2_128_KS32
# Table 13 is compression (which I believe was in special case?) for the 64/128 compression parameters

# ------------------
# LaTex row elements
# ------------------


def _get_operation_elem(
    operation_name: str,
    latex_str: str,
    display_element: bool = True,
    display_as_column: bool = False,
    column_span: int = 1,
) -> LatexRowElement:
    return LatexRowElement(
        operation_name,
        ElementType.Operation,
        latex_str,
        display_element=display_element,
        display_as_column=display_as_column,
        column_span=column_span,
    )


PFAIL_2M64_ELEM = LatexRowElement(
    ErrorFailureProbability.TWO_MINUS_64, ElementType.ParamComponent, r"\(2^{-64}\)"
)
PFAIL_2M128_ELEM = LatexRowElement(
    ErrorFailureProbability.TWO_MINUS_128, ElementType.ParamComponent, r"\(2^{-128}\)"
)

PFAIL_2M64_HIDDEN_ELEM = LatexRowElement(
    ErrorFailureProbability.TWO_MINUS_64,
    ElementType.ParamComponent,
    r"\(2^{-64}\)",
    display_element=False,
)
PFAIL_2M128_HIDDEN_ELEM = LatexRowElement(
    ErrorFailureProbability.TWO_MINUS_128,
    ElementType.ParamComponent,
    r"\(2^{-128}\)",
    display_element=False,
)

M1C1_PFAIL_64_ELEM = LatexRowElement(
    Precision.M1C1,
    ElementType.ParamComponent,
    r"${\tt 1\_1\_64}$",
)
M2C2_PFAIL_64_ELEM = LatexRowElement(
    Precision.M2C2,
    ElementType.ParamComponent,
    r"${\tt 2\_2\_64}$",
)
M4C4_PFAIL_64_ELEM = LatexRowElement(
    Precision.M4C4,
    ElementType.ParamComponent,
    r"${\tt 4\_4\_64}$",
)
M1C1_PFAIL_128_ELEM = LatexRowElement(
    Precision.M1C1,
    ElementType.ParamComponent,
    r"${\tt 1\_1\_128}$",
)
M2C2_PFAIL_128_ELEM = LatexRowElement(
    Precision.M2C2,
    ElementType.ParamComponent,
    r"${\tt 2\_2\_128}$",
)
M2C2_PFAIL_128_KS32_ELEM = LatexRowElement(
    Precision.M2C2,
    ElementType.ParamComponent,
    r"${\tt 2\_2\_128\_KS32}$",
)
M4C4_PFAIL_128_ELEM = LatexRowElement(
    Precision.M4C4,
    ElementType.ParamComponent,
    r"${\tt 4\_4\_128}$",
)

KSPBS_HIDDEN_ELEM = LatexRowElement(
    AtomicPattern.KSPBS,
    ElementType.ParamComponent,
    "",
    display_element=False,
)
KS32PBS_HIDDEN_ELEM = LatexRowElement(
    AtomicPattern.KS32PBS,
    ElementType.ParamComponent,
    "",
    display_element=False,
)

KS_OP_ELEM = _get_operation_elem("keyswitch", r"\ks")
PBS_OP_ELEM = _get_operation_elem("pbs_mem_optimized", r"\pbs")
MB_PBS_OP_ELEM = _get_operation_elem("multi_bit_deterministic_pbs", r"\mbpbs")
KSPBS_OP_ELEM = _get_operation_elem("ks_pbs", r"\kspbs")
KS_MB_PBS_OP_ELEM = _get_operation_elem("multi_bit_deterministic_ks_pbs", r"\ksmbpbs")

ADD_OP_HIDDEN_ELEM = _get_operation_elem(
    "unsigned_add_parallelized", "Addition", display_element=False
)
BITAND_OP_HIDDEN_ELEM = _get_operation_elem(
    "unsigned_bitand_parallelized", "Bitwise AND", display_element=False
)
MUL_OP_HIDDEN_ELEM = _get_operation_elem(
    "unsigned_mul_parallelized", "Multiplication", display_element=False
)

# ---------------------
# LaTex column elements
# ---------------------


def _get_precision_column_element(
    precision: Precision, sub_cols: list[LatexColumnElement] = None
) -> LatexColumnElement:
    return LatexColumnElement(
        precision, ElementType.ParamComponent, "", sub_cols=sub_cols
    )


def _get_grouping_factor_column_element(
    grouping_factor: GroupingFactor,
) -> LatexColumnElement:
    return LatexColumnElement(
        grouping_factor, ElementType.ParamComponent, str(grouping_factor)
    )


def _get_operand_size_column_element(
    op_size: int,
) -> LatexColumnElement:
    return LatexColumnElement(
        OperandSize(op_size), ElementType.SizeComponent, str(op_size)
    )


# Operand size is set to the value of the message size since it's stored as is in the database.
M1C1_COL_ELEM = _get_precision_column_element(
    Precision.M1C1, sub_cols=[_get_operand_size_column_element(1)]
)
M2C2_COL_ELEM = _get_precision_column_element(
    Precision.M2C2, sub_cols=[_get_operand_size_column_element(2)]
)
M3C3_COL_ELEM = _get_precision_column_element(
    Precision.M3C3, sub_cols=[_get_operand_size_column_element(3)]
)
M4C4_COL_ELEM = _get_precision_column_element(
    Precision.M4C4, sub_cols=[_get_operand_size_column_element(4)]
)

ALL_GROUPING_FACTORS_ELEM = [
    _get_grouping_factor_column_element(GroupingFactor.Two),
    _get_grouping_factor_column_element(GroupingFactor.Three),
    _get_grouping_factor_column_element(GroupingFactor.Four),
]

M1C1_ALL_GF_COL_ELEM = _get_precision_column_element(
    Precision.M1C1, sub_cols=ALL_GROUPING_FACTORS_ELEM
)
M2C2_ALL_GF_COL_ELEM = _get_precision_column_element(
    Precision.M2C2, sub_cols=ALL_GROUPING_FACTORS_ELEM
)
M3C3_ALL_GF_COL_ELEM = _get_precision_column_element(
    Precision.M3C3, sub_cols=ALL_GROUPING_FACTORS_ELEM
)
M4C4_ALL_GF_COL_ELEM = _get_precision_column_element(
    Precision.M4C4, sub_cols=ALL_GROUPING_FACTORS_ELEM
)

ALL_OPERAND_SIZES_ELEM = [
    _get_operand_size_column_element(4),
    _get_operand_size_column_element(8),
    _get_operand_size_column_element(16),
    _get_operand_size_column_element(32),
    _get_operand_size_column_element(64),
    _get_operand_size_column_element(128),
    _get_operand_size_column_element(256),
]

OP_AS_COL_SPAN = len(ALL_OPERAND_SIZES_ELEM) + 1

# Operations used in integer special case tables
ADD_OP_AS_COL_ELEM = _get_operation_elem(
    "unsigned_add_parallelized",
    "Addition",
    display_as_column=True,
    column_span=OP_AS_COL_SPAN,
)
BITAND_OP_AS_COL_ELEM = _get_operation_elem(
    "unsigned_bitand_parallelized",
    "Bitwise AND",
    display_as_column=True,
    column_span=OP_AS_COL_SPAN,
)
MUL_OP_AS_COL_ELEM = _get_operation_elem(
    "unsigned_mul_parallelized",
    "Multiplication",
    display_as_column=True,
    column_span=OP_AS_COL_SPAN,
)


# TODO On a besoin de garder quelque part la raw_value du bench (après conversion str) pour effectuer des comparaisons et trouver le minimum sur un groupe de résultats
# TODO Calculer les lignes "amortized" pour TABLE_2

# -----------------------
# LaTex table definitions
# -----------------------

TABLE_PBS_BENCH = LatexTable(
    [
        LatexArraySection(
            [
                [
                    PFAIL_2M64_ELEM,
                    KS_OP_ELEM,
                    M1C1_COL_ELEM,
                    M2C2_COL_ELEM,
                    M3C3_COL_ELEM,
                    M4C4_COL_ELEM,
                ],
                [
                    PFAIL_2M64_ELEM,
                    PBS_OP_ELEM,
                    M1C1_COL_ELEM,
                    M2C2_COL_ELEM,
                    M3C3_COL_ELEM,
                    M4C4_COL_ELEM,
                ],
                [
                    PFAIL_2M64_ELEM,
                    KSPBS_OP_ELEM,
                    M1C1_COL_ELEM,
                    M2C2_COL_ELEM,
                    M3C3_COL_ELEM,
                    M4C4_COL_ELEM,
                ],
                # [PFAIL_2M64_ELEM, KSPBS_OP_ELEM_AMORTIZED, M1C1_COL_ELEM, M2C2_COL_ELEM, M3C3_COL_ELEM, M4C4_COL_ELEM],  # TODO line de données à calculer depuis les résultats
            ]
        ),
        LatexArraySection(
            [
                [
                    PFAIL_2M128_ELEM,
                    KS_OP_ELEM,
                    M1C1_COL_ELEM,
                    M2C2_COL_ELEM,
                    M3C3_COL_ELEM,
                    M4C4_COL_ELEM,
                ],
                [
                    PFAIL_2M128_ELEM,
                    PBS_OP_ELEM,
                    M1C1_COL_ELEM,
                    M2C2_COL_ELEM,
                    M3C3_COL_ELEM,
                    M4C4_COL_ELEM,
                ],
                [
                    PFAIL_2M128_ELEM,
                    KSPBS_OP_ELEM,
                    M1C1_COL_ELEM,
                    M2C2_COL_ELEM,
                    M3C3_COL_ELEM,
                    M4C4_COL_ELEM,
                ],
                # [PFAIL_2M128_ELEM, KSPBS_OP_ELEM_AMORTIZED, M1C1_COL_ELEM, M2C2_COL_ELEM, Precision.M3C3, M4C4_COL_ELEM],
            ]
        ),
    ]
)

TABLE_BENCH_MULTIBIT_BY_PRECISION = LatexTable(
    [
        LatexArraySection(
            [
                [
                    PFAIL_2M64_ELEM,
                    KS_OP_ELEM,
                    M1C1_ALL_GF_COL_ELEM,
                    M2C2_ALL_GF_COL_ELEM,
                    M3C3_ALL_GF_COL_ELEM,
                    M4C4_ALL_GF_COL_ELEM,
                ],
                [
                    PFAIL_2M64_ELEM,
                    MB_PBS_OP_ELEM,
                    M1C1_ALL_GF_COL_ELEM,
                    M2C2_ALL_GF_COL_ELEM,
                    M3C3_ALL_GF_COL_ELEM,
                    M4C4_ALL_GF_COL_ELEM,
                ],
                [
                    PFAIL_2M64_ELEM,
                    KS_MB_PBS_OP_ELEM,
                    M1C1_ALL_GF_COL_ELEM,
                    M2C2_ALL_GF_COL_ELEM,
                    M3C3_ALL_GF_COL_ELEM,
                    M4C4_ALL_GF_COL_ELEM,
                ],
            ]
        ),
        LatexArraySection(
            [
                [
                    PFAIL_2M128_ELEM,
                    KS_OP_ELEM,
                    M1C1_ALL_GF_COL_ELEM,
                    M2C2_ALL_GF_COL_ELEM,
                    M3C3_ALL_GF_COL_ELEM,
                    M4C4_ALL_GF_COL_ELEM,
                ],
                [
                    PFAIL_2M128_ELEM,
                    MB_PBS_OP_ELEM,
                    M1C1_ALL_GF_COL_ELEM,
                    M2C2_ALL_GF_COL_ELEM,
                    M3C3_ALL_GF_COL_ELEM,
                    M4C4_ALL_GF_COL_ELEM,
                ],
                [
                    PFAIL_2M128_ELEM,
                    KS_MB_PBS_OP_ELEM,
                    M1C1_ALL_GF_COL_ELEM,
                    M2C2_ALL_GF_COL_ELEM,
                    M3C3_ALL_GF_COL_ELEM,
                    M4C4_ALL_GF_COL_ELEM,
                ],
            ]
        ),
    ]
)

TABLE_COMPARISON_OPERATIONS_PRECISION_PFAIL64 = LatexTable(
    [
        LatexArraySection(
            [
                BITAND_OP_AS_COL_ELEM,
                [
                    BITAND_OP_HIDDEN_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    M1C1_PFAIL_64_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    BITAND_OP_HIDDEN_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    M2C2_PFAIL_64_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    BITAND_OP_HIDDEN_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    M4C4_PFAIL_64_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                ADD_OP_AS_COL_ELEM,
                [
                    ADD_OP_HIDDEN_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    M1C1_PFAIL_64_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    ADD_OP_HIDDEN_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    M2C2_PFAIL_64_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    ADD_OP_HIDDEN_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    M4C4_PFAIL_64_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                MUL_OP_AS_COL_ELEM,
                [
                    MUL_OP_HIDDEN_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    M1C1_PFAIL_64_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    MUL_OP_HIDDEN_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    M2C2_PFAIL_64_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    MUL_OP_HIDDEN_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    M4C4_PFAIL_64_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
            ]
        ),
    ]
)

TABLE_COMPARISON_OPERATIONS_PRECISION_PFAIL128 = LatexTable(
    [
        LatexArraySection(
            [
                BITAND_OP_AS_COL_ELEM,
                [
                    BITAND_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M1C1_PFAIL_128_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    BITAND_OP_HIDDEN_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    M2C2_PFAIL_64_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    BITAND_OP_HIDDEN_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    M4C4_PFAIL_64_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                ADD_OP_AS_COL_ELEM,
                [
                    ADD_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M1C1_PFAIL_128_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    ADD_OP_HIDDEN_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    M2C2_PFAIL_128_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    ADD_OP_HIDDEN_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    M4C4_PFAIL_128_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                MUL_OP_AS_COL_ELEM,
                [
                    MUL_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M1C1_PFAIL_128_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    MUL_OP_HIDDEN_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    M2C2_PFAIL_128_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    MUL_OP_HIDDEN_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    M4C4_PFAIL_128_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
            ]
        ),
    ]
)

TABLE_COMPARISON_OPERATIONS_BOOTSTRAPPING = LatexTable(
    [
        LatexArraySection(
            [
                BITAND_OP_AS_COL_ELEM,
                [
                    BITAND_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M1C1_PFAIL_128_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    BITAND_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M2C2_PFAIL_128_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    BITAND_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M4C4_PFAIL_128_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                ADD_OP_AS_COL_ELEM,
                [
                    ADD_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M1C1_PFAIL_128_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    ADD_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M2C2_PFAIL_128_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    ADD_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M4C4_PFAIL_128_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                MUL_OP_AS_COL_ELEM,
                [
                    MUL_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M1C1_PFAIL_128_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    MUL_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M2C2_PFAIL_128_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    MUL_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M4C4_PFAIL_128_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
            ]
        ),
    ]
)


TABLE_COMPARISON_OPERATIONS_BOOTSTRAPPING128KS32 = LatexTable(
    [
        LatexArraySection(
            [
                BITAND_OP_AS_COL_ELEM,
                [
                    BITAND_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KSPBS_HIDDEN_ELEM,
                    M2C2_PFAIL_128_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    BITAND_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_PFAIL_128_KS32_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                ADD_OP_AS_COL_ELEM,
                [
                    ADD_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KSPBS_HIDDEN_ELEM,
                    M2C2_PFAIL_128_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    ADD_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_PFAIL_128_KS32_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                MUL_OP_AS_COL_ELEM,
                [
                    MUL_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KSPBS_HIDDEN_ELEM,
                    M2C2_PFAIL_128_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    MUL_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_PFAIL_128_KS32_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
            ]
        ),
    ]
)

# # No LaTex set for this table.
# table_plaintext_ciphertext_ops_pfail64_ks32 = LatexTable()
#
# # No LaTex set for this table.
# table_plaintext_ciphertext_ops_pfail128_ks32 = LatexTable()
#
# # No LaTex set for this table.
# table_ciphertext_ciphertext_ops_pfail64_ks32 = LatexTable()
#
# # No LaTex set for this table.
# table_ciphertext_ciphertext_ops_pfail128_ks32 = LatexTable()
#
# table_compression_benchmarks = LatexTable()
