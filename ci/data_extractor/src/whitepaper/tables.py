"""
All tables are named after their label in the whitepaper.
"""

from PIL.IptcImagePlugin import COMPRESSION
from benchmark_specs import (
    AtomicPattern,
    ErrorFailureProbability,
    GroupingFactor,
    OperandSize,
    Precision,
    PBSKind,
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
# Table 7 is the multibit special case with V1_4_PARAM_MULTI_BIT_GROUP_X_MESSAGE_Y_CARRY_Y_KS_PBS_GAUSSIAN_2MZ  for X in [2,3,4], Y = 2, Z = 128.
# Table 8 is special case for 2_2_128 and 2_2_128 KS_32
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


def _get_cref_elem(cref_name) -> LatexRowElement:
    return LatexRowElement(cref_name, ElementType.Reference, f"\\cref{{{cref_name}}}")


PFAIL_2M64_ELEM = LatexRowElement(
    ErrorFailureProbability.TWO_MINUS_64, ElementType.ParamComponent, r"\(2^{-64}\)"
)
PFAIL_2M128_ELEM = LatexRowElement(
    ErrorFailureProbability.TWO_MINUS_128, ElementType.ParamComponent, r"\(2^{-128}\)"
)

PFAIL_2M64_HIDDEN_ELEM = LatexRowElement(
    ErrorFailureProbability.TWO_MINUS_64,
    ElementType.ParamComponent,
    "",
    display_element=False,
)
PFAIL_2M128_HIDDEN_ELEM = LatexRowElement(
    ErrorFailureProbability.TWO_MINUS_128,
    ElementType.ParamComponent,
    "",
    display_element=False,
)

CLASSICAL_PBS_HIDDEN_ELEM = LatexRowElement(
    PBSKind.Classical,
    ElementType.ParamComponent,
    "",
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

M2C2_PFAIL_128_GF_2_ELEM = LatexRowElement(
    GroupingFactor.Two,
    ElementType.ParamComponent,
    r"${\tt 2\_2\_128\_multibit2}$",
)

M2C2_PFAIL_128_GF_3_ELEM = LatexRowElement(
    GroupingFactor.Three,
    ElementType.ParamComponent,
    r"${\tt 2\_2\_128\_multibit3}$",
)

M2C2_PFAIL_128_GF_4_ELEM = LatexRowElement(
    GroupingFactor.Four,
    ElementType.ParamComponent,
    r"${\tt 2\_2\_128\_multibit4}$",
)

M2C2_HIDDEN_ELEM = LatexRowElement(
    Precision.M2C2,
    ElementType.ParamComponent,
    "",
    display_element=False,
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

# ----------------------------
# Operations as LaTex elements
# ----------------------------

KS_OP_ELEM = _get_operation_elem("keyswitch", r"\ks")
PBS_OP_ELEM = _get_operation_elem("pbs_mem_optimized", r"\pbs")
MB_PBS_OP_ELEM = _get_operation_elem("multi_bit_deterministic_pbs", r"\mbpbs")
KSPBS_OP_ELEM = _get_operation_elem("ks_pbs", r"\kspbs")
KS_MB_PBS_OP_ELEM = _get_operation_elem("multi_bit_deterministic_ks_pbs", r"\ksmbpbs")

ADD_OP_ELEM = _get_operation_elem(
    "unsigned_add_parallelized", r"\texttt{unsigned\_add\_parallelized}"
)
SUB_OP_ELEM = _get_operation_elem(
    "unsigned_sub_parallelized", r"\texttt{unsigned\_sub\_parallelized}"
)
BITNOT_OP_ELEM = _get_operation_elem(
    "unsigned_bitnot", r"\texttt{unsigned\_bitnot\_non\_parallelized}"
)
BITAND_OP_ELEM = _get_operation_elem(
    "unsigned_bitand_parallelized",
    r"\texttt{unsigned\_bit\{and,or,xor\}\_parallelized}",
)
DIV_REM_OP_ELEM = _get_operation_elem(
    "unsigned_div_rem_parallelized", r"\texttt{unsigned\_div\_rem\_parallelized}"
)
EQ_OP_ELEM = _get_operation_elem(
    "unsigned_eq_parallelized", r"\texttt{unsigned\_\{eq,ne\}\_parallelized}"
)
COMPARISON_OP_ELEM = _get_operation_elem(
    "unsigned_gt_parallelized", r"\texttt{unsigned\_\{ge,gt,le,lt\}\_parallelized}"
)
IF_THEN_ELSE_OP_ELEM = _get_operation_elem(
    "unsigned_if_then_else_parallelized",
    r"\texttt{unsigned\_if\_then\_else\_parallelized}",
)
NEGATION_OP_ELEM = _get_operation_elem(
    "unsigned_neg_parallelized", r"\texttt{unsigned\_neg\_parallelized}"
)
MUL_OP_ELEM = _get_operation_elem(
    "unsigned_mul_parallelized", r"\texttt{unsigned\_mul\_parallelized}"
)
SCALAR_REM_OP_ELEM = _get_operation_elem(
    "unsigned_scalar_rem_parallelized", r"\texttt{unsigned\_scalar\_rem\_parallelized}"
)
SHIFT_OP_ELEM = _get_operation_elem(
    "unsigned_left_shift_parallelized",
    r"\texttt{unsigned\_\{left,right\}\_shift\_parallelized}",
)
ROTATE_OP_ELEM = _get_operation_elem(
    "unsigned_rotate_left_parallelized",
    r"\texttt{unsigned\_\{left,right\}\_rotate\_parallelized}",
)
OVERFLOWING_ADD_OP_ELEM = _get_operation_elem(
    "unsigned_unsigned_overflowing_add_parallelized",
    r"\texttt{unsigned\_overflowing\_add\_parallelized}",
)
OVERFLOWING_SUB_OP_ELEM = _get_operation_elem(
    "unsigned_unsigned_overflowing_sub_parallelized",
    r"\texttt{unsigned\_overflowing\_sub\_parallelized}",
)
OVERFLOWING_MUL_OP_ELEM = _get_operation_elem(
    "unsigned_unsigned_overflowing_mul_parallelized",
    r"\texttt{unsigned\_overflowing\_mul\_parallelized}",
)
SUM_CIPHERTEXTS_5_CTXTS_OP_ELEM = _get_operation_elem(
    "unsigned_sum_ciphertexts_parallelized_5_ctxts",
    r"\texttt{unsigned\_sum\_ciphertexts\_parallelized\_5\_ctxts\_non\_parallelized}",
)
SUM_CIPHERTEXTS_10_CTXTS_OP_ELEM = _get_operation_elem(
    "unsigned_sum_ciphertexts_parallelized_10_ctxts",
    r"\texttt{unsigned\_sum\_ciphertexts\_parallelized\_10\_ctxts\_non\_parallelized}",
)
SUM_CIPHERTEXTS_20_CTXTS_OP_ELEM = _get_operation_elem(
    "unsigned_sum_ciphertexts_parallelized_20_ctxts",
    r"\texttt{unsigned\_sum\_ciphertexts\_parallelized\_20\_ctxts\_non\_parallelized}",
)
COMPRESSION_OP_ELEM = _get_operation_elem("unsigned_packing_compression_pack", "Compress")
DECOMPRESSION_OP_ELEM = _get_operation_elem("unsigned_packing_compression_unpack", "Decompress")

OVERFLOWING_SCALAR_ADD_OP_ELEM = _get_operation_elem(
    "unsigned_unsigned_overflowing_scalar_add_parallelized",
    r"\texttt{unsigned\_overflowing\_scalar\_add\_parallelized}",
)
OVERFLOWING_SCALAR_SUB_OP_ELEM = _get_operation_elem(
    "unsigned_unsigned_overflowing_scalar_sub_parallelized",
    r"\texttt{unsigned\_overflowing\_scalar\_sub\_parallelized}",
)
SCALAR_ADD_OP_ELEM = _get_operation_elem(
    "unsigned_scalar_add_parallelized", r"\texttt{unsigned\_scalar\_add\_parallelized}"
)
SCALAR_SUB_OP_ELEM = _get_operation_elem(
    "unsigned_scalar_sub_parallelized", r"\texttt{unsigned\_scalar\_sub\_parallelized}"
)
SCALAR_BITWISE_OP_ELEM = _get_operation_elem(
    "unsigned_scalar_bitand_parallelized",
    r"\texttt{unsigned\_scalar\_bit\{and,or,xor\}\_parallelized}",
)
SCALAR_DIV_OP_ELEM = _get_operation_elem(
    "unsigned_scalar_div_parallelized", r"\texttt{unsigned\_scalar\_div\_parallelized}"
)
SCALAR_EQ_OP_ELEM = _get_operation_elem(
    "unsigned_scalar_eq_parallelized",
    r"\texttt{unsigned\_scalar\_\{eq,ne\}\_parallelized}",
)
SCALAR_COMPARISON_OP_ELEM = _get_operation_elem(
    "unsigned_scalar_gt_parallelized",
    r"\texttt{unsigned\_scalar\_\{ge,gt,le,lt\}\_parallelized}",
)
SCALAR_MUL_OP_ELEM = _get_operation_elem(
    "unsigned_scalar_mul_parallelized", r"\texttt{unsigned\_scalar\_mul\_parallelized}"
)
SCALAR_REM_OP_ELEM = _get_operation_elem(
    "unsigned_scalar_rem_parallelized", r"\texttt{unsigned\_scalar\_rem\_parallelized}"
)
SCALAR_SHIFT_OP_ELEM = _get_operation_elem(
    "unsigned_scalar_left_shift_parallelized",
    r"\texttt{unsigned\_scalar\_\{left,right\}\_shift\_parallelized}",
)
SCALAR_ROTATE_OP_ELEM = _get_operation_elem(
    "unsigned_scalar_rotate_left_parallelized",
    r"\texttt{unsigned\_scalar\_\{left,right\}\_rotate\_parallelized}",
)

ADD_OP_HIDDEN_ELEM = _get_operation_elem(
    "unsigned_add_parallelized", "Addition", display_element=False
)
BITAND_OP_HIDDEN_ELEM = _get_operation_elem(
    "unsigned_bitand_parallelized", "Bitwise AND", display_element=False
)
MUL_OP_HIDDEN_ELEM = _get_operation_elem(
    "unsigned_mul_parallelized", "Multiplication", display_element=False
)

# --------------------
# \cref LaTex elements
# --------------------

ADD_CREF_ELEM = _get_cref_elem("alg:addition")
BITNOT_CREF_ELEM = _get_cref_elem("alg:bitwise-not")
BITWISE_CREF_ELEM = _get_cref_elem("alg:bitwise-ops")
EQ_CREF_ELEM = _get_cref_elem("alg:eq")
DIV_REM_CREF_ELEM = _get_cref_elem("alg:unsig-div-rem")
IF_THEN_ELSE_CREF_ELEM = _get_cref_elem("alg:select")
ROTATE_SHIFT_CREF_ELEM = _get_cref_elem("alg:shift-rot-encr")
MUL_CREF_ELEM = _get_cref_elem("alg:multiplication")
NEGATION_CREF_ELEM = _get_cref_elem("alg:negation")
SUB_CREF_ELEM = _get_cref_elem("alg:sub")
SUM_CIPHERTEXTS_CREF_ELEM = _get_cref_elem("alg:sum")
OVERFLOWING_CREF_ELEM = _get_cref_elem("ssec:overflow")
COMPARISON_CREF_ELEM = _get_cref_elem("alg:comparison")
COMPRESSION_REF_ELEM = _get_cref_elem("alg:compression")
DECOMPRESSION_REF_ELEM = _get_cref_elem("alg:decompression")
SCALAR_ADD_CREF_ELEM = _get_cref_elem("sssec:addition-scalar")
SCALAR_BITWISE_CREF_ELEM = _get_cref_elem("alg:scalar-bitwise")
SCALAR_DIV_CREF_ELEM = _get_cref_elem("sssec:scalar-div")
SCALAR_EQ_CREF_ELEM = _get_cref_elem("sssec:equality-scalar")
SCALAR_MUL_CREF_ELEM = _get_cref_elem("alg:scalar-multiplication")
SCALAR_SHIFT_CREF_ELEM = _get_cref_elem("alg:left_shift_scalar,alg:right_shift_scalar")
SCALAR_ROTATE_CREF_ELEM = _get_cref_elem(
    "alg:left_rotate_scalar,alg:right_rotate_scalar"
)
SCALAR_SUB_CREF_ELEM = _get_cref_elem("ssec:subtraction-scalar")


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
    "pbs_bench",
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
                # [PFAIL_2M64_ELEM, KSPBS_OP_ELEM_AMORTIZED, M1C1_COL_ELEM, M2C2_COL_ELEM, M3C3_COL_ELEM, M4C4_COL_ELEM],  # TODO data line to compute from database values
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
                # [PFAIL_2M128_ELEM, KSPBS_OP_ELEM_AMORTIZED, M1C1_COL_ELEM, M2C2_COL_ELEM, Precision.M3C3, M4C4_COL_ELEM], # TODO data line to compute from database values
            ]
        ),
    ]
)

TABLE_BENCH_MULTIBIT_BY_PRECISION = LatexTable(
    "bench_multibit_by_precision",
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
    "comparison_operations_precision_pfail64",
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
    "comparison_operations_precision_pfail128",
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
    "comparison_operations_bootstrapping",
    [
        LatexArraySection(
            [
                BITAND_OP_AS_COL_ELEM,
                [
                    BITAND_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M2C2_PFAIL_128_ELEM,
                    CLASSICAL_PBS_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    BITAND_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M2C2_PFAIL_128_GF_2_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    BITAND_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M2C2_PFAIL_128_GF_3_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    BITAND_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M2C2_PFAIL_128_GF_4_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                ADD_OP_AS_COL_ELEM,
                [
                    ADD_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M2C2_PFAIL_128_ELEM,
                    CLASSICAL_PBS_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    ADD_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M2C2_PFAIL_128_GF_2_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    ADD_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M2C2_PFAIL_128_GF_3_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    ADD_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M2C2_PFAIL_128_GF_4_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                MUL_OP_AS_COL_ELEM,
                [
                    MUL_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M2C2_PFAIL_128_ELEM,
                    CLASSICAL_PBS_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    MUL_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M2C2_PFAIL_128_GF_2_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    MUL_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M2C2_PFAIL_128_GF_3_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    MUL_OP_HIDDEN_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    M2C2_PFAIL_128_GF_4_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
            ]
        ),
    ]
)


TABLE_COMPARISON_OPERATIONS_BOOTSTRAPPING128KS32 = LatexTable(
    "comparison_operations_bootstrapping128ks32",
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

# No LaTex label set for this table.
TABLE_PLAINTEXT_CIPHERTEXT_OPS_PFAIL64_KS32 = LatexTable(
    "plaintext_ciphertext_ops_pfail64_ks32",
    [
        LatexArraySection(
            [
                [
                    OVERFLOWING_SCALAR_ADD_OP_ELEM,
                    OVERFLOWING_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    OVERFLOWING_SCALAR_SUB_OP_ELEM,
                    OVERFLOWING_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_ADD_OP_ELEM,
                    SCALAR_ADD_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_BITWISE_OP_ELEM,
                    SCALAR_BITWISE_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_DIV_OP_ELEM,
                    SCALAR_DIV_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_EQ_OP_ELEM,
                    SCALAR_EQ_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_COMPARISON_OP_ELEM,
                    COMPARISON_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_MUL_OP_ELEM,
                    SCALAR_MUL_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_REM_OP_ELEM,
                    SCALAR_DIV_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_SHIFT_OP_ELEM,
                    SCALAR_SHIFT_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_ROTATE_OP_ELEM,
                    SCALAR_ROTATE_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_SUB_OP_ELEM,
                    SCALAR_SUB_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
            ]
        ),
    ]
)

# No LaTex label set for this table.
TABLE_PLAINTEXT_CIPHERTEXT_OPS_PFAIL128_KS32 = LatexTable(
    "plaintext_ciphertext_ops_pfail128_ks32",
    [
        LatexArraySection(
            [
                [
                    OVERFLOWING_SCALAR_ADD_OP_ELEM,
                    OVERFLOWING_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    OVERFLOWING_SCALAR_SUB_OP_ELEM,
                    OVERFLOWING_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_ADD_OP_ELEM,
                    SCALAR_ADD_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_BITWISE_OP_ELEM,
                    SCALAR_BITWISE_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_DIV_OP_ELEM,
                    SCALAR_DIV_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_EQ_OP_ELEM,
                    SCALAR_EQ_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_COMPARISON_OP_ELEM,
                    COMPARISON_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_MUL_OP_ELEM,
                    SCALAR_MUL_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_REM_OP_ELEM,
                    SCALAR_DIV_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_SHIFT_OP_ELEM,
                    SCALAR_SHIFT_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_ROTATE_OP_ELEM,
                    SCALAR_ROTATE_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SCALAR_SUB_OP_ELEM,
                    SCALAR_SUB_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
            ]
        ),
    ]
)

# No LaTex label set for this table.
TABLE_CIPHERTEXT_CIPHERTEXT_OPS_PFAIL64_KS32 = LatexTable(
    "ciphertext_ciphertext_ops_pfail64_ks32",
    [
        LatexArraySection(
            [
                [
                    ADD_OP_ELEM,
                    ADD_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    BITNOT_OP_ELEM,
                    BITNOT_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    BITAND_OP_ELEM,
                    BITWISE_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    DIV_REM_OP_ELEM,
                    DIV_REM_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    EQ_OP_ELEM,
                    EQ_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    COMPARISON_OP_ELEM,
                    COMPARISON_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    IF_THEN_ELSE_OP_ELEM,
                    IF_THEN_ELSE_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SHIFT_OP_ELEM,
                    ROTATE_SHIFT_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    MUL_OP_ELEM,
                    MUL_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    NEGATION_OP_ELEM,
                    NEGATION_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    OVERFLOWING_SCALAR_ADD_OP_ELEM,
                    OVERFLOWING_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    OVERFLOWING_MUL_OP_ELEM,
                    OVERFLOWING_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    OVERFLOWING_SUB_OP_ELEM,
                    OVERFLOWING_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    ROTATE_OP_ELEM,
                    ROTATE_SHIFT_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SUB_OP_ELEM,
                    SUB_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SUM_CIPHERTEXTS_10_CTXTS_OP_ELEM,
                    SUM_CIPHERTEXTS_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SUM_CIPHERTEXTS_20_CTXTS_OP_ELEM,
                    SUM_CIPHERTEXTS_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SUM_CIPHERTEXTS_5_CTXTS_OP_ELEM,
                    SUM_CIPHERTEXTS_CREF_ELEM,
                    PFAIL_2M64_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
            ]
        ),
    ]
)

# No LaTex label set for this table.
TABLE_CIPHERTEXT_CIPHERTEXT_OPS_PFAIL128_KS32 = LatexTable(
    "ciphertext_ciphertext_ops_pfail128_ks32",
    [
        LatexArraySection(
            [
                [
                    ADD_OP_ELEM,
                    ADD_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    BITNOT_OP_ELEM,
                    BITNOT_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    BITAND_OP_ELEM,
                    BITWISE_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    DIV_REM_OP_ELEM,
                    DIV_REM_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    EQ_OP_ELEM,
                    EQ_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    COMPARISON_OP_ELEM,
                    COMPARISON_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    IF_THEN_ELSE_OP_ELEM,
                    IF_THEN_ELSE_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SHIFT_OP_ELEM,
                    ROTATE_SHIFT_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    MUL_OP_ELEM,
                    MUL_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    NEGATION_OP_ELEM,
                    NEGATION_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    OVERFLOWING_SCALAR_ADD_OP_ELEM,
                    OVERFLOWING_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    OVERFLOWING_MUL_OP_ELEM,
                    OVERFLOWING_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    OVERFLOWING_SUB_OP_ELEM,
                    OVERFLOWING_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    ROTATE_OP_ELEM,
                    ROTATE_SHIFT_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SUB_OP_ELEM,
                    SUB_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SUM_CIPHERTEXTS_10_CTXTS_OP_ELEM,
                    SUM_CIPHERTEXTS_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SUM_CIPHERTEXTS_20_CTXTS_OP_ELEM,
                    SUM_CIPHERTEXTS_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
                [
                    SUM_CIPHERTEXTS_5_CTXTS_OP_ELEM,
                    SUM_CIPHERTEXTS_CREF_ELEM,
                    PFAIL_2M128_HIDDEN_ELEM,
                    KS32PBS_HIDDEN_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                ],
            ]
        ),
    ]
)

#
TABLE_COMPRESSION_BENCHMARKS = LatexTable(
    "compression_benchmarks",
    [
        LatexArraySection(
            [
                [
                    COMPRESSION_OP_ELEM,
                    COMPRESSION_REF_ELEM,
                    PFAIL_2M64_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                    _get_operand_size_column_element(512),
                ],
                [
                    DECOMPRESSION_OP_ELEM,
                    DECOMPRESSION_REF_ELEM,
                    PFAIL_2M64_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                    _get_operand_size_column_element(512),
                ],
            ]
        ),
        LatexArraySection(
            [
                [
                    COMPRESSION_OP_ELEM,
                    COMPRESSION_REF_ELEM,
                    PFAIL_2M128_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                    _get_operand_size_column_element(512),
                ],
                [
                    DECOMPRESSION_OP_ELEM,
                    DECOMPRESSION_REF_ELEM,
                    PFAIL_2M128_ELEM,
                    M2C2_HIDDEN_ELEM,
                    *ALL_OPERAND_SIZES_ELEM,
                    _get_operand_size_column_element(512),
                ],
            ]
        ),
    ]
)
