import collections
import enum

from benchmark_specs import (
    ALL_RUST_INTEGER_TYPES,
    Backend,
    BenchDetails,
    BenchType,
    OperandType,
    RustType,
    ZKOperation,
)
from formatters.common import (
    OPERATION_SIZE_COLUMN_HEADER,
    BenchArray,
    GenericFormatter,
    ZKGenericFormatter,
)


class OperationDisplayName(enum.StrEnum):
    Negation = "Negation (-)"
    AddSub = "Add / Sub (+,-)"
    Mul = "Mul (x)"
    EqualNotEqual = "Equal / Not Equal (eq, ne)"
    Comparisons = "Comparisons (ge, gt, le, lt)"
    MaxMin = "Max / Min (max, min)"
    Bitwise = "Bitwise operations (&, \\|, ^)"
    Div = "Div  (/)"
    Rem = "Rem  (%)"
    DivRem = "Div / Rem  (/, %)"
    Shifts = "Left / Right Shifts (<<, >>)"
    Rotates = "Left / Right Rotations (left_rotate, right_rotate)"
    LeadingTrailing = "Leading / Trailing zeros/ones"
    Log2 = "Log2"
    Select = "Select"


class IntegerFormatter(GenericFormatter):
    @staticmethod
    def _format_data(data: dict[BenchDetails : list[int]], conversion_func):
        formatted = collections.defaultdict(
            lambda: {
                2: "N/A",
                8: "N/A",
                16: "N/A",
                32: "N/A",
                64: "N/A",
                128: "N/A",
                256: "N/A",
            }
        )
        for details, timings in data.items():
            test_name = "_".join((details.sign_flavor.value, details.operation_name))
            bit_width = details.bit_size
            value = conversion_func(timings[-1])

            if bit_width == 40:
                # Ignore this width as it's not displayed publicly.
                continue

            formatted[test_name][bit_width] = value

        return formatted

    def _generate_arrays(
        self,
        data,
        operand_type: OperandType = None,
        included_types: list[RustType] = ALL_RUST_INTEGER_TYPES,
        excluded_types: list[RustType] = None,
    ):
        match operand_type:
            case OperandType.CipherText:
                prefix = "unsigned"
            case OperandType.PlainText:
                prefix = "unsigned_scalar"

        match self.backend:
            case Backend.CPU:
                operations = [
                    f"{prefix}_neg_parallelized",
                    f"{prefix}_add_parallelized",
                    f"{prefix}_mul_parallelized",
                    f"{prefix}_eq_parallelized",
                    f"{prefix}_gt_parallelized",
                    f"{prefix}_max_parallelized",
                    f"{prefix}_bitand_parallelized",
                    f"{prefix}_div_rem_parallelized",
                    f"{prefix}_left_shift_parallelized",
                    f"{prefix}_rotate_left_parallelized",
                    f"{prefix}_leading_zeros_parallelized",
                    f"{prefix}_ilog2_parallelized",
                    f"{prefix}_if_then_else_parallelized",
                ]
            case Backend.GPU:
                operations = [
                    f"{prefix}_neg",
                    f"{prefix}_add",
                    f"{prefix}_mul",
                    f"{prefix}_eq",
                    f"{prefix}_gt",
                    f"{prefix}_max",
                    f"{prefix}_bitand",
                    f"{prefix}_div_rem",
                    f"{prefix}_left_shift",
                    f"{prefix}_rotate_left",
                    f"{prefix}_leading_zeros",
                    f"{prefix}_ilog2",
                    f"{prefix}_if_then_else",
                ]
            case Backend.HPU:
                operations = [
                    f"{prefix}_sub",  # Negation operation doesn't exist in HPU yet
                    (
                        f"{prefix}_add"
                        if operand_type == OperandType.CipherText
                        else f"{prefix}_adds"
                    ),
                    (
                        f"{prefix}_mul"
                        if operand_type == OperandType.CipherText
                        else f"{prefix}_muls"
                    ),
                    f"{prefix}_cmp_eq",
                    f"{prefix}_cmp_gt",
                    f"{prefix}_max",
                    f"{prefix}_bw_and",
                    (
                        f"{prefix}_div"
                        if operand_type == OperandType.CipherText
                        else f"{prefix}_divs"
                    ),
                    (
                        f"{prefix}_shift_l"
                        if operand_type == OperandType.CipherText
                        else f"{prefix}_shifts_l"
                    ),
                    (
                        f"{prefix}_rot_l"
                        if operand_type == OperandType.CipherText
                        else f"{prefix}_rots_l"
                    ),
                    f"{prefix}_lead0",
                    f"{prefix}_ilog2",
                    f"{prefix}_if_then_else",
                ]
            case _:
                raise NotImplementedError(
                    f"backend '{self.backend}' not supported yet for integer formatting"
                )

        display_names = [
            OperationDisplayName.Negation,
            OperationDisplayName.AddSub,
            OperationDisplayName.Mul,
            OperationDisplayName.EqualNotEqual,
            OperationDisplayName.Comparisons,
            OperationDisplayName.MaxMin,
            OperationDisplayName.Bitwise,
            OperationDisplayName.DivRem,
            OperationDisplayName.Shifts,
            OperationDisplayName.Rotates,
            OperationDisplayName.LeadingTrailing,
            OperationDisplayName.Log2,
            OperationDisplayName.Select,
        ]

        types = included_types.copy()
        excluded_types = excluded_types if excluded_types is not None else []
        for excluded in excluded_types:
            types.remove(excluded)

        first_column_header = OPERATION_SIZE_COLUMN_HEADER

        # Adapt list to plaintext benchmarks results.
        if operand_type == OperandType.PlainText and self.backend != Backend.HPU:
            if self.backend == Backend.CPU:
                div_name = f"{prefix}_div_parallelized"
                rem_name = f"{prefix}_rem_parallelized"
            elif self.backend == Backend.GPU:
                div_name = f"{prefix}_div"
                rem_name = f"{prefix}_rem"

            operations.insert(8, div_name)
            operations.insert(9, rem_name)
            operations.pop(7)

            display_names.insert(
                8,
                OperationDisplayName.Div,
            )
            display_names.insert(
                9,
                OperationDisplayName.Rem,
            )
            display_names.pop(7)  # Remove Div / Rem

            # Negation operation doesn't exist in plaintext
            operations.pop(0)
            display_names.pop(0)

        data_without_excluded_types = {}
        for op, values in data.items():
            try:
                data_without_excluded_types[op] = {
                    typ: val
                    for typ, val in values.items()
                    if RustType.from_int(typ) in types
                }
            except NotImplementedError:
                # Unknown type from database, ignoring
                continue

        filtered_data = filter(lambda t: t in operations, data_without_excluded_types)
        # Get operation names as key of the dict to ease fetching
        filtered_data_dict = {
            item: tuple(data_without_excluded_types[item].values())
            for item in filtered_data
        }

        result_lines = []
        for name, op in zip(display_names, operations):
            try:
                line = {first_column_header: name.value}
                line.update(
                    {
                        types[i].name: value
                        for i, value in enumerate(filtered_data_dict[op])
                    }
                )
                result_lines.append(line)
            except KeyError:
                # Operation not found in the results, ignoring this line.
                print(
                    f"backend '{self.backend}' could not find operation '{op}' to put in line '{name}'"
                )
                continue

        return [
            BenchArray(result_lines, self.layer),
        ]


class ZKFormatter(ZKGenericFormatter):
    @staticmethod
    def _get_default_dict() -> collections.defaultdict:
        return collections.defaultdict(
            lambda: {
                ZKOperation.Proof: "N/A",
                ZKOperation.Verify: "N/A",
                ZKOperation.VerifyAndExpand: "N/A",
            }
        )

    @staticmethod
    def _match_case_variation_filter(*args, **kwargs):
        # At this layer, server-like ZK are performed there are no variations such as browser kind.
        # Simply match all cases.
        return True
