import collections
import copy
import enum
import pathlib
import xml.dom.minidom
from collections.abc import Callable

import svg
from benchmark_specs import (ALL_RUST_TYPES, Backend, BenchDetails,
                             CoreCryptoOperation, ErrorFailureProbability,
                             Layer, NoiseDistribution, OperandType, PBSKind,
                             RustType)
from py_markdown_table.markdown_table import markdown_table


def compute_comparisons(*results):
    """
    Compute gains for data in ``results``. The first element is considered as the baseline.

    :param results: :class:`list` of results

    :return: :class:`list` of gains with length of ``results`` minus one (baseline is not sent back)
    """
    gains = []
    baseline = results[0]

    for compared_results in results[1:]:
        for key, base_value in baseline.items():
            try:
                compared_value = compared_results[key]
            except KeyError:
                # Ignore missing entries
                continue

            gain = round((base_value - compared_value) * 100 / base_value, 2)
            compared_results[key] = gain

        gains.append(compared_results)

    return gains


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


class BenchArray:
    def __init__(self, array, layer, metadata: dict = None):
        self.array = array
        self.layer = layer
        self.metadata = metadata

    def __repr__(self):
        return f"BenchArray(layer={self.layer}, metadata={self.metadata})"


class GenericFormatter:
    def __init__(
        self,
        layer: Layer,
        backend: Backend,
        pbs_kind: PBSKind,
        grouping_factor: int = None,
    ):
        """
        Generic formatter for a given specified layer, backend, and PBS kind.

        :param layer: Represents the layer configuration for the object.
        :type layer: Layer
        :param backend: Specifies the backend system to be used.
        :type backend: Backend
        :param pbs_kind: Specifies the type or kind of PBS (Private Backend System).
        :type pbs_kind: PBSKind
        :param grouping_factor: Specifies the multi-bit PBS grouping factor to use a filter.
        :type grouping_factor: int, optional
        """
        self.layer = layer
        self.backend = backend
        self.pbs_kind = pbs_kind
        self.requested_grouping_factor = grouping_factor

    def set_grouping_factor(self, grouping_factor: int):
        """
        Sets the grouping factor for a computation or operation.

        This method allows configuration of the requested grouping factor
        value, which can affect how operations using multi-bit parameters set are processed.

        :param grouping_factor: The desired grouping factor to use.
        :type grouping_factor: int
        """
        self.requested_grouping_factor = grouping_factor

    def format_data(
        self, data: dict[BenchDetails : list[int]], conversion_func: Callable
    ):
        """
        Formats data based on the specified layer and applies a conversion function to
        transform the data.

        The method determines the data formatting logic by matching the
        current layer of the object and invokes the appropriate specific layer-related
        formatting function.

        :param data: A dictionary where the keys are instances of `BenchDetails` and
            the values are lists of integers, representing the benchmark data to be
            formatted.
        :type data: dict[BenchDetails : list[int]]
        :param conversion_func: A callable function that will be applied to transform
            the data values based on the specific layer requirements.
        :type conversion_func: Callable

        :return: The formatted data results after applying layer and conversion logic.
        :rtype: Any

        :raises NotImplementedError: Raised when the specified layer is unsupported.
        """
        match self.layer:
            case Layer.Integer:
                return self._format_integer_data(data, conversion_func)
            case Layer.CoreCrypto:
                return self._format_core_crypto_data(data, conversion_func)
            case _:
                raise NotImplementedError(f"layer '{self.layer}' not supported yet")

    @staticmethod
    def _format_integer_data(data: dict[BenchDetails : list[int]], conversion_func):
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

    @staticmethod
    def _format_core_crypto_data(data: dict[BenchDetails : list[int]], conversion_func):
        params_set = set()
        for details in data:
            try:
                params_set.add(details.get_params_definition())
            except Exception:
                # Might be a Boolean parameters set, ignoring
                continue

        params_set = sorted(params_set)

        formatted = collections.defaultdict(
            lambda: {params: "N/A" for params in params_set}
        )
        for details, timings in data.items():
            try:
                reduced_params = details.get_params_definition()
            except Exception:
                # Might be a Boolean parameters set, ignoring
                continue

            test_name = details.operation_name
            value = conversion_func(timings[-1])
            formatted[test_name][reduced_params] = value

        return formatted

    def generate_array(
        self,
        data,
        operand_type: OperandType = None,
        excluded_types: list[RustType] = None,
    ) -> list[BenchArray]:
        """
        Generates an array of `BenchArray` based on the specified layer and criteria.

        This method takes input data and generates an array of `BenchArray` objects,
        using the rules defined by the current `layer`. The behavior varies depending
        on the active layer, and certain types can be explicitly excluded from the
        generation process.

        :param data: Input data to generate the array from.
        :type data: Any
        :param operand_type: Specifies the type of operand to guide the array generation.
            Defaults to `None`.
        :type operand_type: OperandType, optional
        :param excluded_types: A list of `RustType` to exclude from array generation.
            Defaults to `None`.
        :type excluded_types: list[RustType], optional

        :return: A list of generated `BenchArray` objects.
        :rtype: list[BenchArray]

        :raises NotImplementedError: If the current layer is not implemented.
        """
        match self.layer:
            case Layer.Integer:
                return self._generate_unsigned_integer_array(
                    data, operand_type, excluded_types
                )
            case Layer.CoreCrypto:
                return self._generate_core_crypto_showcase_arrays(data)
            case _:
                raise NotImplementedError

    def _generate_unsigned_integer_array(
        self,
        data,
        operand_type: OperandType = None,
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
                match operand_type:
                    case OperandType.CipherText:
                        prefix = "cuda"
                    case OperandType.PlainText:
                        prefix = "cuda_scalar"

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

        types = ALL_RUST_TYPES.copy()
        excluded_types = excluded_types if excluded_types is not None else []
        for excluded in excluded_types:
            types.remove(excluded)

        first_column_header = "Operation \\ Size"

        # Adapt list to plaintext benchmarks results.
        if operand_type == OperandType.PlainText:
            operations.insert(8, f"{prefix}_div_parallelized")
            operations.insert(9, f"{prefix}_rem_parallelized")
            operations.pop(7)  # Remove div_rem_parallelized

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

        data_without_excluded_types = copy.deepcopy(data)
        for v in data_without_excluded_types.values():
            for excluded in excluded_types:
                try:
                    v.pop(excluded.value)
                except KeyError:
                    # Type is not contained in the results, ignoring
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

    def _build_results_dict(
        self,
        pfails: list[ErrorFailureProbability],
        noise_distributions: list[NoiseDistribution],
        operation_displays: list[CoreCryptoOperation],
        default_precisions: Callable[[], dict],
    ):
        results_dict = {}

        for pfail in pfails:
            for noise in noise_distributions:
                results_dict[CoreCryptoResultsKey(pfail, noise)] = {
                    o: default_precisions() for o in operation_displays
                }

        return results_dict

    def _generate_core_crypto_showcase_arrays(
        self,
        data,
    ):
        supported_pfails = [
            ErrorFailureProbability.TWO_MINUS_40,
            ErrorFailureProbability.TWO_MINUS_64,
            ErrorFailureProbability.TWO_MINUS_128,
        ]
        noise_distributions = [
            NoiseDistribution.Gaussian,
            NoiseDistribution.TUniform,
        ]

        operation_displays = [op.value for op in OPERATIONS_DISPLAYS]

        sorted_results = self._build_results_dict(
            supported_pfails,
            noise_distributions,
            OPERATIONS_DISPLAYS,
            DEFAULT_CORE_CRYPTO_PRECISIONS,
        )

        for operation, timings in data.items():
            try:
                formatted_name = CoreCryptoOperation.from_str(operation)
            except NotImplementedError:
                # Operation is not supported.
                continue

            for param_definition, value in timings.items():
                pfail = param_definition.p_fail
                if pfail not in supported_pfails:
                    print(f"[{operation}] P-fail '{pfail}' is not supported")
                    continue
                noise = param_definition.noise_distribution
                precision = int(param_definition.message_size) * 2
                key = CoreCryptoResultsKey(pfail, noise)

                if (
                    formatted_name == CoreCryptoOperation.MultiBitPBS
                    or formatted_name == CoreCryptoOperation.KeySwitchMultiBitPBS
                ) and param_definition.pbs_kind != PBSKind.MultiBit:
                    # Skip this operation since a multi-bit operation cannot be done with any other parameters type.
                    continue

                grouping_factor = param_definition.grouping_factor
                if (
                    grouping_factor is not None
                    and grouping_factor != self.requested_grouping_factor
                ):
                    continue

                if (
                    param_definition.details["variation"]
                    or param_definition.details["trailing_details"]
                ):
                    continue

                try:
                    sorted_results[key][formatted_name][precision] = value
                except KeyError:
                    # Operation is not supposed to appear in the formatted array.
                    continue

        first_column_header = "Operation \\ Precision (bits)"

        arrays = []
        for key, results in sorted_results.items():
            array = []
            for operation, timings in results.items():
                d = {first_column_header: operation.value}
                d.update({str(k): v for k, v in timings.items()})
                array.append(d)

            arrays.append(
                BenchArray(
                    array,
                    self.layer,
                    metadata={"pfail": key.pfail, "noise": key.noise_distribution},
                )
            )

        return arrays


# ---------------------------
# Core_crypto layer constants
# ---------------------------

OPERATIONS_DISPLAYS = [
    #CoreCryptoOperation.KeySwitch, # Uncomment this line to get keyswitch in the tables
    CoreCryptoOperation.PBS,
    CoreCryptoOperation.MultiBitPBS,
    CoreCryptoOperation.KeyswitchPBS,
    CoreCryptoOperation.KeySwitchMultiBitPBS,
]

DEFAULT_CORE_CRYPTO_PRECISIONS = lambda: {
    2: "N/A",
    4: "N/A",
    6: "N/A",
    8: "N/A",
}


class CoreCryptoResultsKey:
    """
    Representation of a hashable result key for the core_crypto layer.

    :param pfail: Probability of failure associated with the cryptographic result.
    :type pfail: ErrorFailureProbability
    :param noise_distribution: Noise distribution parameter linked to the
        cryptographic result.
    :type noise_distribution: NoiseDistribution
    """

    def __init__(
        self, pfail: ErrorFailureProbability, noise_distribution: NoiseDistribution
    ):
        self.pfail = pfail
        self.noise_distribution = noise_distribution

    def __eq__(self, other):
        return (
            self.pfail == other.pfail
            and self.noise_distribution == other.noise_distribution
        )

    def __hash__(self):
        return hash((self.pfail, self.noise_distribution))

    def __repr__(self):
        return f"CoreCryptoResultsKey(pfail={self.pfail}, noise_distribution={self.noise_distribution})"


class CSVFormatter(GenericFormatter):
    """
    Formatter to generate CSV content.
    """

    def generate_csv(self, data: dict[str, collections.defaultdict]) -> list[list]:
        """
        Generates a CSV-compatible data structure based on the provided input data and
        the current layer type. The method processes the input to construct headers and
        rows suitable for CSV writing.

        :param data: A dictionary where keys represent row identifiers and values
            are dictionaries of column-value pairs representing the data for
            each row.
        :type data: dict[str, collections.defaultdict]

        :return: A list of lists where each sub-list represents a row in the CSV,
            including the header row.
        :rtype: list

        :raises NotImplementedError: If the layer type specified in the object's
            `layer` attribute is unsupported.
        """
        headers_values = data.get(list(data)[0]).keys()

        match self.layer:
            case Layer.Integer:
                headers = ["Operation \\ Size(bit)", *headers_values]
            case Layer.CoreCrypto:
                headers = ["Operation \\ Parameters set", *headers_values]
            case _:
                print(
                    f"tfhe-rs layer '{self.layer}' currently not supported for CSV writing"
                )
                raise NotImplementedError

        csv_data = [headers]
        csv_data.extend(
            [[key, *list(values_dict.values())] for key, values_dict in data.items()]
        )

        return csv_data


class MarkdownFormatter(GenericFormatter):
    """
    Formatter to generate Markdown content.
    """

    def generate_markdown_array(
        self,
        generic_array: BenchArray,
    ) -> str:
        """
        Generates a Markdown representation of the provided generic array.

        :param generic_array: The input array encapsulated in a BenchArray object.

        :return: A Markdown formatted string representing the input array.
        :rtype: str
        """
        md_array = (
            markdown_table(generic_array.array)
            .set_params(row_sep="markdown", quote=False, padding_weight="right")
            .get_markdown()
        )

        return md_array


# -------------
# SVG constants
# -------------

BLACK_COLOR = "black"
WHITE_COLOR = "white"
LIGHT_GREY_COLOR = "#f3f3f3"
YELLOW_COLOR = "#fbbc04"

FONT_FAMILY = "Arial"
FONT_SIZE = 14

BORDER_WIDTH_PIXEL = 2
# Operation name is always in table first column
OPERATION_NAME_HORIZONTAL_POSITION = 6

SPECIAL_CHARS_PAIRS = {
    "&": "&#38;",
    "<": "&#60;",
    ">": "&#62;",
    "\\|": "&#124;",
}

# -------------


class SVGFormatter(GenericFormatter):
    """
    Formatter to generate SVG content.
    """

    @staticmethod
    def _transform_special_characters(strg: str):
        for char, replacement in SPECIAL_CHARS_PAIRS.items():
            if char in strg:
                strg = strg.replace(char, replacement)

        return strg

    def _build_svg_headers_row(
        self,
        layer: Layer,
        headers,
        overall_width,
        row_height,
        op_name_col_width,
        per_timing_col_width,
    ):
        op_header = headers.pop(0)
        header_elements = [
            svg.Rect(
                x=0, y=0, width=overall_width, height=row_height, fill=BLACK_COLOR
            ),
            self._build_svg_text(
                OPERATION_NAME_HORIZONTAL_POSITION,
                row_height / 2,
                op_header,
                text_anchor="start",
                fill=WHITE_COLOR,
                font_weight="bold",
            ),
        ]

        for row_idx, type_ident in enumerate(headers):
            curr_x = op_name_col_width + row_idx * per_timing_col_width

            match layer:
                case Layer.Integer:
                    type_name_width = type_ident.strip("FheUint")
                    header_elements.extend(
                        [
                            # Rust type class
                            self._build_svg_text(
                                curr_x + per_timing_col_width / 2,
                                row_height / 3,
                                "FheUint",
                                fill=WHITE_COLOR,
                                font_weight="bold",
                            ),
                            # Actual size of the Rust type
                            self._build_svg_text(
                                curr_x + per_timing_col_width / 2,
                                2 * row_height / 3 + 3,
                                type_name_width,
                                fill=WHITE_COLOR,
                                font_weight="bold",
                            ),
                        ]
                    )
                case Layer.CoreCrypto:
                    header_elements.append(
                        # Core_crypto arrays contains only ciphertext modulus size as headers
                        self._build_svg_text(
                            curr_x + per_timing_col_width / 2,
                            row_height / 2,
                            type_ident,
                            fill=WHITE_COLOR,
                            font_weight="bold",
                        )
                    )
                case _:
                    raise NotImplementedError

        return header_elements

    def _build_svg_timing_row(
        self,
        timings_row,
        row_y_pos,
        row_height,
        op_name_col_width,
        per_timing_col_width,
    ):
        timing_elements = []
        op_name = timings_row.pop(0)
        timing_elements.append(
            self._build_svg_text(
                OPERATION_NAME_HORIZONTAL_POSITION,
                row_y_pos + row_height / 2,
                op_name,
                text_anchor="start",
            )
        )
        for timing_idx, timing in enumerate(timings_row):
            timing_elements.append(
                self._build_svg_text(
                    op_name_col_width
                    + timing_idx * per_timing_col_width
                    + per_timing_col_width / 2,
                    row_y_pos + row_height / 2,
                    timing,
                )
            )

        return timing_elements

    def _build_svg_text(
        self, x, y, text, text_anchor="middle", fill=BLACK_COLOR, font_weight="normal"
    ):
        return svg.Text(
            x=x,
            y=y,
            dominant_baseline="middle",
            text_anchor=text_anchor,
            font_family=FONT_FAMILY,
            font_size=FONT_SIZE,
            fill=fill,
            text=text,
            font_weight=font_weight,
        )

    def _build_svg_borders(
        self,
        overall_width,
        overall_height,
        row_height,
        op_name_col_width,
        per_timing_col_width,
        row_count,
        col_count,
    ):
        border_elements = []

        # Horizontal borders, scrolling vertically
        for row_idx in range(row_count + 2):
            row_y = row_idx * row_height
            border_elements.append(
                svg.Line(
                    x1=0,
                    y1=row_y,
                    x2=overall_width,
                    y2=row_y,
                    stroke=WHITE_COLOR,
                    stroke_width=BORDER_WIDTH_PIXEL,
                )
            )

        # Vertical borders, scrolling horizontally
        # Left border
        border_elements.append(
            svg.Line(
                x1=0,
                y1=0,
                x2=0,
                y2=overall_height,
                stroke=WHITE_COLOR,
                stroke_width=BORDER_WIDTH_PIXEL,
            )
        )
        # Timing cols
        for col_idx in range(col_count + 1):
            col_x = op_name_col_width + col_idx * per_timing_col_width
            border_elements.append(
                svg.Line(
                    x1=col_x,
                    y1=0,
                    x2=col_x,
                    y2=overall_height,
                    stroke=WHITE_COLOR,
                    stroke_width=BORDER_WIDTH_PIXEL,
                )
            )

        return border_elements

    def generate_svg_table(self, generic_array: BenchArray) -> str:
        """
        Generates an SVG representation of a table from the given `BenchArray` object.
        This method processes array data to create a visual representation of the
        provided headers and values as an SVG image, organizing them into rows and
        columns consistent with the structure of the input.

        :param generic_array: The BenchArray object containing structured data for
            generating the table.
        :type generic_array: BenchArray

        :return: An SVG representation of the table as a well-formatted string.
            The SVG is generated with appropriate dimensions, colors, and styles
            to ensure a visually clear and consistent layout.
        :rtype: str
        """
        headers = list(generic_array.array[0].keys())
        ops = generic_array.array[:]

        # TODO Create a class to handle table dimension which will depend on tfhe-rs layer
        col_count = len(headers) - 1
        row_count = 1 + len(ops)

        overall_width = int(round(900 / 1.25))
        row_height = int(round(50 / 1.25))
        op_name_col_width = int(round(375 / 1.25))
        per_timing_col_width = (overall_width - op_name_col_width) / col_count
        overall_height = row_count * row_height

        svg_elements = []

        # Generate headers row
        svg_elements.extend(
            self._build_svg_headers_row(
                self.layer,
                headers,
                overall_width,
                row_height,
                op_name_col_width,
                per_timing_col_width,
            )
        )

        # Generate operations rectangle
        yellow_rect_for_op_names = svg.Rect(
            x=0,
            y=row_height,
            width=op_name_col_width,
            height=overall_height - row_height,
            fill=YELLOW_COLOR,
        )
        svg_elements.append(yellow_rect_for_op_names)

        # Generate timings rectangle
        grey_rect_for_timings = svg.Rect(
            x=op_name_col_width,
            y=row_height,
            width=overall_width - op_name_col_width,
            height=overall_height - row_height,
            fill=LIGHT_GREY_COLOR,
        )
        svg_elements.append(grey_rect_for_timings)

        for row_count, row in enumerate(ops):
            row_y = row_height + row_count * row_height
            row_split = [
                self._transform_special_characters(v)
                for v in filter(None, row.values())
            ]
            svg_elements.extend(
                self._build_svg_timing_row(
                    row_split,
                    row_y,
                    row_height,
                    op_name_col_width,
                    per_timing_col_width,
                )
            )

        # Generate borders
        svg_elements.extend(
            self._build_svg_borders(
                overall_width,
                overall_height,
                row_height,
                op_name_col_width,
                per_timing_col_width,
                row_count,
                col_count,
            )
        )

        canvas = svg.SVG(
            width="100%",
            height=overall_height,
            viewBox=f"0 0 {overall_width} {overall_height}",
            elements=svg_elements,
            preserveAspectRatio="meet",
        )

        dom = xml.dom.minidom.parseString(str(canvas))
        return dom.toprettyxml()

    def generate_svg_table_from_markdown_file(
        self,
        input_filepath: str,
    ) -> str:
        """
        Generates an SVG table from a Markdown file.

        This method reads a Markdown file, parses the table content, and transforms
        it into an SVG representation. The input Markdown file must have headers
        defined in the first row and rows of data separated by the "|" character.

        :param input_filepath: The file path to the Markdown file.
        :type input_filepath: str

        :return: The generated SVG representation of the parsed Markdown table.
        :rtype: str
        """
        with pathlib.Path(input_filepath).open("r") as f:
            md_lines = f.read().splitlines()

        headers = [h.lstrip().rstrip() for h in md_lines.pop(0).split("|")[1:-1]]

        md_lines.pop(0)  # remove separation line
        parsed_data = []
        for line in md_lines:
            values = [v.lstrip().rstrip() for v in line.split("|")[1:-1]]
            if len(values) > len(headers):
                # A '|' character is contained in the operation name
                values[0] += "".join(["|", values.pop(1)])
            parsed_data.append({k: v for k, v in zip(headers, values)})

        array = BenchArray(parsed_data, self.layer)

        return self.generate_svg_table(array)
