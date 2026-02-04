import collections
import pathlib
import xml.dom.minidom
from collections.abc import Callable

import svg
from benchmark_specs import (
    ALL_RUST_INTEGER_TYPES,
    Backend,
    BenchDetails,
    CoreCryptoOperation,
    ErrorFailureProbability,
    Layer,
    NoiseDistribution,
    OperandType,
    PBSKind,
    RustType,
    ZKComputeLoad,
    ZKOperation,
)
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


OPERATION_SIZE_COLUMN_HEADER = "Operation \\ Size"
OPERATION_PRECISION_COLUMN_HEADER = "Operation \\ Precision (bits)"


class BenchArray:
    """
    Represents a structured collection of benchmark data encapsulated with metadata.

    :ivar array: The primary dataset stored as a list of dictionaries.
    :type array: list[dict]
    :ivar layer: The associated layer information for this dataset.
    :type layer: Layer
    :ivar metadata: Additional metadata associated with the dataset.
    :type metadata: dict, optional
    """

    def __init__(self, array: list[dict], layer: Layer, metadata: dict = None):
        self.array = array
        self.layer = layer
        self.metadata = metadata

    def __repr__(self):
        return f"BenchArray(layer={self.layer}, metadata={self.metadata})"

    def replace_column_name(self, current: str, new: str):
        """
        Replaces the name of a column for the whole array.
        If the ``current`` column name does not exist, the array is left unchanged.

        :param current: The column name to be replaced.
        :type current: str
        :param new: The new column name to replace the current one.
        :type new: str
        :return: None
        """
        for line in self.array:
            try:
                line[new] = line.pop(current)
            except KeyError:
                # Column name doesn't exist on this line, ignoring
                continue

    def extend(self, *others, ops_column_name: str = None):
        """
        Extends the current array with values from other benchmark arrays by combining
        and updating the entries based on a specified column name. This method merges
        items from the current array and other provided arrays by using the values
        from the specified column as keys.

        :param others: Additional benchmark arrays to merge into the current array.
            Each `other` must have a similar structure as the current array.
        :type others: iterable[BenchArray]
        :param ops_column_name: The name of the column whose values will be used as
            keys for merging arrays. This parameter is optional, but required for
            the merge operation to function correctly.
        :type ops_column_name: str
        :return: None
        """
        array_as_dict = {}
        for item in self.array:
            op_name = item.pop(ops_column_name)
            array_as_dict[op_name] = item

        for other_bench_array in others:
            for item in other_bench_array.array:
                op_name = item.pop(ops_column_name)
                array_as_dict[op_name].update(item)

        array_as_list = []
        for op_name, values in array_as_dict.items():
            array_as_list.append({ops_column_name: op_name, **values})

        self.array = array_as_list


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
        return self._format_data(data, conversion_func)

    @staticmethod
    def _format_data(*args, **kwargs):
        # Must be implemented by subclasses
        raise NotImplementedError(
            f"format_data() not implemented for this formatter: '{__class__.__name__}'"
        )

    def generate_array(
        self,
        data,
        operand_type: OperandType = None,
        included_types: list[RustType] = ALL_RUST_INTEGER_TYPES,
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
        :param included_types: A list of `RustType` to include in array generation.
            Defaults to `benchmark_specs.ALL_RUST_INTEGER_TYPES`.
        :type included_types: list[RustType], optional
        :param excluded_types: A list of `RustType` to exclude from array generation.
            Note that any type available in excluded_types takes precedence over the same type in included_types.
            Defaults to `None`.
        :type excluded_types: list[RustType], optional

        :return: A list of generated `BenchArray` objects.
        :rtype: list[BenchArray]

        :raises NotImplementedError: If the current layer is not implemented.
        """
        return self._generate_arrays(
            data,
            operand_type,
            included_types=included_types,
            excluded_types=excluded_types,
        )

    def _generate_arrays(self, *args, **kwargs):
        # Must be implemented by subclasses
        raise NotImplementedError(
            f"generate_arrays() not implemented for this formatter: '{__class__.__name__}'"
        )


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
                raise NotImplementedError(
                    f"tfhe-rs layer '{self.layer}' currently not supported for CSV writing"
                )

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


class ZKGenericFormatter(GenericFormatter):
    INPUTS_PROOF_COLUMN_HEADERS = f"Inputs ({ZKComputeLoad.Proof.value})"
    INPUTS_VERIFY_COLUMN_HEADERS = f"Inputs ({ZKComputeLoad.Verify.value})"
    DEFAULT_CRS_SIZE = 2048

    @staticmethod
    def _get_default_dict() -> collections.defaultdict:
        raise NotImplementedError("This method must be implemented by subclasses")

    @staticmethod
    def _match_case_variation_filter(case_variation: dict):
        raise NotImplementedError("This method must be implemented by subclasses")

    def _format_data(self, data: dict[BenchDetails : list[int]], conversion_func):
        formatted = self._get_default_dict()

        for details, timings in data.items():
            parsed_case_variation = self._parse_benchmarks_case_variation(
                details.case_variation
            )

            if not (
                (parsed_case_variation["crs_size"] == self.DEFAULT_CRS_SIZE)
                and self._match_case_variation_filter(parsed_case_variation)
            ):
                continue

            test_name = "::".join(
                [
                    parsed_case_variation["compute_load"],
                    str(parsed_case_variation["packed_size"]),
                    str(parsed_case_variation["crs_size"]),
                ]
            )

            value = conversion_func(timings[-1])
            formatted[test_name][ZKOperation.from_str(details.operation_name)] = value
        return formatted

    @staticmethod
    def _parse_benchmarks_case_variation(case_variation: str):
        parts = case_variation.split("_")
        return {
            "packed_size": int(parts[0]),
            "crs_size": int(parts[3]),
            "compute_load": parts[8],
        }

    def _generate_arrays(self, data, *args, **kwargs):
        # Sorted as they appear in the public documentation.
        input_names = {
            64: "1xFheUint64 (64 bits)",
            256: "4xFheUint64 (256 bits) ",
            2048: "32xFheUint64 (2048 bits)",
        }

        sorted_with_compute_load = {
            ZKComputeLoad.Proof: {},
            ZKComputeLoad.Verify: {},
        }

        result_lines_compute_load_proof = []
        result_lines_compute_load_verify = []

        for key in data:
            compute_load, packed_bits, _ = key.split("::")
            packed_bits = int(packed_bits)

            if packed_bits not in input_names:
                continue

            sorted_with_compute_load[ZKComputeLoad.from_str(compute_load)][
                packed_bits
            ] = data[key]

        for load, results in sorted_with_compute_load.items():
            if load == ZKComputeLoad.Proof:
                table = result_lines_compute_load_proof
                header = self.INPUTS_PROOF_COLUMN_HEADERS
            elif load == ZKComputeLoad.Verify:
                table = result_lines_compute_load_verify
                header = self.INPUTS_VERIFY_COLUMN_HEADERS

            # The following loop ensures display consistency between inputs
            for packed_bits, input_name in input_names.items():
                line = {header: input_name}
                line.update({op.value: v for op, v in results[packed_bits].items()})
                table.append(line)

        return [
            BenchArray(
                result_lines_compute_load_proof,
                self.layer,
                metadata={"compute_load": ZKComputeLoad.Proof.fs_safe_str()},
            ),
            BenchArray(
                result_lines_compute_load_verify,
                self.layer,
                metadata={"compute_load": ZKComputeLoad.Verify.fs_safe_str()},
            ),
        ]


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

            header_one_row_span = self._build_svg_text(
                curr_x + per_timing_col_width / 2,
                row_height / 2,
                type_ident,
                fill=WHITE_COLOR,
                font_weight="bold",
            )

            match layer:
                case Layer.Integer:
                    if type_ident.startswith("FheUint"):
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
                    else:  # Backends comparison (CPU, GPU, HPU)
                        header_elements.append(header_one_row_span)
                case Layer.HLApi | Layer.CoreCrypto | Layer.Wasm:
                    # Core_crypto arrays contains only ciphertext modulus size as headers
                    header_elements.append(header_one_row_span)
                case _:
                    raise NotImplementedError(
                        f"svg header row generation not supported for '{layer}' layer"
                    )

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
