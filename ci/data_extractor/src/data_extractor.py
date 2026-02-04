"""
data_extractor
--------------

Extract benchmarks results from Zama PostgreSQL instance.
It will output the filtered results in a file formatted as CSV.

PostgreSQL connection configuration can be passed through a configuration file or via environment variables.
When using the environment variables, make sure to set the following ones:
 * DATA_EXTRACTOR_DATABASE_HOST
 * DATA_EXTRACTOR_DATABASE_USER
 * DATA_EXTRACTOR_DATABASE_PASSWORD

Note that if provided, environment variables will take precedence over the configuration file.
"""

import argparse
import datetime
import sys

import comparison
import config
import connector
import formatters.core
import formatters.hlapi
import formatters.integer
import formatters.wasm
import regression
from benchmark_specs import BenchSubset, BenchType, Layer, OperandType, RustType
from formatters.common import BenchArray, CSVFormatter, MarkdownFormatter, SVGFormatter

import utils

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()
parser.add_argument(
    "output_file", help="File storing parsed results (with no extension)"
)
parser.add_argument(
    "-c" "--config-file",
    dest="config_file",
    help="Location of configuration file containing credentials to connect to "
    "PostgreSQL instance",
)
parser.add_argument(
    "--bench-date",
    dest="bench_date",
    default=datetime.datetime.now().isoformat(),
    help=(
        "Last insertion date to look for in the database,"
        " formatted as ISO 8601 timestamp YYYY-MM-DDThh:mm:ss"
    ),
)
parser.add_argument(
    "-d",
    "--database",
    dest="database",
    default="tfhe_rs",
    help="Name of the database used to store results",
)
group.add_argument(
    "-w",
    "--hardware",
    dest="hardware",
    default="hpc7a.96xlarge",
    help="Hardware reference used to perform benchmark",
)
group.add_argument(
    "--hardware-comp",
    dest="hardware_comp",
    help="Comma separated values of hardware to compare. "
    "The first value would be chosen as baseline.",
)
parser.add_argument(
    "-V", "--project-version", dest="project_version", help="Commit hash reference"
)
parser.add_argument(
    "-b",
    "--branch",
    dest="branch",
    default="main",
    help="Git branch name on which benchmark was performed",
)
parser.add_argument(
    "--base-branch",
    dest="base_branch",
    default="main",
    help="Git base branch name on which benchmark history can be fetched",
)
parser.add_argument(
    "--backend",
    dest="backend",
    choices=["cpu", "gpu", "hpu"],
    default="cpu",
    help="Backend on which benchmarks have run",
)
parser.add_argument(
    "--backends-comparison",
    dest="backends_comparison",
    action="store_true",
    help="Produce a comparison between backends on 64 bits ciphertext/ciphertext integer operations",
)
parser.add_argument(
    "--tfhe-rs-layer",
    dest="layer",
    default="integer",
    help="Layer of the tfhe-rs library to filter against",
)
parser.add_argument(
    "--pbs-kind",
    dest="pbs_kind",
    choices=["classical", "multi_bit", "any"],
    default="classical",
    help="Kind of PBS to look for",
)
parser.add_argument(
    "--grouping-factor",
    dest="grouping_factor",
    type=int,
    choices=[2, 3, 4],
    help="Grouping factor used in multi-bit parameters set",
)
parser.add_argument(
    "--time-span-days",
    dest="time_span_days",
    type=int,
    default=30,
    help="Numbers of days prior of `bench_date` we search for results in the database",
)
parser.add_argument(
    "--bench-type",
    dest="bench_type",
    choices=["latency", "throughput", "both"],
    default="latency",
    help="Type of benchmark to filter against",
)
parser.add_argument(
    "--bench-subset",
    dest="bench_subset",
    choices=["all", "erc20", "zk"],
    default="all",
    help="Subset of benchmarks to filter against, dedicated formatting will be applied",
)
parser.add_argument(
    "--regression-profiles",
    dest="regression_profiles",
    help="Path to file containing regression profiles formatted as TOML",
)
parser.add_argument(
    "--regression-selected-profile",
    dest="regression_selected_profile",
    help="Regression profile to select from the regression profiles file to filter out database results",
)
exclusive_generation_group = parser.add_mutually_exclusive_group()
exclusive_generation_group.add_argument(
    "--generate-markdown",
    dest="generate_markdown",
    action="store_true",
    help="Generate Markdown array",
)
exclusive_generation_group.add_argument(
    "--generate-svg",
    dest="generate_svg",
    action="store_true",
    help="Generate SVG table formatted like ones in tfhe-rs documentation",
)
exclusive_generation_group.add_argument(
    "--generate-svg-from-markdown",
    dest="generate_svg_from_file",
    help="Generate SVG table formatted like ones in tfhe-rs documentation from a Markdown table",
)
exclusive_generation_group.add_argument(
    "--generate-regression-json",
    dest="generate_regression_json",
    action="store_true",
    help="Generate JSON file with regression data with all the results from base branch and the latest results of the development branch",
)


def generate_svg_from_file(
    user_config: config.UserConfig, layer: Layer, input_file: str
):
    """
    Generates an SVG file based on a given formatted array in Markdown file.

    :param user_config: An instance of the UserConfig class, used to manage
        configuration details like backend, PBS kind, and output file paths.
    :type user_config: config.UserConfig
    :param layer: The layer information used in SVG formatting and
        generation.
    :type layer: Layer
    :param input_file: File path of the input Markdown file to be converted to
        SVG format.
    :type input_file: str

    :return: None
    """
    utils.write_to_svg(
        SVGFormatter(
            layer,
            user_config.backend,
            user_config.pbs_kind,
        ).generate_svg_table_from_markdown_file(input_file),
        user_config.output_file,
    )


def perform_hardware_comparison(
    user_config: config.UserConfig,
    layer: Layer,
):
    """
    Perform a hardware comparison by fetching benchmark data, computing
    comparisons, and generating CSV outputs for each hardware configuration. It
    outputs both raw data and gain-based analysis for comparison between
    reference and target hardware.

    :param user_config: An instance of the UserConfig class, used to manage
        configuration details like backend, PBS kind, and output file paths.
    :type user_config: config.UserConfig
    :param layer: The layer object containing specific information required for
        formatting and processing benchmark data.
    :type layer: Layer

    :return: None
    """
    results = []

    for hw in hardware_list:
        try:
            res = conn.fetch_benchmark_data(user_config, operand_type)
        except RuntimeError as err:
            print(f"Failed to fetch benchmark data: {err}")
            sys.exit(2)

        results.append(res)

        match user_config.bench_type:
            case BenchType.Latency:
                conversion_func = utils.convert_latency_value_to_readable_text
            case BenchType.Throughput:
                conversion_func = utils.convert_throughput_value_to_readable_text

        output_filename = "".join(
            [user_config.output_file, "_", hw, "_", operand_type.lower(), ".csv"]
        )
        csv_formatter = CSVFormatter(layer, user_config.backend, user_config.pbs_kind)
        formatted_data = csv_formatter.format_data(res, conversion_func)
        utils.write_to_csv(
            csv_formatter.generate_csv(formatted_data),
            output_filename,
        )

    gains_results = formatters.compute_comparisons(*results)
    reference_hardware = hardware_list[0]
    for i, hw in enumerate(hardware_list[1:]):
        output_filename = "".join(
            [
                user_config.output_file,
                "_",
                operand_type.lower(),
                "_",
                reference_hardware,
                "_",
                hw,
                "_gains.csv",
            ]
        )
        csv_formatter = CSVFormatter(layer, user_config.backend, user_config.pbs_kind)
        formatted_data = csv_formatter.format_data(
            gains_results[i],
            utils.convert_gain_to_text,
        )
        utils.write_to_csv(
            csv_formatter.generate_csv(formatted_data),
            output_filename,
        )


def get_formatter(layer: Layer, bench_subset: BenchSubset):
    match bench_subset:
        case BenchSubset.Erc20:
            return formatters.hlapi.Erc20Formatter
        case BenchSubset.Zk:
            return formatters.wasm.ZKFormatter

    match layer:
        case Layer.Integer:
            return formatters.integer.IntegerFormatter
        case Layer.CoreCrypto:
            return formatters.core.CoreFormatter
        case Layer.HLApi:
            return formatters.hlapi.HlApiFormatter
        case _:
            raise NotImplementedError(f"layer '{layer}' not supported yet")


def perform_data_extraction(
    user_config: config.UserConfig,
    layer: Layer,
    operand_type: OperandType,
    output_filename: str,
    bench_subset: BenchSubset,
):
    """
    Extracts, formats, and processes benchmark data for a specified operand type and
    saves the results into various file formats such as CSV, Markdown, or SVG based
    on user configuration.

    :param user_config: An instance of the UserConfig class, used to manage
        configuration details like backend, PBS kind, and output file paths.
    :type user_config: config.UserConfig
    :param layer: Layer object specifying the granularity and context of the
        operand processing.
    :type layer: Layer
    :param operand_type: Type of operand data for which the benchmarks are
        extracted and processed.
    :type operand_type: OperandType
    :param output_filename: The base filename for the output files where results
        will be saved.
    :type output_filename: str

    :return: Generic formatted arrays
    :rtype: list[BenchArray]
    """
    operation_filter = [bench_subset.value] if bench_subset != BenchSubset.All else None

    try:
        res = conn.fetch_benchmark_data(
            user_config, operand_type, operation_filter=operation_filter
        )
    except RuntimeError as err:
        print(f"Failed to fetch benchmark data: {err}")
        sys.exit(2)

    match user_config.bench_type:
        case BenchType.Latency:
            conversion_func = utils.convert_latency_value_to_readable_text
        case BenchType.Throughput:
            conversion_func = utils.convert_throughput_value_to_readable_text
        case BenchType.Both:
            conversion_func = None

    generic_formatter_class = get_formatter(layer, bench_subset)
    generic_formatter = generic_formatter_class(
        layer, user_config.backend, user_config.pbs_kind, user_config.grouping_factor
    )
    formatted_results = generic_formatter.format_data(
        res,
        conversion_func,
    )

    if layer != Layer.CoreCrypto:
        file_suffix = f"-{operand_type.lower()}"
    else:
        file_suffix = ""
    filename = utils.append_suffix_to_filename(output_filename, file_suffix, ".csv")

    try:
        utils.write_to_csv(
            CSVFormatter(layer, user_config.backend, user_config.pbs_kind).generate_csv(
                formatted_results
            ),
            filename,
        )
    except NotImplementedError as err:
        # Ignore this error if a formatter does not support CSV generation.
        print(f"CSV generation not supported (error: {err})")

    generic_arrays = generic_formatter.generate_array(
        formatted_results,
        operand_type,
        excluded_types=[RustType.FheUint2, RustType.FheUint4, RustType.FheUint256],
    )

    return generic_arrays


def generate_files_from_arrays(
    generic_arrays: list[BenchArray],
    user_config: config.UserConfig,
    layer: Layer,
    output_filename: str,
    file_suffix: str = "",
    generate_markdown: bool = False,
    generate_svg: bool = False,
):
    for array in generic_arrays:
        metadata_suffix = ""
        if array.metadata:
            for value in array.metadata.values():
                # In recent Python, dict keep insert order.
                # This call won't change metadata order in the suffix between runs.
                metadata_suffix += f"-{value}".lower()

        current_suffix = file_suffix + metadata_suffix

        if generate_markdown:
            filename = utils.append_suffix_to_filename(
                output_filename, current_suffix, ".md"
            )

            data_formatter = MarkdownFormatter(
                layer, user_config.backend, user_config.pbs_kind
            )

            utils.write_to_markdown(
                data_formatter.generate_markdown_array(array),
                filename,
            )
        elif generate_svg:
            filename = utils.append_suffix_to_filename(
                output_filename, current_suffix, ".svg"
            )

            data_formatter = SVGFormatter(
                layer, user_config.backend, user_config.pbs_kind
            )

            utils.write_to_svg(
                data_formatter.generate_svg_table(
                    array,
                ),
                filename,
            )


def get_operands_types(layer: Layer, bench_subset: BenchSubset = None):
    ciphertext_only = (OperandType.CipherText,)

    if layer == Layer.CoreCrypto:
        return ciphertext_only
    elif bench_subset:
        match bench_subset:
            case BenchSubset.Zk | BenchSubset.Erc20:
                return ciphertext_only
            case _:
                raise NotImplementedError(
                    f"operand types cannot be defined for bench subset '{bench_subset}'"
                )
    else:
        return OperandType.CipherText, OperandType.PlainText


if __name__ == "__main__":
    args = parser.parse_args()
    user_config = config.UserConfig(args)
    layer = user_config.layer
    bench_subset = user_config.bench_subset

    if args.generate_svg_from_file:
        generate_svg_from_file(user_config, layer, args.generate_svg_from_file)
        sys.exit(0)

    try:
        postgre_config = connector.PostgreConfig(args.config_file)
        conn = connector.PostgreConnector(postgre_config)
        conn.connect_to_database(user_config.database)
    except Exception:
        sys.exit(1)

    if args.generate_regression_json:
        try:
            regression.perform_regression_json_generation(conn, user_config)
        except RuntimeError as err:
            print(f"Failed to perform performance regression JSON: {err}")
            sys.exit(2)
        else:
            sys.exit(0)

    if args.backends_comparison:
        try:
            arrays = comparison.perform_backends_comparison(conn, user_config)
            generate_files_from_arrays(
                arrays,
                user_config,
                layer,
                user_config.output_file,
                generate_markdown=args.generate_markdown,
                generate_svg=args.generate_svg,
            )
        except RuntimeError as err:
            print(f"Failed to perform backends comparison: {err}")
            sys.exit(2)
        else:
            sys.exit(0)

    hardware_list = (
        args.hardware_comp.lower().split(",") if args.hardware_comp else None
    )

    operands_types = get_operands_types(layer, bench_subset)

    for operand_type in operands_types:
        if hardware_list:
            perform_hardware_comparison(user_config, layer)

            if args.generate_markdown:
                print("Markdown generation is not supported with comparisons")
            continue

        file_suffix = f"_{operand_type.lower()}"
        arrays = perform_data_extraction(
            user_config,
            layer,
            operand_type,
            user_config.output_file,
            bench_subset=bench_subset,
        )
        generate_files_from_arrays(
            arrays,
            user_config,
            layer,
            user_config.output_file,
            file_suffix=file_suffix,
            generate_markdown=args.generate_markdown,
            generate_svg=args.generate_svg,
        )

    conn.close()
