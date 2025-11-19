import copy

import config
import connector

from benchmark_specs import Backend, Layer, RustType, OperandType, PBSKind
from formatter import GenericFormatter, OPERATION_SIZE_COLUMN_HEADER
import utils

DEFAULT_CPU_HARDWARE = "hpc7a.96xlarge"
DEFAULT_GPU_HARDWARE = "n3-H100-SXM5x8"
DEFAULT_HPU_HARDWARE = "hpu_x1"


def perform_backends_comparison(
    conn: connector.PostgreConnector, user_config: config.UserConfig
):
    """
    Compares benchmark data for different backends (CPU, GPU, HPU) using the provided
    database connection and user configurations. The function fetches, processes, and
    formats benchmark data for each backend, considering specific configurations and
    hardware capabilities. Finally, it combines the formatted results into a unified
    array for comparison.

    :param conn: A database connector used to fetch benchmark data from the data source.
    :type conn: PostgreConnector
    :param user_config: A user configuration copied and updated for each backend data fetch.
    :type user_config: UserConfig
    :return: A list containing a single formatted `BenchArray`, merging benchmark data
        across all backends for comparison.
    :rtype: list[BenchArray]
    """
    user_config.layer = Layer.Integer
    conversion_func = utils.convert_latency_value_to_readable_text

    backend_arrays = []

    for backend, hardware_name in [
        (Backend.CPU, DEFAULT_CPU_HARDWARE),
        (Backend.GPU, DEFAULT_GPU_HARDWARE),
        (Backend.HPU, DEFAULT_HPU_HARDWARE),
    ]:
        case_config = copy.deepcopy(user_config)
        case_config.backend = backend
        case_config.hardware = hardware_name
        if backend == Backend.GPU:
            case_config.pbs_kind = PBSKind.MultiBit
            case_config.grouping_factor = 4

        print(f"Getting {backend} data")

        res = conn.fetch_benchmark_data(case_config)

        generic_formatter = GenericFormatter(
            case_config.layer,
            case_config.backend,
            case_config.pbs_kind,
            case_config.grouping_factor,
        )
        formatted_results = generic_formatter.format_data(
            res,
            conversion_func,
        )

        # Currently max/min operations are not available at the integer layer for HPU backend.
        # Retrieve values by fetching HLAPI layer and insert them into the existing integer array.
        if backend == Backend.HPU:
            case_config.layer = Layer.HLApi
            hlapi_res = conn.fetch_benchmark_data(case_config)
            hlapi_generic_formatter = GenericFormatter(
                case_config.layer,
                case_config.backend,
                case_config.pbs_kind,
                case_config.grouping_factor,
            )
            hlapi_formatted_results = hlapi_generic_formatter.format_data(
                hlapi_res,
                conversion_func,
            )
            integer_sizes_fetched = formatted_results["max"].keys()
            formatted_results["unsigned_max"] = {
                k: v
                for k, v in hlapi_formatted_results["max"].items()
                if k in integer_sizes_fetched
            }

        generic_arrays = generic_formatter.generate_array(
            formatted_results,
            OperandType.CipherText,
            included_types=[
                RustType.FheUint64,
            ],
        )

        resulting_array = generic_arrays[0]
        resulting_array.replace_column_name(
            RustType.FheUint64.name, case_config.backend.name
        )
        backend_arrays.append(resulting_array)

    print(f"Generating comparison array")

    backend_arrays[0].extend(
        *backend_arrays[1:], ops_column_name=OPERATION_SIZE_COLUMN_HEADER
    )

    return [
        backend_arrays[0],
    ]
