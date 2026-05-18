import collections
from collections.abc import Callable

from benchmark_specs import Backend, BenchDetails, BenchType, RustType
from formatters.common import BenchArray, GenericFormatter

import utils


class HlApiFormatter(GenericFormatter):
    """
    Formatter for arithmetic operations benchmarks.
    """

    @staticmethod
    def _format_data(data: dict[BenchDetails : list[int]], conversion_func):
        formatted = collections.defaultdict(
            lambda: {
                2: "N/A",
                4: "N/A",
                8: "N/A",
                10: "N/A",
                12: "N/A",
                14: "N/A",
                16: "N/A",
                32: "N/A",
                64: "N/A",
                128: "N/A",
            }
        )
        for details, timings in data.items():
            test_name = details.operation_name.lstrip("ops::")
            bit_width = details.bit_size
            value = conversion_func(timings[-1])
            formatted[test_name][bit_width] = value

        return formatted


TRANSFER_IMPLEM_COLUMN_HEADER = "Transfer implementation"


class Erc7984Formatter(HlApiFormatter):
    """
    Formatter for ERC7984 benchmarks.
    """

    @staticmethod
    def _format_data(data: dict[BenchDetails : list[int]], *args):
        formatted = collections.defaultdict(
            lambda: {
                BenchType.Latency: "N/A",
                BenchType.Throughput: "N/A",
            }
        )

        for details, timings in data.items():
            name_parts = details.operation_name.split("::")
            test_name = name_parts[name_parts.index("transfer") + 1]
            if "throughput" in name_parts:
                bench_type = BenchType.Throughput
                conversion_func = utils.convert_throughput_value_to_readable_text
            else:
                bench_type = BenchType.Latency
                conversion_func = utils.convert_latency_value_to_readable_text

            # For now ERC7984 benchmarks are only made on 64-bit ciphertexts.
            value = conversion_func(timings[-1])
            formatted[test_name][bench_type] = value

        return formatted

    def _generate_arrays(self, data, *args, **kwargs):
        first_column_header = TRANSFER_IMPLEM_COLUMN_HEADER

        match self.backend:
            case Backend.HPU:
                op_names = ["whitepaper", "hpu_optim", "hpu_simd"]
            case _:
                op_names = ["whitepaper", "no_cmux", "overflow"]

        result_lines = []
        for op_name in op_names:
            line = {first_column_header: op_name}
            line.update({str(bench_type): v for bench_type, v in data[op_name].items()})
            result_lines.append(line)

        return [
            BenchArray(result_lines, self.layer),
        ]


OPERATIONS_DISPLAYS = [
    "get",
    "update",
    "map",
]

DEFAULT_STORE_SIZE = (
    2,
    4,
    8,
    16,
    32,
    64,
    128,
    256,
    512,
    1024,
)

DEFAULT_KVSTORE_VALUE_SIZE = lambda: {
    8: "N/A",
    16: "N/A",
    32: "N/A",
    64: "N/A",
    128: "N/A",
}


STORE_SIZE_COLUMN_HEADER = "Store size \\ Value"


class KVStoreFormatter(HlApiFormatter):
    """
    Formatter for Key-Value store benchmarks.
    """

    @staticmethod
    def _format_data(data: dict[BenchDetails : list[int]], conversion_func):
        results_dict = {}

        for op in OPERATIONS_DISPLAYS:
            results_dict[op] = {
                size: DEFAULT_KVSTORE_VALUE_SIZE() for size in DEFAULT_STORE_SIZE
            }

        for details, timings in data.items():
            test_name = details.operation_name.lstrip("kv_store::")
            # This is a hack to get the array size and the precision of the value.
            # It would be fixed once the data extractor would be rewritten in Rust
            # thanks to the benchmark specs.
            case_variation = details.rust_type.split("_")
            array_size = int(case_variation[-1])
            value_size = int(case_variation[-3].lstrip("FheUint"))
            value = conversion_func(timings[-1])
            results_dict[test_name][array_size][value_size] = value

        return results_dict

    def _generate_arrays(self, data, *args, **kwargs):
        first_column_header = STORE_SIZE_COLUMN_HEADER

        arrays = []

        for op_name in data.keys():
            result_lines = []
            for array_size, values in data[op_name].items():
                line = {first_column_header: str(array_size)}
                line.update(
                    {
                        RustType.from_int(bench_type).name: v
                        for bench_type, v in values.items()
                    }
                )
                result_lines.append(line)

            bench_array = BenchArray(result_lines, self.layer)
            bench_array.metadata = {"operation": op_name}
            arrays.append(bench_array)

        return arrays
