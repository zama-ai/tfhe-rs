import collections

from benchmark_specs import BenchDetails
from formatters import GenericFormatter


class HlApiFormatter(GenericFormatter):
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
