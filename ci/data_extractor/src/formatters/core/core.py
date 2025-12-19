import collections
from collections.abc import Callable

from benchmark_specs import (
    BenchDetails,
    CoreCryptoOperation,
    ErrorFailureProbability,
    NoiseDistribution,
    PBSKind,
)
from formatters.common import (
    OPERATION_PRECISION_COLUMN_HEADER,
    BenchArray,
    GenericFormatter,
)

OPERATIONS_DISPLAYS = [
    CoreCryptoOperation.PBS,
    CoreCryptoOperation.MultiBitPBS,
    CoreCryptoOperation.KeySwitchPBS,
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


class CoreFormatter(GenericFormatter):
    @staticmethod
    def _format_data(data: dict[BenchDetails : list[int]], conversion_func):
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

    @staticmethod
    def _format_data_with_available_sizes(
        data: dict[BenchDetails : list[int]], conversion_func
    ):
        formatted = collections.defaultdict(lambda: collections.defaultdict(lambda: {}))

        for details, timings in data.items():
            reduced_params = details.get_params_definition()
            test_name = details.operation_name
            bit_width = details.bit_size
            value = conversion_func(timings[-1])

            formatted[test_name][reduced_params][bit_width] = value

        return formatted

    def _generate_arrays(
        self,
        data,
        *args,
        **kwargs,
    ):
        supported_pfails = [
            ErrorFailureProbability.TWO_MINUS_64,
            ErrorFailureProbability.TWO_MINUS_128,
        ]
        noise_distributions = [
            NoiseDistribution.Gaussian,
            NoiseDistribution.TUniform,
        ]

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
                elif (
                    formatted_name == CoreCryptoOperation.PBS
                    or formatted_name == CoreCryptoOperation.KeySwitchPBS
                ) and param_definition.pbs_kind != PBSKind.Classical:
                    # Skip this operation since a classical operation cannot be done with any other parameters type.
                    continue

                grouping_factor = param_definition.grouping_factor
                if (
                    grouping_factor is not None
                    and grouping_factor != self.requested_grouping_factor
                ):
                    continue

                if param_definition.details["variation"] not in ["", "BENCH"]:
                    continue

                try:
                    sorted_results[key][formatted_name][precision] = value
                except KeyError:
                    # Operation is not supposed to appear in the formatted array.
                    continue

        first_column_header = OPERATION_PRECISION_COLUMN_HEADER

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
                    metadata={
                        "noise": key.noise_distribution,
                        "pfail": key.pfail,
                    },
                )
            )

        return arrays

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
