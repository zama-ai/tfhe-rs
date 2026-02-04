import argparse
import pathlib

from benchmark_specs import Backend, BenchSubset, BenchType, Layer, PBSKind


class UserConfig:
    """
    Manages the configuration provided by the user input.

    This class encapsulates the user-provided configuration data necessary for execution.
    It sets up various attributes based on the input arguments, converting or transforming
    values as needed to ensure compatibility and correct behavior within the system.

    :param input_args: The input arguments provided by the user.
    :type input_args: argparse.Namespace
    """

    def __init__(self, input_args: argparse.Namespace):
        self.output_file = input_args.output_file

        self.database = input_args.database
        self.backend = Backend.from_str(input_args.backend.lower())
        self.hardware = input_args.hardware  # This input is case-sensitive

        self.head_branch = input_args.branch.lower()
        self.base_branch = input_args.base_branch.lower()

        self.project_version = input_args.project_version

        self.bench_date = input_args.bench_date
        self.time_span_days = input_args.time_span_days

        self.bench_type = BenchType.from_str(input_args.bench_type.lower())

        self.bench_subset = BenchSubset.from_str(input_args.bench_subset)

        self.name_suffix = input_args.name_suffix

        self.layer = Layer.from_str(input_args.layer.lower())
        self.pbs_kind = PBSKind.from_str(input_args.pbs_kind)
        self.grouping_factor = input_args.grouping_factor

        self.regression_selected_profile = input_args.regression_selected_profile
        self.regression_profiles_path = (
            pathlib.Path(input_args.regression_profiles)
            if input_args.regression_profiles
            else None
        )
