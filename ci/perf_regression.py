"""
perf_regression
---------------

This script allows zama-ai developers to run performance regression benchmarks.
It is capable of launching any performance benchmarks available in `tfhe-benchmark` crate.
Used in a GitHub action workflow, it can parse an issue comment and generate arguments to be fed
to a `cargo bench` command.

To define what to run and where, a TOML file is used to define targets, check `ci/regression.toml` to have an
explanation of all possible fields.
One can also provide a fully custom profile via the issue comment string see: func:`parse_issue_comment` for details.

This script is also capable of checking for performance regression based on previous benchmarks results.
It works by providing a result file containing the baseline values and the results of the last run.
Alongside this mode, a performance report can be generated to help identify potential regressions.
"""

import argparse
import enum
import json
import math
import pathlib
import statistics
import sys
import tomllib
from dataclasses import dataclass

from py_markdown_table.markdown_table import markdown_table

parser = argparse.ArgumentParser()
parser.add_argument(
    "command",
    choices=["parse_profile", "check_regression"],
    help="Command to run",
)
parser.add_argument(
    "--issue-comment",
    dest="issue_comment",
    help="GitHub issue comment defining the regression benchmark profile to use",
)
parser.add_argument(
    "--results-file",
    dest="results_file",
    help="Path to the results file containing the baseline and last run results",
)
parser.add_argument(
    "--generate-report",
    dest="generate_report",
    action="store_true",
    default=False,
    help="Generate markdown report of the regression check",
)

COMMENT_IDENTIFIER = "/bench"

SECONDS_IN_NANO = 1e9
MILLISECONDS_IN_NANO = 1e6
MICROSECONDS_IN_NANO = 1e3

CWD = pathlib.Path(__file__).parent
REPO_ROOT = CWD.parent
PROFILE_DEFINITION_PATH = CWD.joinpath("regression.toml")
BENCH_TARGETS_PATH = REPO_ROOT.joinpath("tfhe-benchmark/Cargo.toml")
# Files generated after parsing an issue comment
GENERATED_COMMANDS_PATH = CWD.joinpath("perf_regression_generated_commands.json")
CUSTOM_ENV_PATH = CWD.joinpath("perf_regression_custom_env.sh")


class ProfileOption(enum.Enum):
    Backend = 1
    RegressionProfile = 2
    Slab = 3
    BenchmarkTarget = 4
    EnvironmentVariable = 5

    @staticmethod
    def from_str(label):
        match label.lower():
            case "backend":
                return ProfileOption.Backend
            case "profile" | "regression-profile" | "regression_profile":
                return ProfileOption.RegressionProfile
            case "slab":
                return ProfileOption.Slab
            case "target":
                return ProfileOption.BenchmarkTarget
            case "env":
                return ProfileOption.EnvironmentVariable
            case _:
                raise NotImplementedError


class TfheBackend(enum.StrEnum):
    Cpu = "cpu"
    Gpu = "gpu"
    Hpu = "hpu"  # Only v80 is supported for now

    @staticmethod
    def from_str(label):
        match label.lower():
            case "cpu":
                return TfheBackend.Cpu
            case "gpu":
                return TfheBackend.Gpu
            case "hpu":
                return TfheBackend.Hpu
            case _:
                raise NotImplementedError


def parse_toml_file(path):
    """
    Parse TOML file.

    :param path: path to TOML file
    :return: file content as :class:`dict`
    """
    try:
        return tomllib.loads(pathlib.Path(path).read_text())
    except tomllib.TOMLDecodeError as err:
        raise RuntimeError(f"failed to parse definition file (error: {err})")


def _parse_bench_targets():
    parsed = {}

    for item in parse_toml_file(BENCH_TARGETS_PATH)["bench"]:
        bench_name = item["name"]
        key = bench_name.title().replace("-", "").replace("_", "")
        parsed[key] = bench_name

    return enum.Enum("TargetOption", parsed)


# This Enum is built at runtime to ensure we have the most up-to-date benchmark targets.
TargetOption = _parse_bench_targets()


class SlabOption(enum.Enum):
    Backend = 1
    Profile = 2

    @staticmethod
    def from_str(label):
        match label.lower():
            case "backend":
                return SlabOption.Backend
            case "profile":
                return SlabOption.Profile
            case _:
                raise NotImplementedError


class EnvOption(enum.StrEnum):
    FastBench = "__TFHE_RS_FAST_BENCH"
    BenchOpFlavor = "__TFHE_RS_BENCH_OP_FLAVOR"
    BenchType = "__TFHE_RS_BENCH_TYPE"
    BenchParamType = "__TFHE_RS_PARAM_TYPE"
    BenchParamsSet = "__TFHE_RS_PARAMS_SET"

    @staticmethod
    def from_str(label):
        match label.lower():
            case "fast_bench":
                return EnvOption.FastBench
            case "bench_op_flavor":
                return EnvOption.BenchOpFlavor
            case "bench_type":
                return EnvOption.BenchType
            case "bench_param_type":
                return EnvOption.BenchParamType
            case "bench_params_set":
                return EnvOption.BenchParamsSet
            case _:
                raise NotImplementedError


def _parse_option_content(content):
    key, _, value = content.partition("=")
    return key, value


class ProfileDefinition:
    def __init__(self, tfhe_rs_targets: list[dict]):
        """
        Regression profile definition builder capable of generating Cargo commands and custom environment variables for
        benchmarks to run.

        :param tfhe_rs_targets: parsed TOML from tfhe-benchmark crate containing cargo targets definition
        """
        self.backend = None
        self.regression_profile = "default"
        self.targets = {}
        self.slab_backend = None
        self.slab_profile = None

        self.env_vars = {
            EnvOption.FastBench: "false",
            EnvOption.BenchOpFlavor: "default",
            EnvOption.BenchType: "latency",
            EnvOption.BenchParamType: "classical",
            EnvOption.BenchParamsSet: "default",
        }

        # TargetOption.check_targets_consistency(tfhe_rs_targets)

        self.tfhe_rs_targets = self._build_tfhe_rs_targets(tfhe_rs_targets)

    def __str__(self):
        return f"ProfileDefinition(backend={self.backend}, regression_profile={self.regression_profile}, targets={self.targets}, slab_backend={self.slab_backend}, slab_profile={self.slab_profile}, env_vars={self.env_vars})"

    def set_field_from_option(self, option: ProfileOption, value: str):
        """
        Set a profile definition field based on a user input value.

        :param option: profile option field
        :param value: profile option value
        """
        match option:
            case ProfileOption.Backend:
                self.backend = TfheBackend.from_str(value)
            case ProfileOption.RegressionProfile:
                self.regression_profile = value
            case ProfileOption.BenchmarkTarget:
                key, value = _parse_option_content(value)
                for target_option in TargetOption:
                    if target_option.value == key:
                        trgt = TargetOption
                        operations = value.replace(" ", "").split(",")
                        try:
                            self.targets[trgt].extend(operations)
                        except KeyError:
                            self.targets[trgt] = operations
                        break
                else:
                    raise KeyError(f"unknown benchmark target `{key}`")
            case ProfileOption.Slab:
                key, value = _parse_option_content(value)
                if key == "backend":
                    self.slab_backend = value
                elif key == "profile":
                    self.slab_profile = value
            case ProfileOption.EnvironmentVariable:
                key, value = _parse_option_content(value)
                self.env_vars[EnvOption.from_str(key)] = value
            case _:
                raise NotImplementedError

    def set_defaults_from_definitions_file(self, definitions: dict):
        """
        Set profile definition fields based on definitions file.

        :param definitions: definitions parsed form file.
        """
        base_error_msg = "failed to set regression profile values"

        if not self.backend:
            raise ValueError(f"{base_error_msg}: no backend specified")

        try:
            backend_defs = definitions[self.backend]
        except KeyError:
            raise KeyError(
                f"{base_error_msg}: no definitions found for `{self.backend}` backend"
            )

        try:
            profile_def = backend_defs[self.regression_profile]
        except KeyError:
            raise KeyError(
                f"{base_error_msg}: no definition found for `{self.backend}.{self.regression_profile}` profile"
            )

        for key, value in profile_def.items():
            try:
                option = ProfileOption.from_str(key)
            except NotImplementedError:
                print(
                    f"ignoring unknown option name `{key}` in definition `{self.backend}.{self.regression_profile}`"
                )
                continue

            match option:
                case ProfileOption.BenchmarkTarget:
                    for target_key, ops in value.items():
                        for target_option in TargetOption:
                            if target_option.value == target_key:
                                trgt = target_option
                                if trgt not in self.targets:
                                    self.targets[trgt] = ops
                                break
                        else:
                            raise KeyError(f"unknown benchmark target `{target_key}`")
                case ProfileOption.Slab:
                    for slab_key, val in value.items():
                        if slab_key == "backend":
                            self.slab_backend = val
                        elif slab_key == "profile":
                            self.slab_profile = val
                case ProfileOption.EnvironmentVariable:
                    for env_key, val in value.items():
                        self.env_vars[EnvOption.from_str(env_key)] = val
                case _:
                    continue

    def _build_tfhe_rs_targets(self, tfhe_rs_targets: list[dict]):
        targets = {}
        for key in TargetOption:
            required_features = []
            for item in tfhe_rs_targets:
                if item["name"] == key.value:
                    required_features = item["required-features"]
                    break

            targets[key] = {"target": key.value, "required_features": required_features}

        return targets

    def _build_features(self, target):
        features = self.tfhe_rs_targets[target]["required_features"]

        match self.backend:
            case TfheBackend.Cpu:
                features.append("nightly-avx512")
            case TfheBackend.Gpu:
                features.extend(["gpu", "nightly-avx512"])
            case TfheBackend.Hpu:
                features.extend(["hpu", "hpu-v80"])

        features.append("pbs-stats")

        return features

    def generate_cargo_commands(self):
        """
        Generate Cargo commands to run benchmarks.

        :return: :class:`list` of :class:`str` of Cargo commands
        """
        commands = []
        for key, ops in self.targets.items():
            features = self._build_features(key)
            ops_filter = [f"::{op}::" for op in ops]
            commands.append(
                f"--bench {self.tfhe_rs_targets[key]["target"]} --features={','.join(features)} -- '{"\\|".join(ops_filter)}'"
            )

        return commands


def parse_issue_comment(comment):
    """
    Parse GitHub issue comment string. To be parsable, the string must be formatted as:
    `/bench <benchmark_args>`.

    Note that multiline command and group of commands are not supported.

    :param comment: :class:`str`

    :return: :class:`list` of (:class:`ProfileOption`, :class:`str`)
    """
    identifier, profile_arguments = comment.split(" ", maxsplit=1)

    if identifier != COMMENT_IDENTIFIER:
        raise ValueError(
            f"unknown issue comment identifier (expected: `{COMMENT_IDENTIFIER}`, got `{identifier}`)"
        )

    arguments_pairs = []
    for raw_pair in profile_arguments.split("--")[1:]:
        name, value = raw_pair.split(" ", maxsplit=1)
        try:
            profile_option = ProfileOption.from_str(name)
        except NotImplementedError:
            raise ValueError(f"unknown profile option `{name}`")
        else:
            arguments_pairs.append((profile_option, value.strip()))

    return arguments_pairs


def build_definition(profile_args_pairs, profile_defintions):
    """
    Build regression profile definition form user inputs and definitions file.

    :param profile_args_pairs: pairs of profile options and their value parsed from a string
    :param profile_defintions: parsed profile definitions file

    :return: :class:`ProfileDefinition`
    """
    bench_targets = parse_toml_file(BENCH_TARGETS_PATH)["bench"]
    definition = ProfileDefinition(bench_targets)

    for profile_option, value in profile_args_pairs:
        definition.set_field_from_option(profile_option, value)

    definition.set_defaults_from_definitions_file(profile_defintions)

    return definition


def write_commands_to_file(commands):
    """
    Write commands to a file.
    This file is meant to be read a string and passed to `toJSON()` GitHub actions function.

    :param commands: :class:`list` of commands to write
    """
    with GENERATED_COMMANDS_PATH.open("w") as f:
        f.write("[")
        for command in commands[:-1]:
            f.write(f'"{command}", ')
        f.write(f'"{commands[-1]}"]')


def write_env_to_file(env_vars: dict[EnvOption, str]):
    """
    Write environment variables to a file.
    This file is meant to be executed in a GitHub actions function. The variable contained in it, would be sent to
    a GITHUB_ENV file thus the following workflow steps would be able to use these variables.

    :param env_vars: dict of environment variables to write
    """
    with CUSTOM_ENV_PATH.open("w") as f:
        if not env_vars:
            f.write("echo 'no env vars to set';\n")
            return

        for key, v in env_vars.items():
            f.write(f'echo "{key.value}={v}";')


def write_backend_config_to_file(backend, profile):
    """
    Write backend and profile configuration to different files to ease parsing.

    :param backend:
    :param profile:
    :return:
    """
    for filepart, content in [("backend", backend), ("profile", profile)]:
        pathlib.Path(f"ci/perf_regression_slab_{filepart}_config.txt").write_text(
            f"{content}\n"
        )


def write_regression_config_to_file(tfhe_rs_backend, regression_profile):
    """
    Write tfhe-rs backend and regression configuration to different files to ease parsing.

    :param backend:
    :param profile:
    :return:
    """
    for filepart, content in [
        ("tfhe_rs_backend", tfhe_rs_backend),
        ("selected_profile", regression_profile),
    ]:
        pathlib.Path(f"ci/perf_regression_{filepart}_config.txt").write_text(
            f"{content}\n"
        )


# Scale factor to improve the signal/noise ratio in anomaly detection.
MAJOR_CHANGE_SCALE_FACTOR = 4
MINOR_CHANGE_SCALE_FACTOR = 2
REGRESSION_REPORT_FILE = CWD.joinpath("regression_report.md")


class PerfChange(enum.StrEnum):
    NoChange = "no changes"
    MinorImprovement = "minor improvement"
    MajorImprovement = "improvement"
    MinorRegression = "minor regression"
    MajorRegression = "regression"

    def get_emoji(self):
        match self:
            case PerfChange.NoChange:
                return ":heavy_minus_sign:"
            case PerfChange.MinorImprovement:
                return ":white_check_mark:"
            case PerfChange.MajorImprovement:
                return ":heavy_check_mark:"
            case PerfChange.MinorRegression:
                return ":warning:"
            case PerfChange.MajorRegression:
                return ":bangbang:"


@dataclass
class OperationPerformance:
    name: str
    baseline_mean: float
    baseline_stdev: float
    head_branch_value: float
    change_percentage: float
    change_type: PerfChange = PerfChange.NoChange

    def __init__(self, name: str, baseline_data: list[float], head_branch_value: float):
        self.name = name
        self.baseline_mean = round(statistics.mean(baseline_data), 2)
        self.baseline_stdev = round(statistics.stdev(baseline_data), 2)
        self.head_branch_value = head_branch_value

    def compute_change(self):
        self.change_percentage = round(
            (self.head_branch_value - self.baseline_mean) / self.baseline_mean * 100, 2
        )

        major_threshold = MAJOR_CHANGE_SCALE_FACTOR * self.baseline_stdev
        minor_threshold = MINOR_CHANGE_SCALE_FACTOR * self.baseline_stdev

        if self.head_branch_value > self.baseline_mean + major_threshold:
            self.change_type = PerfChange.MajorRegression
        elif self.head_branch_value > self.baseline_mean + minor_threshold:
            self.change_type = PerfChange.MinorRegression
        elif (self.head_branch_value < self.baseline_mean + minor_threshold) and (
            self.head_branch_value > self.baseline_mean - minor_threshold
        ):
            # Between +/- MINOR_CHANGE_SCALE_FACTOR * Std_dev we consider there is no change
            self.change_type = PerfChange.NoChange
        if self.head_branch_value < self.baseline_mean - minor_threshold:
            self.change_type = PerfChange.MinorImprovement
        elif self.head_branch_value < self.baseline_mean - major_threshold:
            self.change_type = PerfChange.MajorImprovement

        return self.change_percentage, self.change_type

    def change_percentage_as_str(self):
        if (
            self.change_type == PerfChange.MajorImprovement
            or self.change_type == PerfChange.MinorImprovement
            or (
                self.change_type == PerfChange.NoChange
                and (self.head_branch_value < self.baseline_mean)
            )
        ):
            sign = ""
        else:
            # Minus sign is already embedded in the float value.
            sign = "+"

        return f"{sign}{self.change_percentage}%"


def convert_value_to_readable_text(value: float, max_digits=3):
    """
    Convert timing in nanoseconds to the highest unit usable.

    :param value: timing value
    :param max_digits: number of digits to keep in the final representation of the value

    :return: human-readable value with unit as :class:`str`
    """
    if value > SECONDS_IN_NANO:
        converted_parts = (value / SECONDS_IN_NANO), "s"
    elif value > MILLISECONDS_IN_NANO:
        converted_parts = (value / MILLISECONDS_IN_NANO), "ms"
    elif value > MICROSECONDS_IN_NANO:
        converted_parts = (value / MICROSECONDS_IN_NANO), "us"
    else:
        converted_parts = value, "ns"

    power_of_10 = math.floor(math.log10(converted_parts[0]))
    rounding_digit = max_digits - (power_of_10 + 1)
    if converted_parts[0] >= 100.0:
        rounding_digit = None

    return f"{round(converted_parts[0], rounding_digit)} {converted_parts[1]}"


def check_performance_changes(results_file: pathlib.Path):
    """
    Check if any operation has regressed compared to the base branch.

    Results file must be in JSON format with the following structure:

    ```json
    {
      "backend": "<tfhe-rs_backend>",
      "profile": "<regression_profile>",
      "operation": [
        {
          "name": "<operation_name>",
          "bit_size": <int>,
          "params": "<parameters_alias>",

          "results": {
            "base": {
              "name": "<base_branche_name>",
              "data": [
                <float>,
                <float>,
                ...,
              ]
            },
            "head": {
              "name": "<dev_branch_name>",
              "value": <float>
            }
          }
        }
      ]
    }
    ```

    :param results_file: path to the result file
    :type results_file: pathlib.Path

    :return: :class:`list` of :class:`OperationPerformance`
    """
    changes = []

    results = json.loads(results_file.read_text())
    for operation in results["operations"]:
        op_name = operation["name"]
        try:
            baseline_data = operation["results"]["base"]["data"]
        except KeyError:
            raise KeyError(
                f"no base branch data found in results file for '{op_name}' operation"
            )

        try:
            head_branch_value = operation["results"]["head"]["value"]
        except KeyError:
            raise KeyError(
                f"no head branch value found in results file for '{op_name}' operation"
            )

        op_perf = OperationPerformance(op_name, baseline_data, head_branch_value)
        op_perf.compute_change()
        changes.append(op_perf)

    return changes, results["backend"], results["profile"]


OPERATION_HEADER = "Operation"
CURRENT_VALUE_HEADER = "Current (ms)"
BASELINE_VALUE_HEADER = "Baseline (ms)"
BASELINE_STDDEV_HEADER = "Baseline Stddev (ms)"
CHANGE_HEADER = "Change (%)"
STATUS_HEADER = "Status"


def generate_regression_report(
    ops_performances: list[OperationPerformance], backend: str, profile: str
):
    """
    Generate a regression report in Markdown format and write it to a specified file.

    This function analyzes performance data for various operations and generates a Markdown
    formatted report summarizing the performance. It highlights any major regressions by
    providing detailed data about the affected operations and overall benchmark results.
    Additionally, it includes configuration details, such as the backend and regression profile
    used in the analysis.

    :param ops_performances: A list of performance data for operations to be analyzed
        and summarized.
    :type ops_performances: list[OperationPerformance]
    :param backend: The backend being used in the performance analysis.
    :type backend: str
    :param profile: The profile identifying the regression analysis configuration.
    :type profile: str
    """
    full_data = [
        {
            OPERATION_HEADER: op.name,
            CURRENT_VALUE_HEADER: convert_value_to_readable_text(op.head_branch_value),
            BASELINE_VALUE_HEADER: convert_value_to_readable_text(op.baseline_mean),
            BASELINE_STDDEV_HEADER: convert_value_to_readable_text(op.baseline_stdev),
            CHANGE_HEADER: op.change_percentage_as_str(),
            STATUS_HEADER: " ".join((op.change_type.get_emoji(), op.change_type.value)),
        }
        for op in ops_performances
    ]
    full_array_markdown = (
        markdown_table(full_data)
        .set_params(row_sep="markdown", quote=False)
        .get_markdown()
    )

    regression_data = []
    for op in ops_performances:
        if op.change_type != PerfChange.MajorRegression:
            continue

        regression_data.append(
            {
                OPERATION_HEADER: op.name,
                CURRENT_VALUE_HEADER: convert_value_to_readable_text(
                    op.head_branch_value
                ),
                BASELINE_VALUE_HEADER: convert_value_to_readable_text(op.baseline_mean),
                CHANGE_HEADER: op.change_percentage_as_str(),
            }
        )

    comment_body = []

    if regression_data:
        regression_array_markdown = (
            markdown_table(regression_data)
            .set_params(row_sep="markdown", quote=False)
            .get_markdown()
        )

        regression_details = [
            "> [!CAUTION]",
            "> Performances for some operations have regressed compared to the base branch.",
            "",  # Add a newline since tables cannot be rendered in markdown note.
            regression_array_markdown,
            "",  # Add a newline to avoid rendering the next line of text into the array.
        ]
        comment_body.extend(regression_details)
    else:
        comment_body.append("No performance regression detected. :tada:")

    comment_body.append(
        "\n".join(
            [
                "Configuration",
                f"* backend: `{backend}`",
                f"* regression-profile: `{profile}`",
                "",
            ]
        )
    )

    all_results_details = [
        "<details>",
        "<summary><strong>View All Benchmarks</strong></summary>",
        "",
        full_array_markdown,
        "</details>",
    ]
    comment_body.extend(all_results_details)

    formatted_text = "\n".join(comment_body)

    try:
        REGRESSION_REPORT_FILE.write_text(formatted_text)
    except Exception as err:
        print(f"failed to write regression report (error: {err})")
        raise


if __name__ == "__main__":
    args = parser.parse_args()

    if args.command == "parse_profile":
        comment = args.issue_comment
        if not comment:
            print(
                f"cannot run `{args.command}` command: please specify the issue comment with `--issue-comment` argument"
            )
            sys.exit(1)

        try:
            profile_args_pairs = parse_issue_comment(comment)
            profile_definitions = parse_toml_file(PROFILE_DEFINITION_PATH)

            definition = build_definition(profile_args_pairs, profile_definitions)
            commands = definition.generate_cargo_commands()
        except Exception as err:
            print(f"failed to generate commands (error:{err})")
            sys.exit(2)

        try:
            write_commands_to_file(commands)
            write_env_to_file(definition.env_vars)
            write_backend_config_to_file(
                definition.slab_backend, definition.slab_profile
            )
            write_regression_config_to_file(
                definition.backend, definition.regression_profile
            )
        except Exception as err:
            print(f"failed to write commands/env to file (error:{err})")
            sys.exit(3)
    elif args.command == "check_regression":
        results_file = args.results_file
        if not results_file:
            print(
                f"cannot run `{args.command}` command: please specify the results file path with `--results-file` argument"
            )
            sys.exit(1)

        results_file_path = pathlib.Path(results_file)
        perf_changes, backend, profile = check_performance_changes(results_file_path)

        if args.generate_report:
            try:
                generate_regression_report(perf_changes, backend, profile)
            except Exception:
                sys.exit(4)

# TODO Add unittests primarly to check if commands and env generated are correct.
