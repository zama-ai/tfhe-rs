"""
perf_regression
---------------

TODO add documentation
"""

import argparse
import enum
import pathlib
import sys
import tomllib

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

COMMENT_IDENTIFIER = "/bench"
PROFILE_DEFINITION_PATH = pathlib.Path("ci/regression.toml")
BENCH_TARGETS_PATH = pathlib.Path("tfhe-benchmark/Cargo.toml")

USER_TO_TFHE_TARGETS = {
    "boolean": "boolean-bench",
    "shortint": "shortint-bench",
    "oprf": "oprf-shortint-bench",
    "comp-shortint": "glwe_packing_compression-shortint-bench",
    "comp-integer": "glwe_packing_compression-integer-bench",
    "hlapi": "hlapi",
    "erc20": "hlapi-erc20",
    "dex": "hlapi-dex",
    "integer": "integer-bench",
    "integer-signed": "integer-signed-bench",
    "zk": "zk-pke-bench",
    "ks": "ks-bench",
    "pbs": "pbs-bench",
    "ks-pbs": "ks-pbs-bench",
    "ms-noise-reduc": "modulus_switch_noise_reduction",
    "pbs128": "pbs128-bench",
}


def check_targets_consistency(bench_targets: list[dict]):
    missing_targets = {}

    print("Checking targets consistency...")
    tfhe_rs_target_names = [item["name"] for item in bench_targets]
    for key, target_name in USER_TO_TFHE_TARGETS.items():
        if target_name not in tfhe_rs_target_names:
            missing_targets[key] = target_name

    if missing_targets:
        print("Inconsistent targets:")
        for key, missing_name in missing_targets.items():
            print(f"tfhe-benchmark target `{missing_name}` not found in {BENCH_TARGETS_PATH} (user target associated: `{key}`)")
        raise KeyError("tfhe-benchmark targets inconsistent")

class ProfileOption(enum.Enum):
    Backend = 1
    RegressionProfile = 2
    Slab = 3
    BenchmarkTarget = 4

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
            case _:
                raise NotImplementedError


class TargetOption(enum.Enum):
    Boolean = 1
    Shortint = 2
    Oprf = 3
    CompShortint = 4
    CompInteger = 5
    HLApi = 6
    Erc20 = 7
    Dex = 8
    Integer = 9
    IntegerSigned = 10
    ZK = 11
    KS = 12
    PBS = 13
    KSPBS = 14
    MsNoiseReduction = 15
    Pbs128 = 16

    @staticmethod
    def from_str(label):
        match label.lower():
            case "boolean":
                return TargetOption.Boolean
            case "shortint":
                return TargetOption.Shortint
            case "oprf":
                return TargetOption.Oprf
            case "comp-shortint":
                return TargetOption.CompShortint
            case "comp-integer":
                return TargetOption.CompInteger
            case "hlapi":
                return TargetOption.HLApi
            case "erc20":
                return TargetOption.Erc20
            case "dex":
                return TargetOption.Dex
            case "integer":
                return TargetOption.Integer
            case "integer-signed":
                return TargetOption.IntegerSigned
            case "zk":
                return TargetOption.ZK
            case "ks":
                return TargetOption.KS
            case "pbs":
                return TargetOption.PBS
            case "ks-pbs":
                return TargetOption.KSPBS
            case "ms-noise-reduc":
                return TargetOption.MsNoiseReduction
            case "pbs128":
                return TargetOption.Pbs128
            case _:
                raise NotImplementedError


class SlabOption(enum.Enum):
    Backend = 1
    Profile = 2

    @staticmethod
    def from_str(label):
        match label.lower():
            case "backend":
                return SlabOption.Backend
            case "profiler":
                return SlabOption.Profile
            case _:
                raise NotImplementedError


def _parse_option_content(content):
    key, _, value = content.partition("=")
    return key, value


class ProfileDefinition:
    def __init__(self, tfhe_rs_targets: list[dict]):
        self.backend = None
        self.regression_profile = "default"
        self.targets = {}
        self.slab_backend = None
        self.slab_profile = None

        check_targets_consistency(tfhe_rs_targets)
        self.tfhe_rs_targets = self._build_tfhe_rs_targets(tfhe_rs_targets)
        print("TARGETS:", self.tfhe_rs_targets)  # DEBUG

    def __str__(self):
        return f"ProfileDefinition(backend={self.backend}, regression_profile={self.regression_profile}, targets={self.targets}, slab_backend={self.slab_backend}, slab_profile={self.slab_profile})"

    def set_field_from_option(self, option: ProfileOption, value: str):
        match option:
            case ProfileOption.Backend:
                self.backend = value
            case ProfileOption.RegressionProfile:
                self.regression_profile = value
            case ProfileOption.BenchmarkTarget:
                key, value = _parse_option_content(value)
                operations = value.replace(" ", "").split(",")
                try:
                    self.targets[key].extend(operations)
                except KeyError:
                    self.targets[key] = operations
            case ProfileOption.Slab:
                key, value = _parse_option_content(value)
                if key == "backend":
                    self.slab_backend = value
                elif key == "profile":
                    self.slab_profile = value
            case _:
                raise NotImplementedError

    def set_defaults_from_definitions_file(self, definitions: dict):
        base_error_msg = "failed to set regression profile values"

        if not self.backend:
            print(f"{base_error_msg}: no backend specified")
            sys.exit(
                3
            )  # TODO raise error instead of quitting program, let __main__ handle the errors

        try:
            backend_defs = definitions[self.backend]
        except KeyError:
            print(
                f"{base_error_msg}: no definitions found for `{self.backend}` backend"
            )
            sys.exit(3)

        try:
            profile_def = backend_defs[self.regression_profile]
        except KeyError:
            print(
                f"{base_error_msg}: no definition found for `{self.backend}.{self.regression_profile}` profile"
            )
            sys.exit(3)

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
                        if target_key not in self.targets:
                            self.targets[target_key] = ops
                case ProfileOption.Slab:
                    for slab_key, val in value.items():
                        if slab_key == "backend":
                            self.slab_backend = val
                        elif slab_key == "profile":
                            self.slab_profile = val
                case _:
                    continue

    def _build_tfhe_rs_targets(self, tfhe_rs_targets: list[dict]):
        targets = {}
        for key, value in USER_TO_TFHE_TARGETS.items():
            required_features = []
            for item in tfhe_rs_targets:
                if item["name"] == value:
                    required_features = item["required-features"]
                    break

            targets[key] = {"target": value, "required_features": required_features}

        return targets

        # TODO gérer le cas où hpu-<custom> est fourni en tant que backend
        #  on doit avoir "hpu,hpu-<custom>" dans la suite de features
        # TODO ajouter "nightly-avx512" si le backend est cpu|gpu

    def _build_operation_filter(self):
        pass

    def generate_cargo_commands(self):
        pass


def parse_issue_comment(comment):
    identifier, profile_arguments = comment.split(" ", maxsplit=1)

    if identifier != COMMENT_IDENTIFIER:
        print(
            f"unknown issue comment identifier (expected: `{COMMENT_IDENTIFIER}`, got `{identifier}`)"
        )
        sys.exit(2)

    arguments_pairs = []
    for raw_pair in profile_arguments.split("--")[1:]:
        name, value = raw_pair.split(" ", maxsplit=1)
        try:
            profile_option = ProfileOption.from_str(name)
        except NotImplementedError:
            print(f"unknown profile option `{name}`")
            sys.exit(2)
        else:
            arguments_pairs.append((profile_option, value.strip()))

    return arguments_pairs


def parse_toml_file(path):
    try:
        return tomllib.loads(pathlib.Path(path).read_text())
    except tomllib.TOMLDecodeError as err:
        print(f"failed to parse definition file (error: {err})")
        sys.exit(3)


def build_definition(profile_args_pairs, profile_defintions):
    bench_targets = parse_toml_file(BENCH_TARGETS_PATH)["bench"]
    definition = ProfileDefinition(bench_targets)

    for profile_option, value in profile_args_pairs:
        definition.set_field_from_option(profile_option, value)

    print("Before defaults: ", definition)  # DEBUG

    definition.set_defaults_from_definitions_file(profile_defintions)

    print("After  defaults: ", definition)  # DEBUG


# Doit être capable de parser un commentaire d'issue
# puis de sortir les commandes cargo à exécuter

# Doit être capable de faire les calculs de régression si on lui donne une série de données
# est-ce qu'il doit récupérer les données lui même ?

if __name__ == "__main__":
    args = parser.parse_args()

    if args.command == "parse_profile":
        comment = args.issue_comment
        if not comment:
            print(
                f"cannot run `{args.command}` command: please specify the issue comment with `--issue-comment` argument"
            )
            sys.exit(1)

        profile_args_pairs = parse_issue_comment(comment)
        profile_definitions = parse_toml_file(PROFILE_DEFINITION_PATH)
        print(profile_definitions)

        build_definition(profile_args_pairs, profile_definitions)
