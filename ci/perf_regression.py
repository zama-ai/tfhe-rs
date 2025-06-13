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

class ProfileOption(enum.Enum):
    Backend = 1
    RegressionProfile = 2
    # IntegerOps = 3
    # TODO implement other operations layers support
    #  IntegerZkOps
    #  HighLevelApiOps
    #  HighLevelApiDexOps
    #  HighLevelApiErc20Ops
    #  ...
    Slab = 3
    BenchmarkTarget = 4

    @staticmethod
    def from_str(label):
        match label.lower():
            case 'backend':
                return ProfileOption.Backend
            case 'profile' | 'regression-profile'| 'regression_profile':
                return ProfileOption.RegressionProfile
            case 'slab':
                return ProfileOption.Slab
            case 'target':
                return ProfileOption.BenchmarkTarget
            case _:
                raise NotImplementedError

class TargetOption(enum.Enum):
    Integer = 1
    HLApi = 2
    Dex = 3
    Erc20 = 4
    # TODO implement other targets

    @staticmethod
    def from_str(label):
        match label.lower():
            case 'integer':
                return TargetOption.Integer
            case 'hlapi':
                return TargetOption.HLApi
            case 'dex':
                return TargetOption.Dex
            case 'erc20':
                return TargetOption.Erc20
            case _:
                raise NotImplementedError

class SlabOption(enum.Enum):
    Backend = 1
    Profile = 2

    @staticmethod
    def from_str(label):
        match label.lower():
            case 'backend':
                return SlabOption.Backend
            case 'profiler':
                return SlabOption.Profile
            case _:
                raise NotImplementedError

class ProfileDefinition:
    def __init__(self, bench_targets: list[dict]):
        self.backend = None
        self.regression_profile = "default"
        self.integer_ops_list = []
        self.slab_instance_provider = None
        self.slab_profile = None

        self.bench_targets = bench_targets

    def __str__(self):
        return f"ProfileDefinition(backend={self.backend}, regression_profile={self.regression_profile}, integer_ops={self.integer_ops_list}, slab_instance_provider={self.slab_instance_provider}, slab_profile={self.slab_profile})"
    def set_field_from_option(self, option: ProfileOption, value: str):
        match option:
            case ProfileOption.Backend:
                self.backend = value
            case ProfileOption.RegressionProfile:
                self.regression_profile = value
            case ProfileOption.IntegerOps:
                self.integer_ops_list = self._list_from_str(value)
            case _:
                raise NotImplementedError

    def set_defaults_from_definitions_file(self, definitions: dict):
        base_error_msg = "failed to set regression profile values"

        if not self.backend:
            print(f"{base_error_msg}: no backend specified")
            sys.exit(3) # TODO raise error instead of quitting program, let __main__ handle the errors

        try:
            backend_defs = definitions[self.backend]
        except KeyError:
            print(f"{base_error_msg}: no definitions found for `{self.backend}` backend")
            sys.exit(3)

        try:
            profile_def = backend_defs[self.regression_profile]
        except KeyError:
            print(f"{base_error_msg}: no definition found for `{self.backend}.{self.regression_profile}` profile")
            sys.exit(3)

        for key, value in profile_def.items():
            try:
                option = ProfileOption.from_str(key)
            except NotImplementedError:
                print(f"ignoring unknown option name `{key}` in definition `{self.backend}.{self.regression_profile}`")
                continue

            match option:
                case ProfileOption.IntegerOps:
                    if not self.integer_ops_list:
                        self.integer_ops_list = value
                case ProfileOption.SlabInstanceProvider:
                    if not self.slab_instance_provider:
                        self.slab_instance_provider = value
                case ProfileOption.SlabProfile:
                    if not self.slab_profile:
                        self.slab_profile = value
                case _:
                    continue

    @staticmethod
    def _list_from_str(value: str):
        if value.startswith('[') and value.endswith(']'):
            parts = value.lstrip('[').rstrip(']').split(",")
            return [p.strip() for p in parts]
        else:
            print(f"string is not formatted as list (value: {value})")
            sys.exit(3)

    # TODO il faut récupérer la target de bench a exécuter, et en fonction de cette dernière, on peut récupérer les required_features associées dans tfhe-benchmark/Cargo.toml
    def _get_target(self):
        pass

    def _build_tfhe_features(self, bench_target):
        # TODO gérer le cas où hpu-<custom> est fourni en tant que backend
        #  on doit avoir "hpu,hpu-<custom>" dans la suite de features
        # TODO ajouter "nightly-avx512" si le backend est cpu|gpu
        pass

    def _build_operation_filter(self):
        pass

    def generate_cargo_commands(self):
        pass

def parse_issue_comment(comment):
    identifier, profile_arguments = comment.split(" ", maxsplit=1)

    if identifier != COMMENT_IDENTIFIER:
        print(f"unknown issue comment identifier (expected: `{COMMENT_IDENTIFIER}`, got `{identifier}`)")
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

    print(arguments_pairs)  # DEBUG
    return arguments_pairs

def parse_toml_file(path):
    try:
        return tomllib.loads(pathlib.Path(path).read_text())
    except tomllib.TOMLDecodeError as err:
        print(f'failed to parse definition file (error: {err})')
        sys.exit(3)


def build_definition(profile_args_pairs, profile_defintions):
    bench_targets = parse_toml_file(BENCH_TARGETS_PATH)['bench']
    definition = ProfileDefinition(bench_targets)

    for profile_option, value in profile_args_pairs:
        definition.set_field_from_option(profile_option, value)

    print(definition)

    definition.set_defaults_from_definitions_file(profile_defintions)

    print(definition)

# Doit être capable de parser un commentaire d'issue
# puis de sortir les commandes cargo à exécuter

# Doit être capable de faire les calculs de régression si on lui donne une série de données
# est-ce qu'il doit récupérer les données lui même ?

if __name__ == "__main__":
    args = parser.parse_args()

    if args.command == "parse_profile":
        comment = args.issue_comment
        if not comment:
            print(f"cannot run `{args.command}` command: please specify the issue comment with `--issue-comment` argument")
            sys.exit(1)

        profile_args_pairs = parse_issue_comment(comment)
        profile_definitions = parse_toml_file(PROFILE_DEFINITION_PATH)
        print(profile_definitions)

        build_definition(profile_args_pairs, profile_definitions)
