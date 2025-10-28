import pathlib
import sys

import config
import connector
from benchmark_specs import Backend, Layer
from exceptions import NoDataFound

import utils

try:
    import tomllib  # Python v3.11+
except ModuleNotFoundError:
    import pip._vendor.tomli as tomllib  # the same tomllib that's now included in Python v3.11+


def generate_json_regression_file(
    conn: connector.PostgreConnector,
    ops_filter: dict,
    user_config: config.UserConfig,
    params_filter: str = None,
):
    """
    Generate a JSON regression file based on benchmark data from specified branches
    and operations.

    This function extracts benchmark data for a set of operations across HEAD
    and BASE branches, processes it, and generates a structured JSON output
    representing the benchmarking comparison.

    :param conn: Connector to the benchmark data source.
    :type conn: Any
    :param ops_filter: A dictionary containing operations as keys and their
        respective filters as values.
    :type ops_filter: dict
    :param user_config: A configuration object that contains branch information,
        backend settings, and output preferences for regression.
    :type user_config: UserConfig
    :param params_filter: Optional parameter filter to be applied to the benchmark results
    :type params_filter: str, optional

    :raises NoDataFound: If benchmark data is not found for the HEAD or BASE branch
        during processing.
    :raises json.JSONDecodeError: If the final dictionary cannot be converted into
        JSON format.
    """
    error_msg = "Cannot generate JSON regression file (error: no data found on {} branch '{}' (layer: {}, operations: {}))"
    regression_data = {}

    for bench_target, ops in ops_filter.items():
        layer_name, _, bench_id = bench_target.partition("-")
        layer = Layer.from_str(layer_name)

        try:
            head_branch_data = conn.fetch_benchmark_data(
                user_config,
                operation_filter=ops,
                layer=layer,
                branch=user_config.head_branch,
                name_suffix="_mean_regression",
                last_value_only=True,
            )
        except NoDataFound:
            print(error_msg.format("HEAD", user_config.head_branch, layer, ops))
            raise

        if params_filter and layer != Layer.HLApi:
            head_branch_data = dict(
                filter(
                    lambda item: params_filter in item[0].params,
                    head_branch_data.items(),
                )
            )

        try:
            base_branch_data = conn.fetch_benchmark_data(
                user_config,
                operation_filter=ops,
                layer=layer,
                branch=user_config.base_branch,
                last_value_only=False,
            )
        except NoDataFound:
            print(error_msg.format("BASE", user_config.base_branch, layer, ops))
            raise

        for bench_details, values in head_branch_data.items():
            regression_data[bench_details.operation_name] = {
                "name": bench_details.operation_name,
                "bit_size": bench_details.bit_size,
                "params": bench_details.params,
                "results": {
                    "head": {"name": user_config.head_branch, "value": values[0]},
                },
            }

        for bench_details, values in base_branch_data.items():
            try:
                reg = regression_data[bench_details.operation_name]
                if (
                    reg["bit_size"] == bench_details.bit_size
                    and reg["params"] == bench_details.params
                ):
                    reg["results"]["base"] = {
                        "name": user_config.base_branch,
                        "data": values,
                    }
            except KeyError:
                # No value exists on the head branch for this key, ignoring the base branch result.
                continue

    final_dict = {
        "backend": user_config.backend,
        "profile": user_config.regression_selected_profile,
        "operations": list(regression_data.values()),
    }

    output_file = "".join([user_config.output_file, ".json"])
    utils.write_to_json(final_dict, output_file)


def parse_toml_file(
    path: str, backend: Backend, profile_name: str
) -> dict[str, list[str]]:
    """
    Parse a TOML file defining regression profiles and return its content as a dictionary.

    :param path: path to TOML file
    :type path: str
    :param backend: type of backend used for the benchmarks
    :type backend: Backend
    :param profile_name: name of the regression profile
    :type profile_name: str

    :return: profile content formatted as `{"<benchmark_target>": ["<operation_1>", ...]}`
    :rtype: dict[str, list[str]]
    """
    file_path = pathlib.Path(path)
    try:
        return tomllib.loads(file_path.read_text())[backend][profile_name]
    except tomllib.TOMLDecodeError as err:
        raise RuntimeError(f"failed to parse definition file (error: {err})")
    except KeyError:
        raise RuntimeError(
            f"failed to find definition profile (error: profile '{profile_name}' cannot be found in '{file_path}')"
        )


def perform_regression_json_generation(
    conn: connector.PostgreConnector, user_config: config.UserConfig
):
    """
    Generates a JSON file for regression testing based on the selected regression profile.

    This function generates a JSON file with benchmarks for the specified regression profile.
    The function requires the `regression_selected_profile` attribute of the `user_config` parameter if
    custom regression profile operations are to be filtered. If no such profile is provided or no profile
    definitions file is specified, the function terminates the program with an appropriate message.

    :param conn: PostgreConnector object used for generating the JSON regression file.
    :type conn: Any
    :param user_config: Configuration object containing user-defined regression profiles and settings.
    :type user_config: UserConfig

    :raises SystemExit: If no regression profile is selected, or if the regression profiles
    file is not provided
    """
    # TODO Currently this implementation doesn't support custom regression profile.
    #  It will return strictly the benchmarks results for the operations defined for the selected profile.
    #  One way to handle that case would be to pass the custom profile as program input (could be either via a string or path containing the profile).
    if not user_config.regression_selected_profile:
        print(
            "Regression generation requires a profile name (see: --regression-selected-profile input argument)"
        )
        sys.exit(5)
    selected_profile = user_config.regression_selected_profile

    operations_filter = {}
    if user_config.regression_profiles_path:
        profile_definition = parse_toml_file(
            user_config.regression_profiles_path, user_config.backend, selected_profile
        )
        operations_filter = profile_definition["target"]
        try:
            user_config.pbs_kind = profile_definition["env"]["bench_param_type"].lower()
        except KeyError:
            # Benchmark parameters type is not declared in the regression definition file
            # Ignoring
            pass
    else:
        print(
            "Regression generation requires a profile definitions file (see: --regression-profiles input argument)"
        )
        sys.exit(5)

    generate_json_regression_file(
        conn,
        operations_filter,
        user_config,
        profile_definition.get("parameters_filter", None),
    )
