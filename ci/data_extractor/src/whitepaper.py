import copy
import itertools
import pathlib
import sys

import config
import connector
from benchmark_specs import ErrorFailureProbability
from formatters.core import CoreFormatter
import utils

class Default(dict):
    def __missing__(self, key):
        return f"{{{key}}}"


class ParametersFilterCase:
    def __init__(
        self,
        param_name_pattern: str,
        pfails: list[ErrorFailureProbability] = None,
        grouping_factors: list[int] = None,
        message_carry_sizes: list[int] = None,
    ):
        self.param_name_pattern = param_name_pattern
        self.pfails = pfails or []
        self.grouping_factors = grouping_factors or []
        self.message_carry_sizes = message_carry_sizes or []

    def get_parameter_variants(self):
        after_pfails = []
        for pfail in self.pfails:
            after_pfails.append(
                self.param_name_pattern.format_map(Default(pfail=pfail.to_str()))
            )

        after_grouping_factors = []
        if after_pfails:
            for name in after_pfails:
                for gf in self.grouping_factors:
                    after_grouping_factors.append(name.format_map(Default(gf=gf)))
        else:
            for gf in self.grouping_factors:
                after_grouping_factors.append(
                    self.grouping_factors.format_map(Default(gf=gf))
                )

        after_msg_carry_sizes = []
        if after_grouping_factors:
            for name in after_grouping_factors:
                for size in self.message_carry_sizes:
                    after_msg_carry_sizes.append(
                        name.format_map(Default(msg=size, carry=size))
                    )
        else:
            for size in self.message_carry_sizes:
                after_msg_carry_sizes.append(
                    self.param_name_pattern.format_map(Default(msg=size, carry=size))
                )

        return (
            after_msg_carry_sizes
            or after_grouping_factors
            or after_pfails
            or [self.param_name_pattern]
        )


CORE_CRYPTO_PARAM_CASES = [
    ParametersFilterCase(
        "%PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_{pfail}",
        pfails=[
            ErrorFailureProbability.TWO_MINUS_64,
            ErrorFailureProbability.TWO_MINUS_128,
        ],
    ),
    ParametersFilterCase(
        "%PARAM_MULTI_BIT_GROUP_{gf}_MESSAGE_{msg}_CARRY_{carry}_KS_PBS_GAUSSIAN_{pfail}",
        pfails=[
            ErrorFailureProbability.TWO_MINUS_64,
            ErrorFailureProbability.TWO_MINUS_128,
        ],
        grouping_factors=[2, 3, 4],
        message_carry_sizes=[1, 2, 3, 4],
    ),
]

INTEGER_PARAM_CASES = [
    ParametersFilterCase(
        "%PARAM_MESSAGE_{msg}_CARRY_{carry}_KS_PBS_GAUSSIAN_{pfail}",  # 1_1, 2_2, 4_4 (pfail: 2m64, 2m128)
        pfails=[
            ErrorFailureProbability.TWO_MINUS_64,
            ErrorFailureProbability.TWO_MINUS_128,
        ],
        message_carry_sizes=[1, 2, 4],
    ),
    ParametersFilterCase(
        "%PARAM_MESSAGE_2_CARRY_2_KS32_PBS_GAUSSIAN_{pfail}",
        pfails=[
            ErrorFailureProbability.TWO_MINUS_64,
            ErrorFailureProbability.TWO_MINUS_128,
        ],
    ),
    ParametersFilterCase(
        "%PARAM_MULTI_BIT_GROUP_{gf}_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_{pfail}",
        pfails=[
            ErrorFailureProbability.TWO_MINUS_64,
            ErrorFailureProbability.TWO_MINUS_128,
        ],
        grouping_factors=[2, 3, 4],
    ),
    ParametersFilterCase(
        "%COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_{pfail}",
        pfails=[
            ErrorFailureProbability.TWO_MINUS_64,
            ErrorFailureProbability.TWO_MINUS_128,
        ],
    ),
]

INTEGER_SPECIAL_CASE_OPERATIONS_FILTER = [
    "add_parallelized",
    "mul_parallelized",
    "bitand_parallelized",
]

def _generate_latex_tables(
    conn: connector.PostgreConnector,
    user_config: config.UserConfig,
    result_dir: pathlib.Path,
):
    conversion_func = utils.convert_latency_value_to_readable_text

    case_config = copy.deepcopy(user_config)
    case_config.backend = config.Backend.CPU
    case_config.pbs_kind = config.PBSKind.Any

    for case in CORE_CRYPTO_PARAM_CASES:
        case_config.layer = config.Layer.CoreCrypto
        param_patterns = case.get_parameter_variants()
        res = conn.fetch_benchmark_data(case_config, param_name_patterns=param_patterns)

        generic_formatter = CoreFormatter(
            case_config.layer,
            case_config.backend,
            case_config.pbs_kind,
            case_config.grouping_factor,
        )
        formatted_results = generic_formatter.format_data(
            res,
            conversion_func,
        )

        # TODO créer le tbaleau qui va bien en fonction du cas
        for r in formatted_results.items():  # DEBUG
            print(r)

        print("--------------------------------------------------")
        print("--------------------------------------------------")
        print("--------------------------------------------------")

    # TODO prendre la valeur minimum dans un groupe d'opération (ex: min/max, gt/ge/lt/le, ...)


def perform_latex_generation(
    conn: connector.PostgreConnector, user_config: config.UserConfig
):
    dir_path = user_config.output_file
    try:
        dir_path.mkdir(parents=True, exist_ok=True)
    except Exception as e:  ## TODO find the exact exception that can be raised here
        pass

    # TODO passer un dossier en user_config et enregistrer les tables latex dans ce dossier un fichier = une table
    _generate_latex_tables(conn, user_config, dir_path)


# Table 2 is core crypto KS/KS-PBS/PBS for 2_2_128  and 2_2_64
# Table 3 is  core crypto KS/KS-PBS/PBS in the multibit case for V1_4_PARAM_MULTI_BIT_GROUP_X_MESSAGE_Y_CARRY_Y_KS_PBS_GAUSSIAN_2MZ  for X in [2,3,4], Y in [1,2,3,4] and Z in [64, 128]
# Table 5 is special case with 1_1_64, 2_2_64, 4_4_64
# Table 6 is special case with 1_1_128, 2_2_128, 4_4_128
# Table 7 is the multibit special case with V1_4_PARAM_MULTI_BIT_GROUP_X_MESSAGE_Y_CARRY_Y_KS_PBS_GAUSSIAN_2MZ  for X in [2,3,4], Y = 2, Z = 64.
# Table 8 is special case for 2_2_128 and 2_2_128 KS_32 <--- changed
# Table 9, 10, 11, 12 are the integer ops for 2_2_64_KS32 and 2_2_128_KS32
# Table 13 is compression (which I believe was in special case?) for the 64/128 compression parameters
