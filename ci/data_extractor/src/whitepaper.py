import copy
import itertools
import pathlib
import sys

import config
import connector
from benchmark_specs import ErrorFailureProbability


class Default(dict):
    def __missing__(self, key):
        return f"{{{key}}}"


class ParametersFilterCase:
    def __init__(
        self,
        param_name_pattern: str,
        pfails: list[ErrorFailureProbability],
        grouping_factors: list[int] = None,
        message_carry_sizes: list[int] = None,
    ):
        self.param_name_pattern = param_name_pattern
        self.pfails = pfails
        self.grouping_factors = grouping_factors or []
        self.message_carry_sizes = message_carry_sizes or []

    def get_parameter_variants(self):
        cases = []

        print("RAW:", self.param_name_pattern)  # DEBUG
        # TODO il faut gérer le cas où les listes sont vides (produit par 0 ne retourne rien)
        #   faire des ifs ?
        # for (pfail, gf, size) in itertools.product(self.pfails, self.grouping_factors, self.message_carry_sizes):
        #     case = self.param_name_pattern.format_map(Default(gf=gf, msg=size, carry=size, pfail=pfail.to_str()))
        #     print("\t case:", case)

        after_pfails = []
        for pfail in self.pfails:
            after_pfails.append(self.param_name_pattern.format_map(Default(pfail=pfail.to_str())))

        after_grouping_factors = []
        for gf in self.grouping_factors:
            self.param_name_pattern.format_map(Default(gf=gf))

        for size in self.message_carry_sizes:
            self.param_name_pattern.format_map(Default(msg=size, carry=size))

        return cases


CORE_CRYPTO_PARAM_CASES = [
    ParametersFilterCase(
        "%PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_{pfail}",
        [ErrorFailureProbability.TWO_MINUS_64, ErrorFailureProbability.TWO_MINUS_128],
    ),  # (pfail: 2m64, 2m128)
    ParametersFilterCase(
        "%PARAM_MULTI_BIT_GROUP_{gf}_MESSAGE_{msg}_CARRY_{carry}_KS_PBS_GAUSSIAN_{pfail}",
        [ErrorFailureProbability.TWO_MINUS_64, ErrorFailureProbability.TWO_MINUS_128],
        grouping_factors=[2, 3, 4],
        message_carry_sizes=[1, 2, 3, 4],
    ),  # 1_1, 2_2, 3_3, 4_4 (gf: 2,3,4) (pfail: 2m64, 2m128)
]

# TODO faire des itérateurs avec des zip pour combiner les différents cas et faire une seule boucle for
CORE_CRYPTO_PARAM_PATTERNS = [
    "%PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_{pfail}",  # (pfail: 2m64, 2m128)
    "%PARAM_MULTI_BIT_GROUP_{gf}_MESSAGE_{msg}_CARRY_{carry}_KS_PBS_GAUSSIAN_{pfail}",  # 1_1, 2_2, 3_3, 4_4 (gf: 2,3,4) (pfail: 2m64, 2m128)
]

INTEGER_PARAM_PATTERNS = [
    "%PARAM_MESSAGE_{msg}_CARRY_{carry}_KS_PBS_GAUSSIAN_{pfail}",  # 1_1, 2_2, 4_4 (pfail: 2m64, 2m128)
    "%PARAM_MESSAGE_2_CARRY_2_KS32_PBS_GAUSSIAN_{pfail}",  # (pfail: 2m64, 2m128)
    "%PARAM_MULTI_BIT_GROUP_{gf}_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_{pfail}",  # (gf: 2,3,4) (pfail: 2m64, 2m128)
    "%COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_{pfail}",  # (pfail: 2m64, 2m128)
]


def _generate_latex_tables(
    conn: connector.PostgreConnector,
    user_config: config.UserConfig,
    result_dir: pathlib.Path,
):
    # TODO prendre la valeur minimum dans un groupe d'opération (ex: min/max, gt/ge/lt/le, ...)
    case_config = copy.deepcopy(user_config)
    case_config.backend = config.Backend.CPU

    for case in CORE_CRYPTO_PARAM_CASES:
        for param in case.get_parameter_variants():
            print(param)  # DEBUG


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
