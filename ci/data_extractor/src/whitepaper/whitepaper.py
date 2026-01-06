import copy
import itertools
import pathlib
import sys

import utils

import config, connector
from benchmark_specs import (
    AtomicPattern,
    ErrorFailureProbability,
    GroupingFactor,
    Precision,
)
from formatters.common import (
    LatexTable,
)
from formatters.core import CoreFormatter
from formatters.integer import IntegerFormatter
from .tables import (
    TABLE_BENCH_MULTIBIT_BY_PRECISION,
    TABLE_COMPARISON_OPERATIONS_BOOTSTRAPPING,
    TABLE_COMPARISON_OPERATIONS_BOOTSTRAPPING128KS32,
    TABLE_COMPARISON_OPERATIONS_PRECISION_PFAIL64,
    TABLE_COMPARISON_OPERATIONS_PRECISION_PFAIL128,
    TABLE_PBS_BENCH,
    TABLE_PLAINTEXT_CIPHERTEXT_OPS_PFAIL64_KS32,
    TABLE_PLAINTEXT_CIPHERTEXT_OPS_PFAIL128_KS32,
    TABLE_CIPHERTEXT_CIPHERTEXT_OPS_PFAIL64_KS32,
    TABLE_CIPHERTEXT_CIPHERTEXT_OPS_PFAIL128_KS32,
    TABLE_COMPRESSION_BENCHMARKS,
)


class Default(dict):
    def __missing__(self, key):
        return f"{{{key}}}"


class ParametersFilterCase:
    def __init__(
        self,
        param_name_pattern: str,
        pfails: list[ErrorFailureProbability] = None,
        grouping_factors: list[GroupingFactor] = None,
        precisions: list[Precision] = None,
        atomic_patterns: list[AtomicPattern] = None,
        additional_parameters: list[str] = None,
        associated_tables: list[LatexTable] = None,
    ):
        self.param_name_pattern = param_name_pattern
        self.pfails = pfails or []
        self.grouping_factors = grouping_factors or []
        self.precisions = precisions or []
        self.atomic_patterns = atomic_patterns or []

        self.additional_parameters = additional_parameters or []

        self.associated_tables = associated_tables or []

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

        last_populated = after_grouping_factors or after_pfails
        after_msg_carry_sizes = []
        if last_populated:
            for name in last_populated:
                for p in self.precisions:
                    after_msg_carry_sizes.append(
                        name.format_map(Default(msg=p.message(), carry=p.carry()))
                    )
        else:
            for p in self.precisions:
                after_msg_carry_sizes.append(
                    self.param_name_pattern.format_map(
                        Default(msg=p.message(), carry=p.carry())
                    )
                )

        last_populated = last_populated or after_msg_carry_sizes
        after_atomic_patterns = []
        if last_populated:
            for name in last_populated:
                for a in self.atomic_patterns:
                    after_atomic_patterns.append(
                        name.format_map(Default(atomic_pattern=a))
                    )
        else:
            for a in self.atomic_patterns:
                after_atomic_patterns.append(
                    self.param_name_pattern.format_map(Default(atomic_pattern=a))
                )

        interpolated_params = (
            last_populated or after_atomic_patterns or [self.param_name_pattern]
        )
        interpolated_params.extend(self.additional_parameters)

        return interpolated_params


CORE_CRYPTO_PARAM_CASES = [
    ParametersFilterCase(
        "%PARAM_MESSAGE_{msg}_CARRY_{carry}_KS_PBS_GAUSSIAN_{pfail}",
        pfails=[
            ErrorFailureProbability.TWO_MINUS_64,
            ErrorFailureProbability.TWO_MINUS_128,
        ],
        precisions=[Precision.M1C1, Precision.M2C2, Precision.M3C3, Precision.M4C4],
        associated_tables=[TABLE_PBS_BENCH],
    ),
    ParametersFilterCase(
        "%PARAM_MULTI_BIT_GROUP_{gf}_MESSAGE_{msg}_CARRY_{carry}_KS_PBS_GAUSSIAN_{pfail}",
        pfails=[
            ErrorFailureProbability.TWO_MINUS_64,
            ErrorFailureProbability.TWO_MINUS_128,
        ],
        grouping_factors=[
            GroupingFactor.Two,
            GroupingFactor.Three,
            GroupingFactor.Four,
        ],
        precisions=[Precision.M1C1, Precision.M2C2, Precision.M3C3, Precision.M4C4],
        associated_tables=[TABLE_BENCH_MULTIBIT_BY_PRECISION],
    ),
]

INTEGER_PARAM_CASES = [
    # # --- Tables 5, 6 ---
    # ParametersFilterCase(
    #     "%PARAM_MESSAGE_{msg}_CARRY_{carry}_KS_PBS_GAUSSIAN_{pfail}",  # 1_1, 2_2, 4_4 (pfail: 2m64, 2m128)
    #     pfails=[
    #         ErrorFailureProbability.TWO_MINUS_64,
    #         ErrorFailureProbability.TWO_MINUS_128,
    #     ],
    #     precisions=[Precision.M1C1, Precision.M2C2, Precision.M4C4],
    #     associated_tables=[
    #         TABLE_COMPARISON_OPERATIONS_PRECISION_PFAIL64,
    #         TABLE_COMPARISON_OPERATIONS_PRECISION_PFAIL128,
    #     ],
    # ),
    # # --- Table 8 ---
    # ParametersFilterCase(
    #     "%PARAM_MESSAGE_2_CARRY_2_{atomic_pattern}_GAUSSIAN_2M128",
    #     atomic_patterns=[
    #         AtomicPattern.KSPBS,
    #         AtomicPattern.KS32PBS,
    #     ],
    #     associated_tables=[TABLE_COMPARISON_OPERATIONS_BOOTSTRAPPING128KS32],
    # ),
    # # --- Tables 9, 10, 11, 12 ---
    # ParametersFilterCase(
    #     "%PARAM_MESSAGE_2_CARRY_2_KS32_PBS_GAUSSIAN_{pfail}",
    #     pfails=[
    #         ErrorFailureProbability.TWO_MINUS_64,
    #         ErrorFailureProbability.TWO_MINUS_128,
    #     ],
    #     associated_tables=[
    #         TABLE_PLAINTEXT_CIPHERTEXT_OPS_PFAIL64_KS32,
    #         TABLE_PLAINTEXT_CIPHERTEXT_OPS_PFAIL128_KS32,
    #         TABLE_CIPHERTEXT_CIPHERTEXT_OPS_PFAIL64_KS32,
    #         TABLE_CIPHERTEXT_CIPHERTEXT_OPS_PFAIL128_KS32,
    #     ],
    # ),
    # # --- Table 7 ---
    # ParametersFilterCase(
    #     "%PARAM_MULTI_BIT_GROUP_{gf}_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_{pfail}",
    #     pfails=[
    #         ErrorFailureProbability.TWO_MINUS_128,
    #     ],
    #     grouping_factors=[
    #         GroupingFactor.Two,
    #         GroupingFactor.Three,
    #         GroupingFactor.Four,
    #     ],
    #     additional_parameters=["%PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128", ],
    #     associated_tables=[TABLE_COMPARISON_OPERATIONS_BOOTSTRAPPING, ],
    # ),
    # # --- Table 13 ---
    ParametersFilterCase(  # TODO Table 13
        # "%COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_{pfail}",
        # pfails=[
        #     ErrorFailureProbability.TWO_MINUS_64,
        #     ErrorFailureProbability.TWO_MINUS_128,
        # ],
        "%COMP_PARAM_CUSTOM_BR_LEVEL_1_NOISE_DISTRIB_Gaussian%",  # DEBUG
        associated_tables=[TABLE_COMPRESSION_BENCHMARKS],
    ),
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

    # for case in CORE_CRYPTO_PARAM_CASES:
    #     case_config.layer = config.Layer.CoreCrypto
    #     param_patterns = case.get_parameter_variants()
    #     res = conn.fetch_benchmark_data(case_config, param_name_patterns=param_patterns)
    #
    #     generic_formatter = CoreFormatter(
    #         case_config.layer,
    #         case_config.backend,
    #         case_config.pbs_kind,
    #         case_config.grouping_factor,
    #     )
    #     formatted_results = generic_formatter.format_data_with_available_sizes(
    #         res,
    #         conversion_func,
    #     )
    #
    #     for k, v in formatted_results.items():  # DEBUG
    #         print(k)
    #         for sub_k, sub_v in v.items():
    #             print(f"\t{sub_k}: {sub_v}")
    #         print("")
    #
    #     print("--------------------------------------------------")
    #     print("--------------------------------------------------")
    #     print("--------------------------------------------------")
    #
    #     for table in case.associated_tables:
    #         formatted_table = table.format_table(
    #             formatted_results
    #         )
    #         print(formatted_table)  # DEBUG

    for case in INTEGER_PARAM_CASES:
        case_config.layer = config.Layer.Integer
        param_patterns = case.get_parameter_variants()
        res = conn.fetch_benchmark_data(case_config, param_name_patterns=param_patterns)

        generic_formatter = IntegerFormatter(
            case_config.layer,
            case_config.backend,
            case_config.pbs_kind,
            case_config.grouping_factor,
        )
        formatted_results = generic_formatter.format_data_with_available_sizes(
            res,
            conversion_func,
        )

        # FIXME il faut qu'on puisse avoir accès aux définitions de paramètres après formattage afin de pouvoir filtrer
        #  ensuite sans quoi on ne peut pas faire de parameters matching
        for k, v in formatted_results.items():  # DEBUG
            print(k)
            for sub_k, sub_v in v.items():
                print(f"\t{sub_k}: {sub_v}")
            print("")

        print("--------------------------------------------------")
        print("--------------------------------------------------")
        print("--------------------------------------------------")

        for table in case.associated_tables:
            formatted_table = table.format_table(formatted_results)
            # TODO écrire chaque table dans un fichier en récupérant le __name__ de la table, le lower() et strip() le préfixe "table_"
            print(formatted_table)  # DEBUG

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
