#!/usr/bin/env python3

from pathlib import Path
import re
from collections import defaultdict
from typing import List
from utils import get_repo_root, format_version_major_minor, get_tfhe_version


pascal_to_snake = lambda s: re.sub(r"(?<!^)(?=[A-Z])", "_", s).lower()


# Example format
# /// All [`ClassicPBSParameters`] in this module.
# pub const VEC_ALL_CLASSIC_PARAMETERS: [&ClassicPBSParameters; 1] =
#     [&V1_0_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128];
def format_all_param_vec(param_type: str, param_names: List[str]) -> str:
    joined_params = ",\n    ".join(
        f"""(&{param_name}, "{param_name}")""" for param_name in param_names
    )
    let_param_type_for_const = pascal_to_snake(param_type).upper()
    let_param_type_for_const = let_param_type_for_const.replace("P_B_S", "PBS")
    return f"""/// All [`{param_type}`] in this module.
pub const VEC_ALL_{let_param_type_for_const}: [(&{param_type}, &str); {len(param_names)}] =
[
    {joined_params}
];
"""


def main():
    all_vec_params = defaultdict(list)
    tfhe_rs_version = format_version_major_minor(get_tfhe_version())
    tfhe_rs_version_capitalized = tfhe_rs_version.upper()
    params_dir_path = get_repo_root() / f"tfhe/src/shortint/parameters/{tfhe_rs_version}"
    for p in params_dir_path.rglob("*"):
        if not p.is_file():
            continue

        file_content = None
        with open(p, "r", encoding="utf-8") as f:
            file_content = f.read()

        matches = re.finditer(
            f"pub const {tfhe_rs_version_capitalized}([^=]+)", file_content, re.MULTILINE
        )

        for match in matches:
            match = match.group(0)
            match = match.replace("\n", " ")

            (pub_const_param_name, param_type) = match.split(":")
            pub_const_param_name = pub_const_param_name.strip()
            param_type = param_type.strip()
            param_name = pub_const_param_name.rsplit(" ", maxsplit=1)[1]

            # print(param_name, param_type)

            all_vec_params[param_type].append(param_name)

    # print(all_vec_params)

    for param_type, param_names in all_vec_params.items():
        print(format_all_param_vec(param_type, param_names))


if __name__ == "__main__":
    main()
