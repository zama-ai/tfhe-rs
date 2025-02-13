"""
lattice_estimator
-----------------

Test cryptographic parameters set against several attacks to estimate their security level.
"""

import pathlib
import sys

sys.path.insert(1, "lattice-estimator")
from estimator import *


model = RC.MATZOV

# Minimum level of security thresholds for parameters set in bits
SECURITY_LEVEL_THRESHOLD_SOFT = 132
SECURITY_LEVEL_THRESHOLD_HARD = 128


def check_security(filename):
    """
    Run lattice estimator to determine if a parameters set is secure or not.

    :param filename: name of the file containing parameters set

    :return: :class:`list` of parameters to update
    """
    filepath = pathlib.Path("ci", filename)
    load(filepath)
    print(f"Parsing parameters in {filepath}")

    to_update = []
    to_watch = []

    group_index = 1

    for param in all_params:
        if "TFHE_LIB_PARAMETERS" in param.tag:
            # This third-party parameters set is known to be less secure, just skip the analysis.
            continue

        if len(param.tag) > 1:
            print(f"\tParameters group #{group_index}:")
            for param_name in sorted(param.tag):
                print(
                    f"\t\t{param_name}\t",
                )
            print(f"\tParameters group #{group_index}...\t", end="")
        else:
            print(f"\t{param.tag[0]}...\t", end="")

        is_n_size_too_low = param.n <= 450
        is_noise_level_too_low = param.Xe.stddev < 4.0
        if is_n_size_too_low:
            reason = f"n size is too low {param.n} minimum is 450"
        elif is_noise_level_too_low:
            reason = f"noise level is too low {round(param.Xe.stddev,3)} minimum is 4.0"

        if is_n_size_too_low or is_noise_level_too_low:
            print(f"FAIL\t{reason}")
            to_update.append((param, reason))
            continue

        try:
            # The lattice estimator is not able to manage such large dimension.
            # If we have the security for smaller `n` then we have security for larger ones.
            if param.n > 16384:
                param = param.updated(n=16384)

            usvp_level = LWE.primal_usvp(param, red_cost_model=model)
            dual_level = LWE.dual_hybrid(param, red_cost_model=model)

            estimator_level = log(min(usvp_level["rop"], dual_level["rop"]), 2).n()
            security_level = f"security level = {estimator_level} bits"
            if estimator_level < SECURITY_LEVEL_THRESHOLD_HARD:
                print(f"FAIL\t({security_level})")
                reason = f"attained {security_level} target is {SECURITY_LEVEL_THRESHOLD_HARD} bits"
                to_update.append((param, reason))
                continue
            elif estimator_level < SECURITY_LEVEL_THRESHOLD_SOFT:
                print(f"WARNING\t({security_level})")
                reason = f"attained {security_level} target is {SECURITY_LEVEL_THRESHOLD_SOFT} bits"
                to_watch.append((param, reason))
                continue
        except Exception as err:
            print("FAIL")
            to_update.append((param, f"{repr(err)}"))
        else:
            print(f"OK\t({security_level})")

        if len(param.tag) > 1:
            group_index += 1

    return to_update, to_watch


if __name__ == "__main__":
    params_to_update = []
    params_to_watch = []

    for params_filename in (
        "boolean_parameters_lattice_estimator.sage",
        "shortint_classic_parameters_lattice_estimator.sage",
        "shortint_multi_bit_parameters_lattice_estimator.sage",
        "shortint_cpke_parameters_lattice_estimator.sage",
        "shortint_list_compression_parameters_lattice_estimator.sage",
    ):
        to_update, to_watch = check_security(params_filename)
        params_to_update.extend(to_update)
        params_to_watch.extend(to_watch)

    if params_to_watch:
        print("Some parameters need attention")
        print("------------------------------")
        for param, reason in params_to_watch:
            params = ",\n\t".join(param.tag)
            print("[\n\t", params, "\n]", sep="")
            print(f"--> reason: {reason} (param: {param})\n")

    if params_to_update:
        if params_to_watch:
            # Add a visual separator.
            print("\n\n ################################### \n\n")
        print("Some parameters need update")
        print("---------------------------")
        for param, reason in params_to_update:
            params = ",\n\t".join(param.tag)
            print("[\n\t", params, "\n]", sep="")
            print(f"--> reason: {reason} (param: {param})\n")
        sys.exit(int(1))  # Explicit conversion is needed to make this call work
    else:
        print("All parameters passed the security check")
