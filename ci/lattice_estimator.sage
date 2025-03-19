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


def check_security(filepath):
    """
    Run lattice estimator to determine if a parameters set is secure or not.

    :param filepath: path of the file containing parameters set

    :return: :class:`list` of parameters to update
    """
    print(f"Parsing parameters in {filepath}")
    load(filepath)

    to_update = []
    to_watch = []

    for group_index, param in enumerate(all_params):
        if "TFHE_LIB_PARAMETERS_lwe" in param.tag or "TFHE_LIB_PARAMETERS_glwe" in param.tag:
            # This third-party parameters set is known to be less secure, just skip the analysis.
            continue

        print(f"\tParameters group #{group_index}:")
        for param_name in sorted(param.tag):
            print(
                f"\t\t{param_name}\t",
            )
        print(f"\tParameters group #{group_index}...\t", end="")

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

    return to_update, to_watch


if __name__ == "__main__":
    params_to_update = []
    params_to_watch = []

    this_file = pathlib.Path(__file__).resolve()
    this_file_sage_source = this_file if this_file.suffix == ".sage" else this_file.with_suffix("")
    parent_dir = this_file.parent
    parameter_files = sorted(list(parent_dir.glob("*.sage")))
    parameter_files.remove(this_file_sage_source)

    for params_file in parameter_files:
        to_update, to_watch = check_security(params_file)
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
