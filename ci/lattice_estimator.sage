"""
lattice_estimator
-----------------

Test cryptographic parameters set against several attacks to estimate their security level.
"""
import pathlib
import sys
sys.path.insert(1, 'lattice-estimator')
from estimator import *


model = RC.BDGL16

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

    for param in all_params:
        if param.tag.startswith("TFHE_LIB_PARAMETERS"):
            # This third-party parameters set is known to be less secure, just skip the analysis.
            continue

        print(f"\t{param.tag}...\t", end= "")

        try:
            # The lattice estimator is not able to manage such large dimension.
            # If we have the security for smaller `n` then we have security for larger ones.
            if param.n == 32768:
                param = param.updated(n = 16384)

            usvp_level = LWE.primal_usvp(param, red_cost_model = model)
            dual_level = LWE.dual_hybrid(param, red_cost_model = model)

            estimator_level = log(min(usvp_level["rop"], dual_level["rop"]),2 )
            if estimator_level < 127:
                print("FAIL")
                reason = f"attained security level = {estimator_level} bits target is 128 bits"
                to_update.append((param, reason))
                continue
        except Exception as err:
            print("FAIL")
            to_update.append((param, f"{repr(err)}"))
        else:
            print("OK")

    return to_update


if __name__ == "__main__":
    params_to_update = []

    for params_filename in ("boolean_parameters_lattice_estimator.sage",
                            "shortint_classic_parameters_lattice_estimator.sage",
                            "shortint_multi_bit_parameters_lattice_estimator.sage"):
        params_to_update.extend(check_security(params_filename))

    if params_to_update:
        print("Some parameters need update")
        print("----------------------------")
        for param, reason in params_to_update:
            print(f"[{param.tag}] reason: {reason} (param)")
        sys.exit(int(1))  # Explicit conversion is needed to make this call work
    else:
        print("All parameters passed the security check")