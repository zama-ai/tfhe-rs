import os
import sys
from estimator import LWE, ND, RC
from sage.all import oo, load, floor, ceil
from generate_data import estimate, get_security_level
import argparse


LOG_N_MAX = 17 + 1
LOG_N_MIN = 10

def get_index(sec, curves):
    """
    Retrieve the index of the curve corresponding to the right security :sec:
    :param sec:  security level
    :param curves: output of `generate_and_verify`
    :return: index of the right curve
    """
    # TODO: Duplicated code from verify_curve
    for i in range(len(curves)):
        if curves[i][2] == sec:
            return i


def estimate_security_with_lattice_estimator(lwe_dimension, std_dev, log_q):
    """
    Return the security of (lwe_dimension, std_dev, log_q) as estimated by the latest
    version of the lattice estimator
    :param lwe_dimension:
    :param std_dev:
    :param log_q:
    :return:
    """
    params = LWE.Parameters(
        n=lwe_dimension, q=2 ** log_q, Xs=ND.UniformMod(2), Xe=ND.DiscreteGaussian(std_dev), m=oo, tag="params"
    )
    costs = estimate(params, red_cost_model = RC.BDGL16)
    return get_security_level(costs, 2)

def get_minimal_lwe_dimension(curve, security_level, log_q):
    """
    Retrieve the smallest lwe dimension usable for the given security level and log_q
    :param curve:
    :param security_level:
    :param log_q:
    :return:
    """
    minimal_lwe_dim = curve[-1]
    return minimal_lwe_dim


def estimate_stddev_with_current_curve(curve, lwe_dimension, log_q):
    """
    Use the current formula to estimate the secure noise from the lwe_dimension
    :param curve:
    :param lwe_dimension:
    :param log_q:
    :return:
    """

    def minimal_stddev(a, b, lwe_dim):
        return 2. ** max(ceil(a * lwe_dim + b), 2)

    a = curve[0]
    b = curve[1] + log_q

    stddev = minimal_stddev(a, b, lwe_dimension)
    return stddev


def compare_curve_and_estimator(security_level, log_q, curves_dir):
    """
    For a subset of every lwe dimension possibles, estimate the security of those lwe dimension
    associated with the stddev recommanded by our current curve.


    Test whether some (lwe_dimension, std dev) that are assumed to be secure with
    the current curves are
    :param security_level:
    :param log_q:
    :return: If one of (lwe dim, std dev) is estimated to be less secure than our target `security_level`
     this function return False, else return True
    """
    print(f"Security Target: {security_level} bits")

    # step 0. loading the right curve
    curves = load(os.path.join(curves_dir, "verified_curves.sobj"))
    j = get_index(security_level, curves)
    curve = curves[j]

    # step 1. define range of lwe dimensions
    n_min = curve[-1]
    n_min = max(2 * security_level, 450, n_min)
    # TODO: REMOVE HARDCODED 10
    lwe_dimensions = list(range(n_min, 1024, 10)) + [2**i for i in range(LOG_N_MIN, LOG_N_MAX)]

    # step 2. check security of those points
    for lwe_dim in lwe_dimensions:
        print("-------------------------")
        # (i) get stddev with current curves
        predicted_stddev = estimate_stddev_with_current_curve(curve, lwe_dim, log_q)
        # (ii) estimate up-to-date security
        predicted_security = estimate_security_with_lattice_estimator(lwe_dim, predicted_stddev, log_q)

        print("-------------------------")
        print(f"lwe dim: {lwe_dim}")
        print(f"stddev: {predicted_stddev}")
        print(f"Security: {predicted_security}")

        if predicted_security < security_level:
            return False

    return True

if __name__ == "__main__":
    CLI = argparse.ArgumentParser()
    CLI.add_argument(
        "--curves-dir",
        help="The directory where curves has been saved (sage object)",
        type=str,
        required=True,
    )
    CLI.add_argument(
        "--security-levels",
        help="The security levels to verify",
        nargs="+",
        type=int,
        required=True
    )
    CLI.add_argument(
        "--log-q",
        type=int,
        required=True
    )
    args = CLI.parse_args()
    for security_level in args.security_levels:
        if not(compare_curve_and_estimator(security_level, args.log_q, args.curves_dir)):
            exit(1)
    exit(0)
