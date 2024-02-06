from sage.all import oo, save, load
from math import log2
import multiprocessing
import argparse
import os
import sys
from estimator import RC, LWE, ND


old_models_sobj = ""

def old_models(security_level, sd, logq=32):
    """
    Use the old model as a starting point for the data gathering step
    :param security_level: the security level under consideration
    :param sd            : the standard deviation of the LWE error distribution Xe
    :param logq          : the (base 2 log) value of the LWE modulus q
    """

    def evaluate_model(a, b, stddev=sd):
        return (stddev - b) / a

    def get_index(sec, curves):
        for i in range(len(curves)):
            if curves[i][2] == sec:
                return i

    if old_models_sobj is None or not(os.path.exists(old_models_sobj)):
        return 450

    curves = load(old_models_sobj)
    j = get_index(security_level, curves)

    a = curves[j][0]
    b = curves[j][1] + logq

    n_est = evaluate_model(a, b, sd)

    return round(n_est)


def estimate(params, red_cost_model=RC.BDGL16, skip=("arora-gb", "bkw")):
    """
    Retrieve an estimate using the Lattice Estimator, for a given set of input parameters
    :param params: the input LWE parameters
    :param red_cost_model: the lattice reduction cost model
    :param skip: attacks to skip
    """

    est = LWE.estimate(params, red_cost_model=red_cost_model, deny_list=skip)

    return est


def get_security_level(est, dp=2):
    """
    Get the security level lambda from a Lattice Estimator output
    :param est: the Lattice Estimator output
    :param dp: the number of decimal places to consider
    """
    attack_costs = []
    # note: key does not need to be specified est vs est.keys()
    for key in est:
        attack_costs.append(est[key]["rop"])
    # get the security level correct to 'dp' decimal places
    security_level = round(log2(min(attack_costs)), dp)

    return security_level


def inequality(x, y):
    """A utility function which compresses the conditions x < y and x > y into a single condition via a multiplier
    :param x: the LHS of the inequality
    :param y: the RHS of the inequality
    """
    if x <= y:
        return 1

    if x > y:
        return -1


def automated_param_select_n(params, target_security=128):
    """A function used to generate the smallest value of n which allows for
    target_security bits of security, for the input values of (params.Xe.stddev,params.q)
    :param params: the standard deviation of the error
    :param target_security: the target number of bits of security, 128 is default

    EXAMPLE:
    sage: X = automated_param_select_n(Kyber512, target_security = 128)
    sage: X
    456
    """

    # get an estimate based on the prev. model
    print("n = {}".format(params.n))
    n_start = old_models(target_security, log2(params.Xe.stddev), log2(params.q))
    # n_start = max(n_start, 450)
    # TODO: think about throwing an error if the required n < 450

    params = params.updated(n=n_start)
    costs2 = estimate(params)
    security_level = get_security_level(costs2, 2)
    z = inequality(security_level, target_security)

    # we keep n > 2 * target_security as a rough baseline for mitm security
    # (on binary key guessing)
    while z * security_level < z * target_security:
        # TODO: fill in this case! For n > 1024 we only need to consider every
        # 256 (optimization)
        params = params.updated(n=params.n + z * 8)
        costs = estimate(params)
        security_level = get_security_level(costs, 2)

        if -1 * params.Xe.stddev > 0:
            print("target security level is unattainable")
            break

    # final estimate (we went too far in the above loop)
    if security_level < target_security:
        # we make n larger
        print("we make n larger")
        params = params.updated(n=params.n + 8)
        costs = estimate(params)
        security_level = get_security_level(costs, 2)

    print(
        "the finalised parameters are n = {}, log2(sd) = {}, log2(q) = {}, with a security level of {}-bits".format(
            params.n, log2(params.Xe.stddev), log2(params.q), security_level
        )
    )

    if security_level < target_security:
        params.updated(n=None)

    return params, security_level


def generate_parameter_matrix(
    params_in, sd_range, target_security_levels=[128], name="default_name"
):
    """
    :param params_in: a initial set of LWE parameters
    :param sd_range: a tuple (sd_min, sd_max) giving the values of sd for which to generate parameters
    :param target_security_levels: a list of the target number of bits of security, 128 is default
    :param name: a name to save the file
    """

    (sd_min, sd_max) = sd_range
    for lam in target_security_levels:
        for sd in range(sd_min, sd_max + 1):
            print(f"run for {lam} {sd}")
            Xe_new = ND.DiscreteGaussian(2 ** sd)
            (params_out, sec) = automated_param_select_n(
                params_in.updated(Xe=Xe_new), target_security=lam
            )

            try:
                results = load("{}.sobj".format(name))
            except BaseException:
                results = dict()
                results["{}".format(lam)] = []

            results["{}".format(lam)].append(
                (params_out.n, log2(params_out.q), log2(params_out.Xe.stddev), sec)
            )
            save(results, "{}.sobj".format(name))

    return results


def generate_zama_curves64(
    sd_range=[2, 58], target_security_levels=[128], name="default_name"
):
    """
    The top level function which we use to run the experiment

    :param sd_range: a tuple (sd_min, sd_max) giving the values of sd for which to generate parameters
    :param target_security_levels: a list of the target number of bits of security, 128 is default
    :param name: a name to save the file
    """
    if __name__ == "__main__":

        D = ND.DiscreteGaussian
        vals = range(sd_range[0], sd_range[1])
        pool = multiprocessing.Pool(2)
        init_params = LWE.Parameters(
            n=1024, q=2 ** 64, Xs=D(0.50, -0.50), Xe=D(2 ** 55), m=oo, tag="params"
        )
        inputs = [
            (init_params, (val, val), target_security_levels, name) for val in vals
        ]
        _res = pool.starmap(generate_parameter_matrix, inputs)

    return "done"

if __name__ == "__main__":
    CLI = argparse.ArgumentParser()
    CLI.add_argument(
        "--security-level",
        type=int,
        required=True,
    )
    CLI.add_argument(
        "--output",
        type=str,
        required=True,
    )
    CLI.add_argument(
        "--old-models",
        type=str,
    )
    CLI.add_argument(
        "--sd-min",
        type=int,
        required=True,
    )
    CLI.add_argument(
        "--sd-max",
        type=int,
        required=True,
    )
    CLI.add_argument(
        "--margin",
        type=int,
        default=0,
    )
    args = CLI.parse_args()
    # The script runs the following commands
    # grab values of the command-line input arguments
    security = args.security_level
    sd_min = args.sd_min
    sd_max = args.sd_max
    margin = args.margin
    output = args.output
    old_models_sobj = args.old_models
    # run the code
    generate_zama_curves64(sd_range=(sd_min, sd_max), target_security_levels=[security + margin], name="security_{}_margin_{} ".format(security, margin))
