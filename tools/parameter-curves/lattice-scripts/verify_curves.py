import numpy as np
from sage.all import save, load, ceil
import json
import os
import argparse

def sort_data(security_level, curves_dir):
    from operator import itemgetter

    # step 1. load the data
    X = load(os.path.join(curves_dir, f"{security_level}.sobj"))

    # step 2. sort by SD
    x = sorted(X["{}".format(security_level)], key=itemgetter(2))

    # step3. replace the sorted value
    X["{}".format(security_level)] = x

    return X


def generate_curve(security_level, curves_dir):

    # step 1. get the data
    X = sort_data(security_level, curves_dir)

    # step 2. group the n and sigma data into lists
    N = []
    SD = []
    for x in X["{}".format(security_level)]:
        N.append(x[0])
        SD.append(x[2] + 0.5)

    # step 3. perform interpolation and return coefficients
    (a, b) = np.polyfit(N, SD, 1)

    return a, b


def verify_curve(security_level, a, b, curves_dir):

    # step 1. get the table and max values of n, sd
    X = sort_data(security_level, curves_dir)
    n_max = X["{}".format(security_level)][0][0]

    # step 2. a function to get model values
    def f_model(a, b, n):
        return ceil(a * n + b)

    # step 3. a function to get table values
    def f_table(table, n):
        for i in range(len(table)):
            n_val = table[i][0]
            if n < n_val:
                pass
            else:
                j = i
                break

        # now j is the correct index, we return the corresponding sd
        return table[j][2]

    # step 3. for each n, check whether we satisfy the table
    n_min = max(2 * security_level, 450, X["{}".format(security_level)][-1][0])

    for n in range(n_max, n_min, -1):
        model_sd = f_model(a, b, n)
        table_sd = f_table(X["{}".format(security_level)], n)
        #print(n, table_sd, model_sd, model_sd >= table_sd)

        if table_sd > model_sd:
            #print("MODEL FAILS at n = {}".format(n))
            return False

    return True, n_min


def generate_and_verify(security_levels, log_q, curves_dir, verified_curves_path):
    success = []
    json = []

    fail = []

    for sec in security_levels:
        # generate the model for security level sec
        (a_sec, b_sec) = generate_curve(sec, curves_dir)
        # verify the model for security level sec
        (status, n_alpha) = verify_curve(sec, a_sec, b_sec, curves_dir)
        # append the information into a list
        if status:
            json.append({"slope": a_sec, "bias": b_sec - log_q, "security_level": sec, "minimal_lwe_dimension": n_alpha})
            success.append((a_sec, b_sec - log_q, sec, a_sec, b_sec))
        else:
            fail.append(sec)

    save(success, verified_curves_path)

    return json, fail


if __name__ == "__main__":
    CLI = argparse.ArgumentParser()
    CLI.add_argument(
        "--verified-curves-path",
        help="The path to store the verified curves (sage object)",
        type=str,
        required=True,
    )
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
    (success, fail) = generate_and_verify(args.security_levels, log_q=args.log_q, curves_dir=args.curves_dir, verified_curves_path=args.verified_curves_path)
    if (fail):
        print("FAILURE: Fail to verify the following curves")
        print(json.dumps(fail))
        exit(1)

    print(json.dumps(success))
