# Usage instructions
# Requirement: SageMath (see installation instructions here: https://doc.sagemath.org/html/en/installation/index.html)
# clone the lattice estimator from github.com/malb/lattice-estimator
# run sage estimates.py from the lattice estimator folder
# note that duplicate parameter sets are removed, e.g. there are several instances with n=2048, which we only estimate once
# for faster running time, we do not consider the parameter sets with n=65536, 32768; this set has the same error
# distribution as the n=8192 case, but has a larger ring dimension (so security is implied).

import sys

sys.path.insert(1, "lattice-estimator")
from estimator import *
from math import log

baseline_params = LWE.Parameters(
    n=1024, q=2**64, Xs=ND.Binary, Xe=ND.DiscreteGaussian(2**64 * 2.17e-19)
)


# Non-CM-64 / Vanilla 64 [Current Table 8]
vanilla_1_lwe_64 = baseline_params.updated(
    n=790, Xe=ND.DiscreteGaussian(2**64 * 7.59e-6)
)

vanilla_1_glwe_64 = baseline_params.updated(
    n=1536, Xe=ND.DiscreteGaussian(2**64 * 1.95e-11)
)

vanilla_2_lwe_64 = baseline_params.updated(
    n=807, Xe=ND.DiscreteGaussian(2**64 * 5.66e-6)
)

vanilla_2_glwe_64 = baseline_params.updated(
    n=2048, Xe=ND.DiscreteGaussian(2**64 * 2.85e-15)
)

vanilla_3_lwe_64 = baseline_params.updated(
    n=936, Xe=ND.DiscreteGaussian(2**64 * 6.12e-7)
)

vanilla_3_glwe_64 = baseline_params.updated(
    n=8192, Xe=ND.DiscreteGaussian(2**64 * 2.17e-19)
)

vanilla_4_lwe_64 = baseline_params.updated(
    n=1072, Xe=ND.DiscreteGaussian(2**64 * 5.85e-8)
)

vanilla_64 = [
    vanilla_1_lwe_64,
    vanilla_1_glwe_64,
    vanilla_2_lwe_64,
    vanilla_2_glwe_64,
    vanilla_3_lwe_64,
    vanilla_3_glwe_64,
    vanilla_4_lwe_64,
]


# CM-64 [Current Table 9]

cm64_1_lwe = baseline_params.updated(n=762, Xe=ND.DiscreteGaussian(2**64 * 1.23e-5))

cm64_2_lwe = baseline_params.updated(n=772, Xe=ND.DiscreteGaussian(2**64 * 1.04e-5))

cm64_3_to_4_lwe = baseline_params.updated(
    n=723, Xe=ND.DiscreteGaussian(2**64 * 2.41e-5)
)

cm64_5_lwe = baseline_params.updated(n=808, Xe=ND.DiscreteGaussian(2**64 * 5.57e-6))

cm64_6_lwe = baseline_params.updated(n=783, Xe=ND.DiscreteGaussian(2**64 * 8.57e-6))

cm64_7_to_8_lwe = baseline_params.updated(
    n=784, Xe=ND.DiscreteGaussian(2**64 * 8.42e-6)
)

cm64_9_lwe = baseline_params.updated(n=936, Xe=ND.DiscreteGaussian(2**64 * 6.12e-7))

cm64_10_to_12_lwe = baseline_params.updated(
    n=909, Xe=ND.DiscreteGaussian(2**64 * 9.74e-7)
)

cm64_13_lwe = baseline_params.updated(n=1077, Xe=ND.DiscreteGaussian(2**64 * 5.37e-8))

cm64_14_lwe = baseline_params.updated(n=1060, Xe=ND.DiscreteGaussian(2**64 * 7.20e-8))

cm64_15_lwe = baseline_params.updated(n=1069, Xe=ND.DiscreteGaussian(2**64 * 6.16e-8))

cm64_16_lwe = baseline_params.updated(n=1075, Xe=ND.DiscreteGaussian(2**64 * 5.56e-8))

cm64 = [
    cm64_1_lwe,
    cm64_2_lwe,
    cm64_3_to_4_lwe,
    cm64_5_lwe,
    cm64_6_lwe,
    cm64_7_to_8_lwe,
    cm64_9_lwe,
    cm64_10_to_12_lwe,
    cm64_13_lwe,
    cm64_14_lwe,
    cm64_15_lwe,
    cm64_16_lwe,
]


# Non-CM-128 / Vanilla 128 [Current Table 10]

vanilla_1_lwe = baseline_params.updated(
    n=838, Xe=ND.DiscreteGaussian(2**64 * 3.31e-6)
)

vanilla_2_lwe = baseline_params.updated(
    n=866, Xe=ND.DiscreteGaussian(2**64 * 2.05e-6)
)

vanilla_3_lwe = baseline_params.updated(
    n=1007, Xe=ND.DiscreteGaussian(2**64 * 1.79e-7)
)

vanilla_4_lwe = baseline_params.updated(
    n=1098, Xe=ND.DiscreteGaussian(2**64 * 3.73e-8)
)

vanilla_128 = [
    vanilla_1_lwe,
    vanilla_2_lwe,
    vanilla_3_lwe,
    vanilla_4_lwe,
]

# CM-128 [Current Table 11]
cm128_1_to_3_lwe = baseline_params.updated(
    n=767, Xe=ND.DiscreteGaussian(2**64 * 1.13e-5)
)

cm128_4_lwe = baseline_params.updated(n=737, Xe=ND.DiscreteGaussian(2**64 * 1.89e-5))

cm128_5_lwe = baseline_params.updated(n=867, Xe=ND.DiscreteGaussian(2**64 * 2.01e-6))

cm128_6_lwe = baseline_params.updated(n=833, Xe=ND.DiscreteGaussian(2**64 * 3.62e-6))

cm128_7_lwe = baseline_params.updated(n=834, Xe=ND.DiscreteGaussian(2**64 * 3.55e-6))

cm128_8_lwe = baseline_params.updated(n=835, Xe=ND.DiscreteGaussian(2**64 * 3.49e-6))

cm128_9_lwe = baseline_params.updated(n=1007, Xe=ND.DiscreteGaussian(2**64 * 1.80e-7))

cm128_10_to_12_lwe = baseline_params.updated(
    n=974, Xe=ND.DiscreteGaussian(2**64 * 3.17e-7)
)

cm128_13_lwe = baseline_params.updated(
    n=1098, Xe=ND.DiscreteGaussian(2**64 * 3.74e-8)
)

cm128_14_lwe = baseline_params.updated(
    n=1070, Xe=ND.DiscreteGaussian(2**64 * 6.06e-8)
)

cm128_15_to_16_lwe = baseline_params.updated(
    n=1071, Xe=ND.DiscreteGaussian(2**64 * 5.95e-8)
)

cm128 = [
    cm128_1_to_3_lwe,
    cm128_4_lwe,
    cm128_5_lwe,
    cm128_6_lwe,
    cm128_7_lwe,
    cm128_8_lwe,
    cm128_9_lwe,
    cm128_10_to_12_lwe,
    cm128_13_lwe,
    cm128_14_lwe,
    cm128_15_to_16_lwe,
]

# Compression-128 [Current Table 12]
# The GLWE parameter set in this table is the same as vanillia_2_glwe

compression128_1_lwe = baseline_params.updated(
    n=805, Xe=ND.DiscreteGaussian(2**64 * 5.86e-6)
)

compression128_2_lwe = baseline_params.updated(
    n=891, Xe=ND.DiscreteGaussian(2**64 * 1.33e-6)
)

compression128_3_lwe = baseline_params.updated(
    n=935, Xe=ND.DiscreteGaussian(2**64 * 6.22e-7)
)

compression128_4_lwe = baseline_params.updated(
    n=1058, Xe=ND.DiscreteGaussian(2**64 * 7.45e-8)
)

compression128 = [
    compression128_1_lwe,
    compression128_2_lwe,
    compression128_3_lwe,
    compression128_4_lwe,
]


def top_k_estimates(estimate, k):
    result = []
    for key in estimate.keys():
        result.append((key, log(estimate[key]["rop"], 2)))
        result = sorted(result, key=lambda x: x[1])
    try:
        result = result[:k]
    except:
        result = result[:3]
    return result


result_vanilla_64 = []
result_cm_64 = []
result_vanilla_128 = []
result_cm_128 = []
result_compression_128 = []


def print_table_8():
    print("TABLE 8")
    for param in vanilla_64:
        estimate = LWE.estimate(param, deny_list=("arora-gb", "bkw"), quiet=True)
        out = (param, top_k_estimates(estimate, 5))
        print(out)
        print(" ")
        result_vanilla_64.append(out)


def print_table_9():
    print("TABLE 9")
    for param in cm64:
        estimate = LWE.estimate(param, deny_list=("arora-gb", "bkw"), quiet=True)
        result_cm_64.append((param, top_k_estimates(estimate, 5)))
        out = (param, top_k_estimates(estimate, 5))
        print(out)
        print(" ")
        result_vanilla_64.append(out)


def print_table_10():
    print("TABLE 10")
    for param in vanilla_128:
        estimate = LWE.estimate(param, deny_list=("arora-gb", "bkw"), quiet=True)
        result_vanilla_128.append((param, top_k_estimates(estimate, 5)))
        out = (param, top_k_estimates(estimate, 5))
        print(out)
        print(" ")
        result_vanilla_64.append(out)


def print_table_11():
    print("TABLE 11")
    for param in cm128:
        estimate = LWE.estimate(param, deny_list=("arora-gb", "bkw"), quiet=True)
        result_cm_128.append((param, top_k_estimates(estimate, 5)))
        out = (param, top_k_estimates(estimate, 5))
        print(out)
        print(" ")
        result_vanilla_64.append(out)


def print_table_12():
    print("TABLE 12")
    for param in compression128:
        estimate = LWE.estimate(param, deny_list=("arora-gb", "bkw"), quiet=True)
        result_compression_128.append((param, top_k_estimates(estimate, 5)))
        out = (param, top_k_estimates(estimate, 5))
        print(out)
        print(" ")
        result_vanilla_64.append(out)


# Comment the undesired tables.
print_table_8()
print_table_9()
print_table_10()
print_table_11()
print_table_12()
