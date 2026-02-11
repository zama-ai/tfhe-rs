"""
Script that generates a cargo-nextest filter as an output.
The string result can be directly injected into a nextest command.
"""

import argparse

parser = argparse.ArgumentParser(allow_abbrev=False)
parser.add_argument(
    "--layer",
    dest="layer",
    choices=["integer", "shortint"],
    required=True,
    help="tfhe-rs layer to use",
)
parser.add_argument(
    "--backend",
    dest="backend",
    choices=["cpu", "gpu"],
    default="cpu",
    help="tfhe-rs backend to use",
)
parser.add_argument(
    "--fast-tests",
    dest="fast_tests",
    action="store_true",
    help="Run only a small subset of test suite",
)
parser.add_argument(
    "--long-tests",
    dest="long_tests",
    action="store_true",
    help="Run only the long tests suite",
)
parser.add_argument(
    "--nightly-tests",
    dest="nightly_tests",
    action="store_true",
    help="Run only a subset of test suite",
)
parser.add_argument(
    "--big-instance",
    dest="big_instance",
    action="store_true",
    help="Backend is using a large instance",
)
parser.add_argument(
    "--multi-bit",
    dest="multi_bit",
    action="store_true",
    help="Include tests running on multi-bit parameters set",
)
parser.add_argument(
    "--signed-only",
    dest="signed_only",
    action="store_true",
    help="Include only signed integer tests",
)
parser.add_argument(
    "--unsigned-only",
    dest="unsigned_only",
    action="store_true",
    help="Include only unsigned integer tests",
)
parser.add_argument(
    "--no-big-params",
    dest="no_big_params",
    action="store_true",
    help="Do not run tests with big parameters set (e.g. 4bits message with 4 bits carry)",
)
parser.add_argument(
    "--no-big-params-gpu",
    dest="no_big_params_gpu",
    action="store_true",
    help="Do not run tests with big parameters set (e.g. 3bits message with 3 bits carry) for GPU",
)
parser.add_argument(
    "--all-but-noise",
    dest="all_but_noise",
    action="store_true",
    help="Run all tests except noise tests",
)
parser.add_argument(
    "--run-prod-only",
    action="store_true",
    help="Specify to run the CPU tests with the prod KS_PBS 2_2 parameters, \
        only the 'layer' parameter will be taken into account if this flag is specified",
)

# block PBS are too slow for high params
# mul_crt_4_4 is extremely flaky (~80% failure)
# test_wopbs_bivariate_crt_wopbs_param_message generate tables that are too big at the moment
# test_integer_smart_mul_param_message_4_carry_4_ks_pbs_gaussian_2m64 is too slow
# skip smart_div, smart_rem which are already covered by the smar_div_rem test
# skip default_div, default_rem which are covered by default_div_rem
EXCLUDED_INTEGER_TESTS = [
    "/.*integer_smart_div_param/",
    "/.*integer_smart_rem_param/",
    "/.*integer_default_div_param/",
    "/.*integer_default_rem_param/",
    "/.*_block_pbs(_base)?_param_message_[34]_carry_[34]_ks_pbs_gaussian_2m64$/",
    "~mul_crt_param_message_4_carry_4_ks_pbs_gaussian_2m64",
    "/.*test_wopbs_bivariate_crt_wopbs_param_message_[34]_carry_[34]_ks_pbs_gaussian_2m64$/",
    "/.*test_integer_smart_mul_param_message_4_carry_4_ks_pbs_gaussian_2m64$/",
    "/.*::tests_long_run::.*/",
]

# skip default_div, default_rem which are covered by default_div_rem
EXCLUDED_INTEGER_FAST_TESTS = [
    "/.*integer_default_div_param/",
    "/.*integer_default_rem_param/",
    "/.*_param_message_[14]_carry_[14]_ks_pbs_gaussian_2m64$/",
]

EXCLUDED_BIG_PARAMETERS = [
    "/.*_param_message_4_carry_4_ks_pbs_gaussian_2m64$/",
]

EXCLUDED_BIG_PARAMETERS_GPU = [
    "/.*_message_3_carry_3.*$/",
    "/.*_group_3_message_2_carry_2.*$/",
]


def filter_integer_tests(input_args):
    # Run all tests except noise tests if all_but_noise is specified on GPU
    if input_args.all_but_noise and input_args.backend == "gpu":
        filter_expression = [
            f"test(/^integer::gpu::.*/)",
            f"not test(/^integer::gpu::server_key::radix::tests_noise_distribution::.*/)",
        ]
        return " and ".join(filter_expression)

    (multi_bit_filter, group_filter) = (
        ("_multi_bit", "_group_[0-9]") if input_args.multi_bit else ("", "")
    )
    backend_filter = ""
    if not input_args.long_tests:
        if input_args.backend == "gpu":
            backend_filter = "gpu::"
            if multi_bit_filter:
                # For now, GPU only has specific parameters set for multi-bit
                multi_bit_filter = "_gpu_multi_bit"

        filter_expression = [f"test(/^integer::{backend_filter}.*/)"]

        if input_args.multi_bit:
            filter_expression.append("test(~_multi_bit)")
        else:
            filter_expression.append("not test(~_multi_bit)")

        if input_args.signed_only:
            filter_expression.append("test(~_signed)")
        if input_args.unsigned_only:
            filter_expression.append("not test(~_signed)")

        if input_args.no_big_params:
            for pattern in EXCLUDED_BIG_PARAMETERS:
                filter_expression.append(f"not test({pattern})")

        if input_args.no_big_params_gpu:
            for pattern in EXCLUDED_BIG_PARAMETERS_GPU:
                filter_expression.append(f"not test({pattern})")

        if input_args.fast_tests and input_args.nightly_tests:
            filter_expression.append(
                f"test(/.*_default_.*?_param{multi_bit_filter}{group_filter}_message_[2-3]_carry_[2-3]_.*/)"
            )
        elif input_args.fast_tests:
            # Test only fast default operations with only one set of parameters
            filter_expression.append(
                f"test(/.*_default_.*?_param{multi_bit_filter}{group_filter}_message_2_carry_2_.*/)"
            )
        elif input_args.nightly_tests:
            # Test only fast default operations with only one set of parameters
            # This subset would run slower than fast_tests hence the use of nightly_tests
            filter_expression.append(
                f"test(/.*_default_.*?_param{multi_bit_filter}{group_filter}_message_3_carry_3_.*/)"
            )
        excluded_tests = (
            EXCLUDED_INTEGER_FAST_TESTS
            if input_args.fast_tests
            else EXCLUDED_INTEGER_TESTS
        )
        for pattern in excluded_tests:
            filter_expression.append(f"not test({pattern})")

    else:
        if input_args.backend == "gpu":
            filter_expression = [
                "test(/^integer::gpu::server_key::radix::tests_long_run.*/)"
            ]
        elif input_args.backend == "cpu":
            filter_expression = [
                "test(/^integer::server_key::radix_parallel::tests_long_run.*/)"
            ]

    # Do not run noise check tests by default as they can be very slow
    # they will be run e.g. nightly or on demand
    if input_args.all_but_noise and input_args.backend == "cpu":
        # For CPU with all_but_noise, exclude also all noise distribution tests
        filter_expression.append(
            f"not test(/^shortint::server_key::.*::tests_noise_distribution::.*/)"
        )
    else:
        # By default, only exclude specific GPU noise check tests
        filter_expression.append(
            f"not test(/^integer::gpu::server_key::radix::tests_noise_distribution::.*::test_gpu_noise_check.*/)"
        )

    return " and ".join(filter_expression)


def shortint_normal_filter(input_args):
    multi_bit_filter = "_multi_bit_group_[0-9]" if input_args.multi_bit else ""

    if input_args.fast_tests:
        msg_carry_pairs = [(2, 1), (2, 2), (2, 3)]
    else:
        msg_carry_pairs = [
            (1, 1),
            (1, 2),
            (1, 3),
            (1, 4),
            (1, 5),
            (1, 6),
            (2, 1),
            (2, 2),
            (2, 3),
            (3, 1),
            (3, 2),
            (3, 3),
        ]
        if input_args.big_instance:
            msg_carry_pairs.append((4, 4))

    filter_expression = [
        f"test(/^shortint::.*_param{multi_bit_filter}_message_{msg}_carry_{carry}\
(_compact_pk)?_ks(32)?_pbs.*/)"
        for msg, carry in msg_carry_pairs
    ]

    filter_expression.append("test(/^shortint::.*meta_param_cpu_2_2_ks32_pbs/)")
    filter_expression.append("test(/^shortint::.*_ci_run_filter/)")

    return filter_expression


def filter_shortint_tests(input_args):
    # We special case the CPU KS_PBS 2_2 parameters to be able to run them alone
    filter_expression = shortint_normal_filter(input_args)
    opt_in_tests = " or ".join(filter_expression)

    # Do not run noise check tests by default as they can be very slow
    # they will be run e.g. nightly or on demand
    filter = f"({opt_in_tests}) and not test(/^shortint::.*test_noise_check/)"

    if input_args.run_prod_only:
        filter = f"({filter}) and test(/^shortint::.*_param_prod.*/)"
    else:
        filter = f"({filter}) and not test(/^shortint::.*_param_prod.*/)"

    return filter


if __name__ == "__main__":
    args = parser.parse_args()

    expression = ""

    if args.layer == "integer":
        expression = filter_integer_tests(args)
    elif args.layer == "shortint":
        expression = filter_shortint_tests(args)

    print(expression)
