"""
Script that generates a cargo-nextest filter as an output.
The string result can be directly injected into a nextest command.

With --check, it instead reads `cargo nextest list --message-format json` on stdin and checks
that the CI workflows run every CPU integer test.
"""

import argparse
import glob
import json
import re
import sys

# Parameter tiers of the CPU integer tests: a test belongs to the tier whose regexes match its
# name, i.e. the param suffix added by create_parameterized_test!.
# Tier 0 (prod params, tested on each PR) is every test no other tier matches, so tests without
# a param in their name, or with a param missing from this table, are tested the most, not never.
CPU_INTEGER_TIERS = {
    # Not prod but promoted to users
    1: [r"_ks32_pbs_tuniform_2m128$"],
    # Less used params
    2: [
        r"_param_message_1_carry_1_",
        r"_param_multi_bit_group_\d_message_[12]_carry_[12]_",
        r"_message_2_carry_2_ks_pbs_gaussian_2m128$",
    ],
    # Big (slow) params and legacy ones
    3: [
        r"_message_[34]_carry_[34]_",
        r"_message_2_carry_3_",
        r"_compact_pk_",
        r"_pbs_ks_gaussian_",
        r"legacy_wopbs_param_",
    ],
}

# Tier 0 should only hold the prod params, under all their alias spellings. A test of another
# param in tier 0 means that param is missing from CPU_INTEGER_TIERS.
CPU_INTEGER_TIER_0_PARAMS = r"_param_message_2_carry_2(_ks_pbs_tuniform_2m128)?$"

# Tests that no tier runs, with the reason. A pattern must match the tests of a single test
# function (for any param), so that it cannot exclude more than intended.
CPU_INTEGER_NEVER_RUN = {
    r"::test_integer_default_div_(test_)?param_": "covered by integer_default_div_rem",
    r"::test_integer_default_rem_(test_)?param_": "covered by integer_default_div_rem",
}

# Long run tests have their own workflow
INTEGER_LONG_RUN_TESTS = r"::tests_long_run::"

# Workflows running tiered integer tests, they give the tiers as a literal input (`tiers: "1"`)
TIERED_INTEGER_WORKFLOWS = ".github/workflows/aws_tfhe_integer_tests*.yml"
WORKFLOW_TIERS_INPUT = re.compile(r"^\s*tiers:\s*[\"']?([0-9][0-9, ]*)[\"']?\s*(#.*)?$", re.MULTILINE)

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
    "--tier",
    dest="tiers",
    action="append",
    type=int,
    choices=sorted({0, *CPU_INTEGER_TIERS}),
    help="Run the tests of this parameter tier (integer layer, cpu backend), can be repeated",
)
parser.add_argument(
    "--check",
    dest="check",
    action="store_true",
    help="Check that the CI workflows run every CPU integer test listed by "
    "`cargo nextest list --message-format json` (read on stdin)",
)

# block PBS are too slow for high params
# mul_crt_4_4 is extremely flaky (~80% failure)
# test_wopbs_bivariate_crt_wopbs_param_message generate tables that are too big at the moment
# test_integer_default_add_sequence_multi_thread_param_message_4_carry_4_ks_pbs_gaussian_2m64 is too slow
# skip default_div, default_rem which are covered by default_div_rem
EXCLUDED_INTEGER_TESTS = [
    "/.*integer_default_div_param/",
    "/.*integer_default_rem_param/",
    "/.*_block_pbs(_base)?_param_message_[34]_carry_[34]_ks_pbs_gaussian_2m64$/",
    "~mul_crt_param_message_4_carry_4_ks_pbs_gaussian_2m64",
    "/.*test_wopbs_bivariate_crt_wopbs_param_message_[34]_carry_[34]_ks_pbs_gaussian_2m64$/",
    "/.*test_integer_default_add_sequence_multi_thread_param_message_4_carry_4_ks_pbs_gaussian_2m64$/",
    "/.*::tests_long_run::.*/",
]

# skip default_div, default_rem which are covered by default_div_rem
EXCLUDED_INTEGER_FAST_TESTS = [
    "/.*integer_default_div_param/",
    "/.*integer_default_rem_param/",
    "/.*_param_message_[14]_carry_[14]_ks_pbs_gaussian_2m64$/",
    "/.*default_add_sequence_multi_thread_param_message_3_carry_3_ks_pbs_gaussian_2m64$/",
]

EXCLUDED_BIG_PARAMETERS = [
    "/.*_param_message_4_carry_4_ks_pbs_gaussian_2m64$/",
]

EXCLUDED_BIG_PARAMETERS_GPU = [
    "/.*_message_3_carry_3.*$/",
    "/.*_group_3_message_2_carry_2.*$/",
]


def filter_integer_tests(input_args):
    if input_args.tiers:
        return filter_cpu_integer_tests_by_tier(input_args)

    # Run all tests except noise tests if all_but_noise is specified on GPU
    if input_args.all_but_noise and input_args.backend == "gpu":
        filter_expression = [
            f"test(/^integer::gpu::.*/)",
            f"not test(/^integer::gpu::server_key::radix::tests_noise_distribution::.*/)"
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
            EXCLUDED_INTEGER_FAST_TESTS if input_args.fast_tests else EXCLUDED_INTEGER_TESTS
        )
        for pattern in excluded_tests:
            filter_expression.append(f"not test({pattern})")

    else:
        if input_args.backend == "gpu":
            filter_expression = ["test(/^integer::gpu::server_key::radix::tests_long_run.*/)"]
        elif input_args.backend == "cpu":
            filter_expression = ["test(/^integer::server_key::radix_parallel::tests_long_run.*/)"]


    # Do not run noise check tests by default as they can be very slow
    # they will be run e.g. nightly or on demand
    if input_args.all_but_noise and input_args.backend == "cpu":
        # For CPU with all_but_noise, exclude also all noise distribution tests
        filter_expression.append(f"not test(/^shortint::server_key::.*::noise_distribution::.*/)")
        filter_expression.append(f"not test(/^integer::server_key::.*::noise_distribution::.*/)")
    else:
        # By default, only exclude specific GPU noise check tests
        filter_expression.append(f"not test(/^integer::gpu::server_key::radix::tests_noise_distribution::.*::test_gpu_noise_check.*/)")

    return " and ".join(filter_expression)


def cpu_integer_tiers_of(test_name):
    """Tiers whose regexes match a test name, [0] when none does"""
    tiers = [
        tier
        for tier, patterns in CPU_INTEGER_TIERS.items()
        if any(re.search(pattern, test_name) for pattern in patterns)
    ]
    return tiers or [0]


def filter_cpu_integer_tests_by_tier(input_args):
    tier_filters = []
    # Each tier adds one term `test(xxx)` / `not test(xxx)` and are composed with `or`,
    # i.e. despite tier 0 being defined differently, it can be combined with other tiers
    # e.g. --tier 0 --tier 1 (TIERS=0,1 for the Makefile)
    for tier in sorted(set(input_args.tiers)):
        # Tier 0 is defined as: everything but other tiers
        # This definition is what allows to be confident that tests that do not need to 
        # be parameterized will run, and they will run as frequently as tier 0 runs
        if tier == 0:
            other_tiers = "|".join(
                pattern for patterns in CPU_INTEGER_TIERS.values() for pattern in patterns
            )
            tier_filters.append(f"not test(/{other_tiers}/)")
        else:
            tier_filters.append(f"test(/{'|'.join(CPU_INTEGER_TIERS[tier])}/)")

    filter_expression = ["test(/^integer::/)", f"({' or '.join(tier_filters)})"]

    if input_args.signed_only:
        filter_expression.append("test(~_signed)")
    if input_args.unsigned_only:
        filter_expression.append("not test(~_signed)")

    filter_expression.append(f"not test(/{INTEGER_LONG_RUN_TESTS}/)")
    for pattern in CPU_INTEGER_NEVER_RUN:
        filter_expression.append(f"not test(/{pattern}/)")

    return " and ".join(filter_expression)


def workflow_tiers(workflow_files):
    """Tiers given as a literal `tiers:` input in the workflow files"""
    tiers = set()
    for workflow_file in workflow_files:
        with open(workflow_file) as f:
            for match in WORKFLOW_TIERS_INPUT.finditer(f.read()):
                tiers |= {int(tier) for tier in match.group(1).replace(" ", "").split(",") if tier}
    return tiers


def check_cpu_integer_tiers(test_list, scheduled_tiers):
    """
    Lists errors that prevent a CPU integer test from the `test_list` from being run in any
    of the `scheduled_tiers`.
    The scheduled tiers must be the tiers CPU_INTEGER_TIERS defines, no more no less.

    `test_list` is the json coming from `cargo nextest list --message-format json`
    """
    # Lists all tests for CPU integer, as the `test_list` will contain tests for other
    # modules
    tests = {}  # test name -> ignored
    for suite in test_list["rust-suites"].values():
        for name, test_case in suite["testcases"].items():
            if name.startswith("integer::") and not name.startswith("integer::gpu::"):
                tests[name] = test_case["ignored"]

    errors = []

    defined_tiers = {0, *CPU_INTEGER_TIERS}
    for tier in sorted(defined_tiers - scheduled_tiers):
        errors.append(f"tier {tier} is not run by any workflow")
    for tier in sorted(scheduled_tiers - defined_tiers):
        errors.append(f"a workflow runs tier {tier}, which CPU_INTEGER_TIERS does not define")

    for pattern, reason in CPU_INTEGER_NEVER_RUN.items():
        # A test function is the test name without its param suffix
        functions = {
            re.sub(r"_(test_)?param_.*$", "", name) for name in tests if re.search(pattern, name)
        }
        if len(functions) != 1:
            errors.append(
                f"CPU_INTEGER_NEVER_RUN pattern {pattern!r} ({reason}) must match the tests of "
                f"one test function, it matches {len(functions)}"
            )

    for name, ignored in sorted(tests.items()):
        if ignored:
            errors.append(f"{name}: is #[ignore]d, nextest does not run it")
        if re.search(INTEGER_LONG_RUN_TESTS, name) or any(
            re.search(pattern, name) for pattern in CPU_INTEGER_NEVER_RUN
        ):
            continue

        tiers = cpu_integer_tiers_of(name)
        test_function = name.rsplit("::", 1)[-1]
        if len(tiers) > 1:
            errors.append(f"{name}: belongs to several tiers {tiers}")
        elif (
            tiers[0] == 0
            and "_param_" in test_function
            and not re.search(CPU_INTEGER_TIER_0_PARAMS, test_function)
        ):
            errors.append(f"{name}: its param has no tier, add it to CPU_INTEGER_TIERS")

    return errors


def filter_shortint_tests(input_args):
    multi_bit_filter, group_filter = (
        ("_multi_bit", "_group_[0-9]") if input_args.multi_bit else ("", "")
    )

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
        f"test(/^shortint::.*_param{multi_bit_filter}{group_filter}_message_{msg}_carry_{carry}(_compact_pk)?_ks(32)?_pbs.*/)"
        for msg, carry in msg_carry_pairs
    ]
    filter_expression.append("test(/^shortint::.*meta_param_cpu_2_2/)")

    filter_expression.append("test(/^shortint::.*_ci_run_filter/)")

    opt_in_tests = " or ".join(filter_expression)

    # Do not run noise check tests by default as they can be very slow
    # they will be run e.g. nightly or on demand
    filter = f"({opt_in_tests}) and not test(/^shortint::.*test_noise_check/)"

    return filter


if __name__ == "__main__":
    args = parser.parse_args()

    if (args.tiers or args.check) and (args.layer != "integer" or args.backend != "cpu"):
        parser.error("--tier and --check only apply to the integer layer on the cpu backend")
    if args.tiers and (
        args.fast_tests
        or args.nightly_tests
        or args.long_tests
        or args.no_big_params
        or args.all_but_noise
        or args.multi_bit
    ):
        parser.error(
            "--tier replaces --fast-tests, --nightly-tests, --long-tests, --no-big-params, "
            "--all-but-noise and --multi-bit (multi-bit params belong to tiers like any param)"
        )

    if args.check:
        scheduled_tiers = workflow_tiers(sorted(glob.glob(TIERED_INTEGER_WORKFLOWS)))
        errors = check_cpu_integer_tiers(json.load(sys.stdin), scheduled_tiers)
        if errors:
            for error in errors:
                print(error, file=sys.stderr)
            sys.exit(f"{len(errors)} CPU integer test(s) would not run in CI, see above")
        print(f"Every CPU integer test runs in CI (scheduled tiers: {sorted(scheduled_tiers)})")
        sys.exit(0)

    expression = ""

    if args.layer == "integer":
        expression = filter_integer_tests(args)
    elif args.layer == "shortint":
        expression = filter_shortint_tests(args)

    print(expression)
