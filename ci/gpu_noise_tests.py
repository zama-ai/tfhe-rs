#!/usr/bin/env python3
"""Helper for the gpu_noise_pfail_tests workflow.

The GPU integer noise and pfail tests live in
tfhe/src/integer/gpu/server_key/radix/tests_noise_distribution, one file per atomic pattern.
Each test is declared with the `create_gpu_parameterized_stringified_test!` macro, which
generates one `#[test]` per parameters set, named `test_gpu_<test>_<parameters lowercased>`.

This script reads those declarations straight from the sources (no compilation needed), so
the workflow can:
  * validate the pattern / test kind / parameters combination before starting a GPU instance,
  * run exactly the selected tests, one `cargo test` invocation per test, and report each
    result in the GitHub job summary,
  * check that the workflow drop-down options are in sync with the sources.

The sanity checks declared in the same files are listed as such and never selected.

Sub-commands:
  list            Print every available (pattern, kind, parameters) combination.
  resolve         Validate the workflow inputs and write the selected tests to $GITHUB_OUTPUT
                  (or the production tests of every pattern when the run_all_production
                  checkbox is ticked).
  run             Run the given tests on the GPU runner, stopping at the first failure, and
                  append the results to a summary.
  check-workflow  Verify the workflow drop-down options match the sources.
"""

import argparse
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tfhe/src/integer/gpu/server_key/radix/tests_noise_distribution"
MODULE_PATH = "integer::gpu::server_key::radix::tests_noise_distribution"
WORKFLOW_FILE = REPO_ROOT / ".github" / "workflows" / "gpu_noise_pfail_tests.yml"
SLAB_TOML = REPO_ROOT / "ci" / "slab.toml"

CARGO_FEATURES = "boolean,shortint,integer,gpu"

TEST_KINDS = ("noise", "pfail")
TEST_KIND_CHOICES = TEST_KINDS + ("both",)
ALL_PARAMS = "all"
ALL_PATTERNS = "all"

# Parameters set of the "run all production tests" checkbox of the workflow.
PRODUCTION_PARAMS = "TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128"

# Workflow platform choice -> Slab backend and profile (see ci/slab.toml).
PLATFORMS = {
    "1xH100": {"backend": "terraform", "profile": "generic-1or2-h100"},
}

MACRO_RE = re.compile(
    r"create_gpu_parameterized_stringified_test!\s*\(\s*(?P<name>\w+)\s*\{(?P<params>[^}]*)\}\s*\)",
    re.DOTALL,
)
LINE_COMMENT_RE = re.compile(r"//[^\n]*")
BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


class Test:
    def __init__(self, pattern, kind, function, param):
        self.pattern = pattern
        self.kind = kind
        self.function = function
        self.param = param

    @property
    def name(self):
        return f"test_gpu_{self.function}_{self.param.lower()}"

    @property
    def path(self):
        return f"{MODULE_PATH}::{self.pattern}::{self.name}"


def classify(function_name):
    if function_name.startswith("sanity_check"):
        return "sanity"
    if "_pfail" in function_name:
        return "pfail"
    if "_noise" in function_name:
        return "noise"
    raise ValueError(
        f"cannot tell whether '{function_name}' is a noise, pfail or sanity test from its name"
    )


def collect_tests(tests_dir=TESTS_DIR):
    """Return every test declared in the noise distribution modules, sanity checks included."""
    tests = []
    for source in sorted(tests_dir.glob("*.rs")):
        if source.name == "mod.rs":
            continue
        content = BLOCK_COMMENT_RE.sub("", source.read_text())
        content = LINE_COMMENT_RE.sub("", content)
        for match in MACRO_RE.finditer(content):
            function = match.group("name")
            kind = classify(function)
            params = [p.strip() for p in match.group("params").split(",") if p.strip()]
            for param in params:
                tests.append(Test(source.stem, kind, function, param))
    if not tests:
        raise RuntimeError(f"no test declaration found in {tests_dir}")
    return tests


def selectable_tests(tests):
    return [t for t in tests if t.kind in TEST_KINDS]


def patterns(tests):
    return sorted({t.pattern for t in selectable_tests(tests)})


def params(tests):
    return sorted({t.param for t in selectable_tests(tests)})


def fail(message):
    print(f"::error::{message}", file=sys.stderr)
    sys.exit(1)


def cmd_list(args):
    tests = collect_tests()
    rows = [(t.pattern, t.kind, t.param) for t in selectable_tests(tests)]
    widths = [max(len(r[i]) for r in rows) for i in range(3)]
    header = ("pattern", "kind", "parameters")
    widths = [max(w, len(h)) for w, h in zip(widths, header)]
    print("  ".join(h.ljust(w) for h, w in zip(header, widths)))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(c.ljust(w) for c, w in zip(row, widths)))
    sanity = len(tests) - len(rows)
    print(f"\n{len(rows)} selectable tests ({sanity} sanity checks are never selected)")


def select_tests(tests, pattern, test_kind, param):
    """Return {kind: [Test]} for the requested combination, or exit with an explanation."""
    tests = selectable_tests(tests)
    available_patterns = patterns(tests)
    if pattern != ALL_PATTERNS and pattern not in available_patterns:
        fail(
            f"unknown pattern '{pattern}', available patterns: "
            f"{', '.join([ALL_PATTERNS] + available_patterns)}"
        )
    if test_kind not in TEST_KIND_CHOICES:
        fail(f"unknown test kind '{test_kind}', expected one of: {', '.join(TEST_KIND_CHOICES)}")
    if param != ALL_PARAMS and param not in params(tests):
        fail(f"unknown parameters '{param}', available parameters: {', '.join(params(tests))}")

    kinds = TEST_KINDS if test_kind == "both" else (test_kind,)
    selected = {}
    for kind in kinds:
        candidates = [
            t for t in tests if pattern in (ALL_PATTERNS, t.pattern) and t.kind == kind
        ]
        matching = [t for t in candidates if param in (ALL_PARAMS, t.param)]
        if matching:
            selected[kind] = matching
            continue
        available = ", ".join(sorted({t.param for t in candidates})) or "none"
        where = "any pattern" if pattern == ALL_PATTERNS else f"pattern '{pattern}'"
        message = (
            f"no {kind} test for {where} with parameters '{param}' "
            f"(available parameters for this kind: {available})"
        )
        if test_kind != "both":
            fail(message)
        print(f"::warning::{message}, skipping {kind} tests")
    if not selected:
        fail(f"no noise or pfail test matches pattern '{pattern}' with parameters '{param}'")
    return selected


def select_production_tests(tests):
    """Return {kind: [Test]} with the noise and pfail tests of every pattern for the
    production parameters."""
    tests = [t for t in selectable_tests(tests) if t.param == PRODUCTION_PARAMS]
    if not tests:
        fail(f"no noise or pfail test uses the production parameters {PRODUCTION_PARAMS}")
    return {kind: [t for t in tests if t.kind == kind] for kind in TEST_KINDS}


def resolve_platform(platform):
    if platform not in PLATFORMS:
        fail(f"unknown platform '{platform}', available platforms: {', '.join(PLATFORMS)}")
    target = PLATFORMS[platform]
    import tomllib  # Python >= 3.11, only needed on the ubuntu-latest runner

    with open(SLAB_TOML, "rb") as f:
        slab = tomllib.load(f)
    profiles = slab.get("backend", {}).get(target["backend"], {})
    if target["profile"] not in profiles:
        fail(
            f"profile '{target['profile']}' not found under [backend.{target['backend']}] "
            f"in {SLAB_TOML.relative_to(REPO_ROOT)}"
        )
    return target


def cmd_resolve(args):
    tests = collect_tests()
    if args.run_all_production == "true":
        print(
            "::notice::run_all_production is set, the pattern, tests and parameters selections "
            f"are ignored: running every noise then every pfail test with {PRODUCTION_PARAMS}"
        )
        selected = select_production_tests(tests)
        selection = "production"
    else:
        selected = select_tests(tests, args.pattern, args.test_kind, args.params)
        selection = f"{args.pattern}_{args.test_kind}_{args.params}"
    platform = resolve_platform(args.platform)

    outputs = {kind: " ".join(t.path for t in selected.get(kind, [])) for kind in TEST_KINDS}
    print(f"selection: {selection}")
    for kind in TEST_KINDS:
        tests = selected.get(kind, [])
        print(f"{kind} tests ({len(tests)}):")
        for test in tests:
            print(f"  {test.path}")
    print(f"platform: {args.platform} -> {platform['backend']}/{platform['profile']}")

    with open(args.output, "a") as f:
        f.write(f"selection={selection}\n")
        for kind in TEST_KINDS:
            f.write(f"{kind}_tests={outputs[kind]}\n")
        f.write(f"backend={platform['backend']}\n")
        f.write(f"profile={platform['profile']}\n")


def cargo_test_command(cargo_profile):
    return [
        "cargo",
        "test",
        "--profile",
        cargo_profile,
        f"--features={CARGO_FEATURES}",
        "-p",
        "tfhe",
        "--lib",
        "--",
    ]


def check_tests_exist(cargo, tests):
    """Make sure every selected test is in the compiled test binary before running anything."""
    listed = subprocess.run(
        cargo + ["--list", "--exact", *tests], capture_output=True, text=True, cwd=REPO_ROOT
    )
    if listed.returncode != 0:
        print(listed.stderr, file=sys.stderr)
        fail("cargo failed to list the GPU tests, see the output above")
    listing = listed.stdout
    found = {line[: -len(": test")] for line in listing.splitlines() if line.endswith(": test")}
    missing = [t for t in tests if t not in found]
    if missing:
        fail(
            "selected tests not found in the compiled test binary (the sources and the "
            "workflow may be out of sync): " + ", ".join(missing)
        )


def format_duration(seconds):
    minutes, seconds = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {seconds:02d}s"
    if minutes:
        return f"{minutes}m {seconds:02d}s"
    return f"{seconds}s"


def cmd_run(args):
    tests = args.tests.split()
    if not tests:
        print(f"no {args.kind} test selected, nothing to run")
        return

    cargo = cargo_test_command(args.cargo_profile)
    check_tests_exist(cargo, tests)

    results = []
    for test in tests:
        print(f"::group::{args.kind}: {test}", flush=True)
        start = time.monotonic()
        returncode = subprocess.run(
            cargo + ["--exact", "--test-threads=1", "--nocapture", test], cwd=REPO_ROOT
        ).returncode
        duration = time.monotonic() - start
        print("::endgroup::", flush=True)
        passed = returncode == 0
        results.append((test, passed, duration))
        if not passed:
            print(f"::error::{args.kind} test failed: {test}", flush=True)
            break
    not_run = tests[len(results) :]

    failed = any(not passed for _, passed, _ in results)
    if not failed:
        status = "🟢 passed"
    elif not_run:
        status = f"🔴 failed, {len(not_run)} remaining test(s) not run"
    else:
        status = "🔴 failed"
    lines = [
        f"## {args.kind.capitalize()} tests: {status}",
        "",
        "| Test | Result | Duration |",
        "| --- | --- | --- |",
    ]
    for test, passed, duration in results:
        lines.append(
            f"| `{short_test_name(test)}` | {'🟢 passed' if passed else '🔴 failed'} "
            f"| {format_duration(duration)} |"
        )
    for test in not_run:
        lines.append(f"| `{short_test_name(test)}` | ⚪ not run | - |")
    summary = "\n".join(lines) + "\n\n"
    print(summary)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as f:
            f.write(summary)

    if failed:
        sys.exit(1)


def short_test_name(test):
    """`<module>::<test>` without the common module path prefix."""
    return "::".join(test.rsplit("::", 2)[-2:])


def workflow_options(workflow_file):
    """Return {input name: [options]} of the workflow_dispatch inputs of the workflow."""
    text = workflow_file.read_text()
    try:
        import yaml
    except ImportError:
        return workflow_options_without_yaml(text)

    data = yaml.safe_load(text)
    # PyYAML parses the bare `on:` key as the boolean True
    triggers = data.get("on") if "on" in data else data.get(True, {})
    inputs = (triggers or {}).get("workflow_dispatch", {}).get("inputs", {})
    return {name: [str(o) for o in spec.get("options", [])] for name, spec in inputs.items()}


def workflow_options_without_yaml(text):
    """Line based fallback for runners without PyYAML, relying on the 2-space indentation
    enforced by prettier: inputs are at indent 6, their `options:` at 8 and the values at 10."""
    options = {}
    current = None
    in_options = False
    for line in text.splitlines():
        if line.startswith("jobs:"):
            break
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if indent == 6 and stripped.endswith(":"):
            current = stripped[:-1]
            in_options = False
        elif indent == 8 and stripped == "options:" and current is not None:
            in_options = True
            options[current] = []
        elif in_options and indent == 10 and stripped.startswith("- "):
            options[current].append(stripped[2:].strip().strip("\"'"))
        elif stripped and indent < 10:
            in_options = False
    return options


def cmd_check_workflow(args):
    tests = collect_tests()
    expected = {
        "pattern": [ALL_PATTERNS] + patterns(tests),
        "test_kind": list(TEST_KIND_CHOICES),
        "params": [ALL_PARAMS] + params(tests),
        "platform": list(PLATFORMS),
    }
    actual = workflow_options(Path(args.workflow))

    errors = []
    for name, expected_options in expected.items():
        options = actual.get(name)
        if options is None:
            errors.append(f"input '{name}' is missing from the workflow")
        elif sorted(options) != sorted(expected_options):
            missing = sorted(set(expected_options) - set(options))
            extra = sorted(set(options) - set(expected_options))
            details = []
            if missing:
                details.append(f"missing: {', '.join(missing)}")
            if extra:
                details.append(f"unexpected: {', '.join(extra)}")
            errors.append(f"input '{name}' options are out of sync ({'; '.join(details)})")

    if errors:
        for error in errors:
            print(f"::error::{error}", file=sys.stderr)
        print(
            f"Update the options in {args.workflow} to match the output of "
            f"'python3 {Path(__file__).relative_to(REPO_ROOT)} list'",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"{args.workflow} options are in sync with the sources")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "list", help="print every available (pattern, kind, parameters) combination"
    )

    resolve = subparsers.add_parser(
        "resolve", help="validate the workflow inputs and output the selected tests"
    )
    resolve.add_argument(
        "--pattern", required=True, help=f"atomic pattern (test module name), or '{ALL_PATTERNS}'"
    )
    resolve.add_argument("--test-kind", required=True, choices=TEST_KIND_CHOICES)
    resolve.add_argument(
        "--params", required=True, help=f"parameters set name, or '{ALL_PARAMS}'"
    )
    resolve.add_argument("--platform", required=True, help=f"one of: {', '.join(PLATFORMS)}")
    resolve.add_argument(
        "--run-all-production",
        choices=("true", "false"),
        default="false",
        help="'true' selects the noise and pfail tests of every pattern for the production "
        "parameters and ignores --pattern/--test-kind/--params",
    )
    resolve.add_argument(
        "--output", required=True, help="file to append key=value pairs to (e.g. $GITHUB_OUTPUT)"
    )

    run = subparsers.add_parser("run", help="run the given tests one by one and report each result")
    run.add_argument(
        "--kind", required=True, choices=TEST_KINDS, help="kind of the given tests, for reporting"
    )
    run.add_argument(
        "--tests", required=True, help="space separated full test paths, as output by resolve"
    )
    run.add_argument("--cargo-profile", default="release")
    run.add_argument(
        "--summary", help="Markdown file to append the results table to (e.g. $GITHUB_STEP_SUMMARY)"
    )

    check = subparsers.add_parser(
        "check-workflow", help="verify the workflow drop-down options match the sources"
    )
    check.add_argument("--workflow", default=str(WORKFLOW_FILE))

    args = parser.parse_args()
    {
        "list": cmd_list,
        "resolve": cmd_resolve,
        "run": cmd_run,
        "check-workflow": cmd_check_workflow,
    }[args.command](args)


if __name__ == "__main__":
    main()
