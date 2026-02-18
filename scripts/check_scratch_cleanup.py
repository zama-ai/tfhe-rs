#!/usr/bin/env python3
"""Check CUDA binding naming conventions and Rust call site patterns.

Checks performed:
  1. No cleanup_ function in bindings.rs has an _async suffix.
  2. All scratch_ and cuda_ functions that form triplets with cleanup_
     have the _async suffix. cleanup_ must NOT have _async.
  3. Rust mod.rs call sites follow valid patterns:
     - Full triplet: scratch_cuda_*_async + cuda_*_async + cleanup_cuda_*
     - Setup/teardown only: scratch_cuda_*_async + cleanup_cuda_*
     - Standalone sync: cuda_* (no _async) called without scratch/cleanup
     Any cuda_*_async call requires matching scratch_*_async and cleanup_*.
  4. Non-async cuda_ functions in bindings.rs must call
     cuda_synchronize_stream in their C++ implementation.
  5. Rust functions calling _async bindings must either have _async in
     their own name, call .synchronize(), or call a cleanup_ binding.
  6. Rust functions calling cleanup_ bindings must NOT have _async in
     their own name (cleanup synchronizes, so the caller is synchronous).
"""

import os
import re
import subprocess
import sys

import tree_sitter as ts
import tree_sitter_rust as tsrust

RUST_LANG = ts.Language(tsrust.language())
RUST_PARSER = ts.Parser(RUST_LANG)

BINDINGS_RS = "backends/tfhe-cuda-backend/src/bindings.rs"

CPP_DIRS = [
    "backends/tfhe-cuda-backend/cuda/src",
    "backends/tfhe-cuda-backend/cuda/include",
]

CPP_EXTENSIONS = {".cu", ".cuh", ".h", ".cpp"}

RUST_CALL_SITES = [
    "tfhe/src/core_crypto/gpu/ffi.rs",
    "tfhe/src/integer/gpu/ffi.rs",
]

# ---------------------------------------------------------------------------
# Expected counts.  These MUST be updated when bindings are added or removed.
#
# If a check fails with a count mismatch, the script will diff the current
# branch against main to identify the offending binding(s), classify each
# change, and explain what is required for the checks to pass.
# ---------------------------------------------------------------------------

# Bindings parsed from bindings.rs
# Scratch functions: Two more than cleanup functions because of
#  'scratch_cuda_programmable_bootstrap_32_async' and
EXPECTED_SCRATCH_COUNT = 70

# Cuda operation functions
EXPECTED_CUDA_COUNT = 107

# Cleanup functions
EXPECTED_CLEANUP_COUNT = 70

# Check 3: Rust call-site scanning
# Number of functions in ffi.rs files
EXPECTED_CHECK3_RUST_FNS = 133
# Number of functions in ffi.rs files that
EXPECTED_CHECK3_ASYNC_CUDA_CALLS = 89

# Number of instances of Rust calls to the scratch/cuda/cleanup in a
# triplet sequence.
EXPECTED_CHECK3_SCRATCH_CUDA_CLEANUP_TRIPLET_CALLS = 110

# Check 5: Rust async-caller scanning
EXPECTED_CHECK5_ASYNC_CALLERS = 117

# Check 6: Rust cleanup-caller scanning
EXPECTED_CHECK6_CLEANUP_CALLERS = 107


def check_paths_exist():
    """Verify that all input files and directories exist.

    Returns a list of error messages (empty if all paths are valid).
    """
    errors = []
    for path in [BINDINGS_RS] + RUST_CALL_SITES:
        if not os.path.isfile(path):
            errors.append(
                f"  File not found: {path}\n"
                f"    If this file was renamed or moved, update the "
                f"corresponding path\n"
                f"    at the top of {os.path.basename(__file__)}."
            )
    for d in CPP_DIRS:
        if not os.path.isdir(d):
            errors.append(
                f"  Directory not found: {d}\n"
                f"    If this directory was renamed or moved, update "
                f"CPP_DIRS\n"
                f"    at the top of {os.path.basename(__file__)}."
            )
    return errors


def get_main_binding_sets():
    """Parse bindings from the main branch for diff comparison.

    Returns (main_scratch, main_cuda, main_cleanup) sets,
    or None if the main branch cannot be read (e.g. shallow clone).
    """
    try:
        content = subprocess.check_output(
            ["git", "show", f"main:{BINDINGS_RS}"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

    all_fns = set()
    for m in re.finditer(r"\bpub fn (\w+)\(", content):
        all_fns.add(m.group(1))

    scratch = {n for n in all_fns if n.startswith("scratch_cuda_")}
    cleanup = {n for n in all_fns if n.startswith("cleanup_cuda_")}
    cuda = {
        n
        for n in all_fns
        if n.startswith("cuda_")
        and not n.startswith("scratch_cuda_")
        and not n.startswith("cleanup_cuda_")
    }
    return scratch, cuda, cleanup


def explain_binding_changes(
    label, constant_name, expected, actual,
    current_set, main_sets,
):
    """Generate a detailed explanation for a binding count mismatch.

    Diffs against main, classifies each added/removed binding, and
    explains what conventions must be followed.

    Args:
        label: Human-readable category name (e.g. "scratch").
        constant_name: The EXPECTED_* constant to update.
        expected: The expected count from the constant.
        actual: The actual count found.
        current_set: Current branch's binding set for this category.
        main_sets: Tuple (main_scratch, main_cuda, main_cleanup) or None.
    """
    lines = [
        f"\n  *** BINDING COUNT CHANGED: {label} ***",
        f"  Expected {expected}, found {actual}.",
    ]

    if main_sets is None:
        lines.append(
            "  Could not read main branch for diff "
            "(shallow clone or missing remote)."
        )
        lines.append(
            f"  If this is not a mistake, update "
            f"{constant_name} to {actual}\n"
            f"  in {os.path.basename(__file__)}."
        )
        return "\n".join(lines)

    main_scratch, main_cuda, main_cleanup = main_sets

    # Pick the right main set based on label
    if label == "scratch":
        main_set = main_scratch
    elif label == "cuda":
        main_set = main_cuda
    else:
        main_set = main_cleanup

    added = sorted(current_set - main_set)
    removed = sorted(main_set - current_set)

    if added:
        lines.append(f"\n  Added in this branch ({len(added)}):")
        for name in added:
            lines.append(f"    + {name}")
            lines.extend(
                f"      {r}"
                for r in _binding_requirements(name)
            )

    if removed:
        lines.append(f"\n  Removed in this branch ({len(removed)}):")
        for name in removed:
            lines.append(f"    - {name}")

    lines.append(
        f"\n  If this is not a mistake, update {constant_name} "
        f"from {expected} to {actual}\n"
        f"  in {os.path.basename(__file__)}."
    )
    return "\n".join(lines)


def _binding_requirements(name):
    """Return a list of convention requirements for a binding name."""
    reqs = []

    if name.startswith("scratch_cuda_"):
        if not name.endswith("_async"):
            reqs.append("-> PROBLEM: scratch functions must end in _async.")
        reqs.append(
            "-> Needs a matching cleanup_cuda_<suffix_without_async>."
        )
        reqs.append(
            "-> Must be called together with its cleanup in the same "
            "Rust wrapper function."
        )

    elif name.startswith("cleanup_cuda_"):
        if name.endswith("_async"):
            reqs.append(
                "-> PROBLEM: cleanup functions must NOT end in _async."
            )
        reqs.append(
            "-> Needs a matching scratch_cuda_<suffix>_async."
        )

    elif name.startswith("cuda_"):
        if name.endswith("_async"):
            reqs.append(
                "-> Async binding: must be called with matching "
                "scratch_*_async + cleanup_* in the same Rust function."
            )
            reqs.append(
                "-> The Rust wrapper must call .synchronize() or a "
                "cleanup_ binding after the async call."
            )
        else:
            reqs.append(
                "-> Sync binding: its C++ implementation must call "
                "cuda_synchronize_stream or .synchronize()."
            )

    return reqs


def explain_rust_scan_count_mismatch(
    label, constant_name, expected, actual,
):
    """Generate explanation for a Rust scan count mismatch."""
    return (
        f"\n  *** RUST SCAN COUNT CHANGED: {label} ***\n"
        f"  Expected {expected}, found {actual}.\n"
        f"\n"
        f"  This count changed because bindings were added/removed or\n"
        f"  Rust call-site code was refactored. Verify that:\n"
        f"    - New async cuda calls have matching scratch + cleanup "
        f"in the same function.\n"
        f"    - Non-async Rust wrappers call .synchronize() or a "
        f"cleanup_ binding.\n"
        f"    - All Rust call-site files are listed in RUST_CALL_SITES.\n"
        f"\n"
        f"  If this is not a mistake, update {constant_name} "
        f"from {expected} to {actual}\n"
        f"  in {os.path.basename(__file__)}."
    )


def parse_bindings(path):
    """Extract all function names declared in bindings.rs."""
    with open(path) as f:
        content = f.read()

    all_fns = set()
    for m in re.finditer(r"\bpub fn (\w+)\(", content):
        all_fns.add(m.group(1))

    scratch = {n for n in all_fns if n.startswith("scratch_cuda_")}
    cleanup = {n for n in all_fns if n.startswith("cleanup_cuda_")}
    cuda = {
        n
        for n in all_fns
        if n.startswith("cuda_")
        and not n.startswith("scratch_cuda_")
        and not n.startswith("cleanup_cuda_")
    }

    return all_fns, scratch, cuda, cleanup


def check_1_no_async_cleanup(cleanup_set):
    """Check 1: No cleanup_ function has _async suffix."""
    violations = []
    for name in sorted(cleanup_set):
        if name.endswith("_async"):
            violations.append(f"  cleanup function has _async suffix: {name}")
    return violations, len(cleanup_set)


def check_2_triplet_async_naming(scratch_set, cuda_set, cleanup_set):
    """Check 2: Triplet scratch/cuda have _async, cleanup does not.

    For each cleanup_cuda_X, look for scratch_cuda_X (violation: missing _async)
    or scratch_cuda_X_async (correct). Same for cuda_X vs cuda_X_async.
    """
    violations = []

    # Build suffix maps
    scratch_by_suffix = {}
    for name in scratch_set:
        suffix = name[len("scratch_cuda_"):]
        scratch_by_suffix[suffix] = name

    cuda_by_suffix = {}
    for name in cuda_set:
        suffix = name[len("cuda_"):]
        cuda_by_suffix[suffix] = name

    cleanup_by_suffix = {}
    for name in cleanup_set:
        suffix = name[len("cleanup_cuda_"):]
        cleanup_by_suffix[suffix] = name

    triplets_checked = 0
    for suffix, cleanup_name in sorted(cleanup_by_suffix.items()):
        # Check for scratch/cuda WITHOUT _async (violations)
        scratch_no_async = scratch_by_suffix.get(suffix)
        scratch_with_async = scratch_by_suffix.get(suffix + "_async")

        cuda_no_async = cuda_by_suffix.get(suffix)
        cuda_with_async = cuda_by_suffix.get(suffix + "_async")

        has_scratch = scratch_no_async or scratch_with_async
        has_cuda = cuda_no_async or cuda_with_async
        if has_scratch or has_cuda:
            triplets_checked += 1

        # scratch exists without _async and no _async version exists
        if scratch_no_async and not scratch_with_async:
            if not scratch_no_async.endswith("_async"):
                violations.append(
                    f"  triplet scratch missing _async: {scratch_no_async} "
                    f"(cleanup: {cleanup_name})"
                )

        # cuda exists without _async in a triplet context
        if cuda_no_async and not cuda_with_async:
            if not cuda_no_async.endswith("_async"):
                if has_scratch:
                    violations.append(
                        f"  triplet cuda missing _async: {cuda_no_async} "
                        f"(cleanup: {cleanup_name})"
                    )

    return violations, triplets_checked


def extract_functions(source):
    """Extract (fn_name, line_number, body_text) for each function.

    Uses tree-sitter-rust for accurate AST-based parsing.
    """
    source_bytes = source.encode("utf-8")
    tree = RUST_PARSER.parse(source_bytes)
    functions = []

    for node in tree.root_node.children:
        if node.type == "function_item":
            name_node = node.child_by_field_name("name")
            body_node = node.child_by_field_name("body")
            if name_node is None or body_node is None:
                continue
            fn_name = name_node.text.decode("utf-8")
            fn_start = node.start_point.row + 1  # 1-indexed
            body_text = source_bytes[body_node.start_byte:body_node.end_byte].decode("utf-8")
            functions.append((fn_name, fn_start, body_text))

    return functions


def check_3_rust_call_sites(rust_files, all_bindings, scratch_set, cuda_set, cleanup_set):
    """Check 3: Rust call sites follow valid patterns."""
    violations = []
    fns_scanned = 0
    async_calls_checked = 0
    scratch_calls_checked = 0

    binding_names = all_bindings

    for filepath in rust_files:
        with open(filepath) as f:
            source = f.read()

        for fn_name, line_no, body in extract_functions(source):
            # Strip comments so commented-out calls are not matched
            code = strip_comments(body)
            # Find all binding calls in this function
            calls = set(re.findall(r"\b(\w+)\s*\(", code))
            binding_calls = calls & binding_names

            if not binding_calls:
                continue

            fns_scanned += 1

            # Separate by type
            scratch_calls = binding_calls & scratch_set
            cuda_calls = binding_calls & cuda_set
            cleanup_calls = binding_calls & cleanup_set

            # cuda_*_async calls require matching scratch and cleanup,
            # but only if such functions exist in bindings.rs.
            async_cuda_calls = {
                c for c in cuda_calls if c.endswith("_async")
            }
            async_calls_checked += len(async_cuda_calls)
            scratch_calls_checked += len(scratch_calls)

            for async_call in sorted(async_cuda_calls):
                suffix = async_call[len("cuda_"):]
                expected_scratch = f"scratch_cuda_{suffix}"
                cleanup_suffix = suffix.removesuffix("_async")
                expected_cleanup = f"cleanup_cuda_{cleanup_suffix}"

                # Check if matching scratch/cleanup exist in bindings.rs
                scratch_exists = expected_scratch in scratch_set
                cleanup_exists = expected_cleanup in cleanup_set

                # Only require scratch/cleanup if they exist in bindings
                if scratch_exists and expected_scratch not in scratch_calls:
                    violations.append(
                        f"  {filepath}:{line_no}: {fn_name}() calls "
                        f"{async_call} but missing {expected_scratch}"
                    )

                if cleanup_exists and expected_cleanup not in cleanup_calls:
                    violations.append(
                        f"  {filepath}:{line_no}: {fn_name}() calls "
                        f"{async_call} but missing {expected_cleanup}"
                    )

                # Naming mismatch: no matching scratch/cleanup exists in
                # bindings.rs but the function calls other scratch/cleanup
                # bindings — the cuda binding's name is inconsistent.
                if not scratch_exists and scratch_calls:
                    violations.append(
                        f"  {filepath}:{line_no}: {fn_name}() calls "
                        f"{async_call} alongside scratch binding(s) "
                        f"({', '.join(sorted(scratch_calls))}) but names "
                        f"don't match (expected {expected_scratch})"
                    )

                if not cleanup_exists and cleanup_calls:
                    violations.append(
                        f"  {filepath}:{line_no}: {fn_name}() calls "
                        f"{async_call} alongside cleanup binding(s) "
                        f"({', '.join(sorted(cleanup_calls))}) but names "
                        f"don't match (expected {expected_cleanup})"
                    )

            # Non-async cuda calls should not appear alongside scratch/cleanup.
            # If a function uses scratch allocation, the cuda call is async too.
            if scratch_calls or cleanup_calls:
                non_async_cuda = {
                    c for c in cuda_calls
                    if not c.endswith("_async")
                }
                for call in sorted(non_async_cuda):
                    violations.append(
                        f"  {filepath}:{line_no}: {fn_name}() calls "
                        f"non-async {call} alongside scratch/cleanup"
                    )

            # scratch_*_async calls require matching cleanup
            for scratch_call in sorted(scratch_calls):
                if not scratch_call.endswith("_async"):
                    violations.append(
                        f"  {filepath}:{line_no}: {fn_name}() calls "
                        f"scratch function without _async: {scratch_call}"
                    )
                    continue

                suffix = scratch_call[len("scratch_cuda_"):]
                cleanup_suffix = suffix.removesuffix("_async")
                expected_cleanup = f"cleanup_cuda_{cleanup_suffix}"

                if expected_cleanup not in cleanup_calls:
                    violations.append(
                        f"  {filepath}:{line_no}: {fn_name}() calls "
                        f"{scratch_call} but missing {expected_cleanup}"
                    )

    return violations, fns_scanned, async_calls_checked, scratch_calls_checked


def collect_cpp_files(dirs):
    """Collect all C++ source files from the given directories."""
    files = []
    for d in dirs:
        for root, _, filenames in os.walk(d):
            for f in filenames:
                if os.path.splitext(f)[1] in CPP_EXTENSIONS:
                    files.append(os.path.join(root, f))
    return sorted(files)


def find_cpp_function_body(func_name, content):
    """Find a C++ function definition body in content.

    Returns the body text (between { and }) if a definition is found,
    None if only declarations/calls are found.
    """
    pos = 0
    while pos < len(content):
        idx = content.find(func_name, pos)
        if idx == -1:
            return None

        # Verify whole-word match
        if idx > 0 and (content[idx - 1].isalnum() or content[idx - 1] == "_"):
            pos = idx + 1
            continue
        end_name = idx + len(func_name)
        if end_name < len(content) and (
            content[end_name].isalnum() or content[end_name] == "_"
        ):
            pos = idx + 1
            continue

        # Must be followed by '('
        after = content[end_name:].lstrip()
        if not after.startswith("("):
            pos = idx + 1
            continue

        # Find matching ')'
        paren_start = content.index("(", end_name)
        paren_depth = 0
        j = paren_start
        while j < len(content):
            if content[j] == "(":
                paren_depth += 1
            elif content[j] == ")":
                paren_depth -= 1
                if paren_depth == 0:
                    break
            j += 1

        # After ')', check for '{' (definition) vs ';' (declaration/call)
        rest = content[j + 1 : j + 100].lstrip()
        if not rest.startswith("{"):
            pos = j + 1
            continue

        # Extract body using brace counting
        brace_start = content.index("{", j + 1)
        brace_depth = 0
        k = brace_start
        while k < len(content):
            if content[k] == "{":
                brace_depth += 1
            elif content[k] == "}":
                brace_depth -= 1
                if brace_depth == 0:
                    return content[brace_start : k + 1]
            k += 1

        pos = idx + 1

    return None


def strip_comments(text):
    """Remove C/C++/Rust comments from text.

    Strips both // line comments and /* block comments */.
    """
    return re.sub(
        r'//[^\n]*|/\*.*?\*/',
        '',
        text,
        flags=re.DOTALL,
    )


def has_synchronize_call(body):
    """Check if a C++ function body contains a synchronization call.

    Accepts either cuda_synchronize_stream(...) or .synchronize().
    Ignores calls inside comments.
    """
    code = strip_comments(body)
    if "cuda_synchronize_stream" in code:
        return True
    if ".synchronize()" in code:
        return True
    return False


def check_4_sync_in_non_async_cpp(cuda_set):
    """Check 4: Non-async cuda functions must call cuda_synchronize_stream.

    For each cuda_ function in bindings.rs that does NOT have the _async
    suffix, verify that its C++ implementation calls cuda_synchronize_stream
    or .synchronize().
    """
    violations = []
    non_async = {c for c in cuda_set if not c.endswith("_async")}

    if not non_async:
        return violations, 0

    cpp_files = collect_cpp_files(CPP_DIRS)

    # Read all C++ files into memory
    file_contents = {}
    for f in cpp_files:
        with open(f) as fh:
            file_contents[f] = fh.read()

    checked = 0
    for func_name in sorted(non_async):
        body = None
        found_in = None
        for f, content in file_contents.items():
            body = find_cpp_function_body(func_name, content)
            if body is not None:
                found_in = f
                break

        if body is None:
            violations.append(
                f"  {func_name}: C++ definition not found in {', '.join(CPP_DIRS)}"
            )
            continue

        checked += 1
        if not has_synchronize_call(body):
            violations.append(
                f"  {found_in}: {func_name}() does not call "
                f"cuda_synchronize_stream or .synchronize() "
                f"(should it be _async?)"
            )

    return violations, checked


def check_5_rust_async_calls_synchronize(rust_files, all_bindings, cleanup_set):
    """Check 5: Rust functions calling _async bindings must synchronize.

    If a Rust function calls any binding ending in _async, it must either:
    - Have _async in its own name (caller is responsible for synchronizing)
    - Call .synchronize() in its body
    - Call a cleanup_ binding (which synchronizes on the C++ side)
    """
    violations = []
    checked = 0

    async_bindings = {n for n in all_bindings if n.endswith("_async")}

    for filepath in rust_files:
        with open(filepath) as f:
            source = f.read()

        for fn_name, line_no, body in extract_functions(source):
            calls = set(re.findall(r"\b(\w+)\s*\(", body))
            async_binding_calls = calls & async_bindings

            if not async_binding_calls:
                continue

            checked += 1

            # If the function itself is _async, caller must synchronize
            if fn_name.endswith("_async"):
                continue

            # Strip comments so commented-out calls are not counted
            code = strip_comments(body)

            # Find position of the last _async binding call
            last_async_pos = -1
            for ac in async_binding_calls:
                pos = code.rfind(ac)
                if pos > last_async_pos:
                    last_async_pos = pos

            # .synchronize() must appear AFTER the last async call
            sync_pos = code.rfind(".synchronize()")
            if sync_pos > last_async_pos:
                continue

            # A cleanup_ binding call AFTER the last async call also counts
            cleanup_calls = calls & cleanup_set
            if cleanup_calls:
                last_cleanup_pos = -1
                for cc in cleanup_calls:
                    pos = code.rfind(cc)
                    if pos > last_cleanup_pos:
                        last_cleanup_pos = pos
                if last_cleanup_pos > last_async_pos:
                    continue

            violations.append(
                f"  {filepath}:{line_no}: {fn_name}() calls async binding(s) "
                f"({', '.join(sorted(async_binding_calls))}): missing "
                f".synchronize() or cleanup_ call, or the calls are "
                f"not in the right order"
            )

    return violations, checked


def check_6_cleanup_callers_not_async(rust_files, all_bindings, cleanup_set):
    """Check 6: Rust functions calling cleanup_ bindings must not be _async.

    Cleanup functions synchronize on the C++ side, so the Rust wrapper
    that calls them should not have _async in its own name.
    """
    violations = []
    checked = 0

    for filepath in rust_files:
        with open(filepath) as f:
            source = f.read()

        for fn_name, line_no, body in extract_functions(source):
            # Strip comments so commented-out calls are not matched
            code = strip_comments(body)
            calls = set(re.findall(r"\b(\w+)\s*\(", code))
            cleanup_calls = calls & cleanup_set

            if not cleanup_calls:
                continue

            checked += 1

            if fn_name.endswith("_async"):
                violations.append(
                    f"  {filepath}:{line_no}: {fn_name}() calls cleanup "
                    f"binding(s) ({', '.join(sorted(cleanup_calls))}) "
                    f"but has _async suffix"
                )

    return violations, checked


def main():
    # -- Pre-flight: verify all input paths exist --
    path_errors = check_paths_exist()
    if path_errors:
        print("ERROR: required files/directories are missing:\n")
        for e in path_errors:
            print(e)
        return 1

    print(f"Parsing {BINDINGS_RS}...")
    all_bindings, scratch_set, cuda_set, cleanup_set = parse_bindings(BINDINGS_RS)
    print(
        f"  {len(scratch_set)} scratch, {len(cuda_set)} cuda, "
        f"{len(cleanup_set)} cleanup, {len(all_bindings)} total"
    )

    all_violations = []

    # -- Validate binding counts --
    print("\nValidating binding counts...")
    main_sets = get_main_binding_sets()  # may be None
    for label, current_set, expected, constant_name in [
        ("scratch", scratch_set, EXPECTED_SCRATCH_COUNT,
         "EXPECTED_SCRATCH_COUNT"),
        ("cuda", cuda_set, EXPECTED_CUDA_COUNT,
         "EXPECTED_CUDA_COUNT"),
        ("cleanup", cleanup_set, EXPECTED_CLEANUP_COUNT,
         "EXPECTED_CLEANUP_COUNT"),
    ]:
        if len(current_set) != expected:
            all_violations.append(
                explain_binding_changes(
                    label, constant_name, expected, len(current_set),
                    current_set, main_sets,
                )
            )

    if all_violations:
        print("  FAIL")
    else:
        print("  PASS")

    # Check 1
    print("\nCheck 1: No cleanup_ function has _async suffix...")
    v, n_cleanup = check_1_no_async_cleanup(cleanup_set)
    all_violations.extend(v)
    print(f"  Scanned {n_cleanup} cleanup functions")
    print(f"  {'PASS' if not v else f'{len(v)} violation(s)'}")

    # Check 2
    print("\nCheck 2: Triplet scratch/cuda have _async suffix...")
    v, n_triplets = check_2_triplet_async_naming(scratch_set, cuda_set, cleanup_set)
    all_violations.extend(v)
    print(f"  Scanned {n_triplets} triplets")
    print(f"  {'PASS' if not v else f'{len(v)} violation(s)'}")

    # Check 3
    print("\nCheck 3: Rust call sites follow valid patterns...")
    v, n_fns, n_async, n_scratch = check_3_rust_call_sites(
        RUST_CALL_SITES, all_bindings, scratch_set, cuda_set, cleanup_set
    )
    all_violations.extend(v)
    print(
        f"  Scanned {n_fns} Rust functions, "
        f"{n_async} async cuda calls, {n_scratch} scratch calls"
    )
    print(f"  {'PASS' if not v else f'{len(v)} violation(s)'}")

    # Validate Check 3 scan counts
    for label, actual, expected, constant_name in [
        ("Rust functions", n_fns, EXPECTED_CHECK3_RUST_FNS,
         "EXPECTED_CHECK3_RUST_FNS"),
        ("async cuda calls", n_async, EXPECTED_CHECK3_ASYNC_CUDA_CALLS,
         "EXPECTED_CHECK3_ASYNC_CUDA_CALLS"),
        ("scratch calls", n_scratch, EXPECTED_CHECK3_SCRATCH_CUDA_CLEANUP_TRIPLET_CALLS,
         "EXPECTED_CHECK3_SCRATCH_CUDA_CLEANUP_TRIPLET_CALLS"),
    ]:
        if actual != expected:
            all_violations.append(
                explain_rust_scan_count_mismatch(
                    label, constant_name, expected, actual,
                )
            )

    # Check 4
    print("\nCheck 4: Non-async cuda functions call synchronize in C++...")
    v, n_checked = check_4_sync_in_non_async_cpp(cuda_set)
    all_violations.extend(v)
    print(f"  Scanned {n_checked} non-async cuda functions")
    print(f"  {'PASS' if not v else f'{len(v)} violation(s)'}")

    # Check 5
    print("\nCheck 5: Rust _async callers are consistent...")
    v, n_checked5 = check_5_rust_async_calls_synchronize(
        RUST_CALL_SITES, all_bindings, cleanup_set
    )
    all_violations.extend(v)
    print(f"  Scanned {n_checked5} Rust functions calling _async bindings")
    print(f"  {'PASS' if not v else f'{len(v)} violation(s)'}")

    # Validate Check 5 scan count
    if n_checked5 != EXPECTED_CHECK5_ASYNC_CALLERS:
        all_violations.append(
            explain_rust_scan_count_mismatch(
                "async callers", "EXPECTED_CHECK5_ASYNC_CALLERS",
                EXPECTED_CHECK5_ASYNC_CALLERS, n_checked5,
            )
        )

    # Check 6
    print("\nCheck 6: Rust cleanup callers are not _async...")
    v, n_checked6 = check_6_cleanup_callers_not_async(
        RUST_CALL_SITES, all_bindings, cleanup_set
    )
    all_violations.extend(v)
    print(f"  Scanned {n_checked6} Rust functions calling cleanup bindings")
    print(f"  {'PASS' if not v else f'{len(v)} violation(s)'}")

    # Validate Check 6 scan count
    if n_checked6 != EXPECTED_CHECK6_CLEANUP_CALLERS:
        all_violations.append(
            explain_rust_scan_count_mismatch(
                "cleanup callers", "EXPECTED_CHECK6_CLEANUP_CALLERS",
                EXPECTED_CHECK6_CLEANUP_CALLERS, n_checked6,
            )
        )

    if all_violations:
        print(f"\n{'=' * 60}")
        print(f"  FAILED: {len(all_violations)} violation(s) found")
        print(f"{'=' * 60}")
        for msg in all_violations:
            print(msg)
        return 1

    print(f"\n{'=' * 60}")
    print("  All checks passed.")
    print(f"{'=' * 60}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
