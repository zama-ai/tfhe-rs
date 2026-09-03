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
  7. No scratch_cuda_* function reaches a host synchronization, directly
     or through any function, constructor, member-initializer list or
     method call below it.
"""

import os
import re
import subprocess
import sys
from collections import defaultdict, deque

import tree_sitter as ts
import tree_sitter_rust as tsrust

RUST_LANG = ts.Language(tsrust.language())
RUST_PARSER = ts.Parser(RUST_LANG)

import tree_sitter_cpp as tscpp

CPP_LANG = ts.Language(tscpp.language())
CPP_PARSER = ts.Parser(CPP_LANG)

BINDINGS_RS = "backends/tfhe-cuda-backend/src/bindings.rs"

CPP_DIRS = [
    "backends/tfhe-cuda-backend/cuda/src",
    "backends/tfhe-cuda-backend/cuda/include",
]

# Check 7 also walks the shared CUDA runtime wrappers.  Scratch paths call
# cuda_memcpy_with_size_tracking_async_to_gpu and its siblings there, and each
# of them calls cuda_set_device, so the walk cannot stop at the backend
# boundary without claiming more than it verifies.  CPP_DIRS itself is left
# alone so the counts of check 4 do not move.
SYNC_WALK_CPP_DIRS = CPP_DIRS + [
    "backends/tfhe-cuda-common/cuda/src",
    "backends/tfhe-cuda-common/cuda/include",
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
EXPECTED_SCRATCH_COUNT = 80

# Cuda operation functions
EXPECTED_CUDA_COUNT = 118

# Cleanup functions
EXPECTED_CLEANUP_COUNT = 80

# Check 3: Rust call-site scanning
# Number of functions in ffi.rs files
EXPECTED_CHECK3_RUST_FNS = 140
# Number of functions in ffi.rs files that
EXPECTED_CHECK3_ASYNC_CUDA_CALLS = 104

# Number of instances of Rust calls to the scratch/cuda/cleanup in a
# triplet sequence.
EXPECTED_CHECK3_SCRATCH_CUDA_CLEANUP_TRIPLET_CALLS = 122

# Check 5: Rust async-caller scanning
EXPECTED_CHECK5_ASYNC_CALLERS = 133

# Check 6: Rust cleanup-caller scanning
EXPECTED_CHECK6_CLEANUP_CALLERS = 120

# Check 7: transitive walk from scratch entry points to a host sync
# Scratch entry points from bindings.rs that have a C++ definition
EXPECTED_CHECK7_SCRATCH_ENTRY_POINTS = 80
# Scratch entry points allowed to reach a host synchronization. This must
# stay 0: a scratch function only allocates and prepares device buffers,
# so it must not block the host.
ALLOWED_CHECK7_SYNC_VIOLATIONS = 0


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
    for d in SYNC_WALK_CPP_DIRS:
        if not os.path.isdir(d):
            errors.append(
                f"  Directory not found: {d}\n"
                f"    If this directory was renamed or moved, update "
                f"CPP_DIRS or SYNC_WALK_CPP_DIRS\n"
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


_CUDA_ATTR_RE = re.compile(
    r"\b(?:__device__|__host__|__global__|__forceinline__|__noinline__)\b"
    r"|__launch_bounds__\s*\([^)]*\)"
)


def _strip_cuda_attrs(source_bytes):
    """Replace CUDA function attributes with spaces to help tree-sitter-cpp."""
    text = source_bytes.decode("utf-8", errors="replace")
    text = _CUDA_ATTR_RE.sub(lambda m: " " * len(m.group(0)), text)
    return text.encode("utf-8")


def find_all_nodes(root, node_types):
    """Yield every descendant (including inside ERROR nodes) matching node_types."""
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in node_types:
            yield node
        stack.extend(reversed(node.children))


def _func_decl_name(declarator):
    """Extract the plain function name from a function_declarator AST node."""
    while declarator.type in ("pointer_declarator", "reference_declarator"):
        inner = None
        for child in declarator.children:
            if child.type in ("function_declarator", "pointer_declarator",
                              "reference_declarator"):
                inner = child
                break
        if inner is None:
            return None
        declarator = inner
    if declarator.type != "function_declarator":
        return None
    for child in declarator.children:
        if child.type in ("identifier", "field_identifier"):
            return child.text.decode("utf-8")
        if child.type == "destructor_name":
            return child.text.decode("utf-8")
        if child.type == "template_function":
            for tc in child.children:
                if tc.type in ("identifier", "field_identifier"):
                    return tc.text.decode("utf-8")
        if child.type == "qualified_identifier":
            last_id = None
            for qc in child.children:
                if qc.type in ("identifier", "field_identifier",
                                "destructor_name"):
                    last_id = qc.text.decode("utf-8")
            if last_id:
                return last_id
    return None


def find_cpp_function_body(func_name, content):
    """Find a C++ function definition body in content using tree-sitter.

    Returns the body text (between { and }) if a definition is found,
    None if only declarations/calls are found.
    """
    tree = CPP_PARSER.parse(_strip_cuda_attrs(content.encode("utf-8")))
    for node in find_all_nodes(tree.root_node, {"function_definition"}):
        declarator = node.child_by_field_name("declarator")
        if declarator is None:
            continue
        name = _func_decl_name(declarator)
        if name == func_name:
            body = node.child_by_field_name("body")
            if body:
                return body.text.decode("utf-8")
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


# ---------------------------------------------------------------------------
# Check 7: transitive walk from scratch entry points to host synchronizations
#
# The graph is built from tree-sitter-cpp ASTs.  CUDA function attributes
# (__device__, __host__, etc.) are stripped before parsing so tree-sitter
# sees clean C++.  Calls inside macro arguments (e.g. DISPATCH_POLY_SIZE)
# are recovered from ERROR nodes where tree-sitter parses the inner call
# as a function_declarator.
# ---------------------------------------------------------------------------

# Calls that block the host.  The last three are the synchronous wrappers in
# device.cu around cudaMemcpy, cudaMalloc and cudaFree; their _async and
# _with_size_tracking_async variants are not in this set.  "synchronize" is
# the CudaStreams member function, spelled ".synchronize()" at the call site,
# which is also what check 4 matches.
HOST_SYNC_CALLS = {
    "cuda_synchronize_stream",
    "cuda_synchronize_device",
    "synchronize",
    "cudaStreamSynchronize",
    "cudaDeviceSynchronize",
    "cudaEventSynchronize",
    "cudaMemcpy",
    "cudaMemcpyPeer",
    "cudaMemset",
    "cudaMalloc",
    "cudaFree",
    "cuda_malloc",
    "cuda_drop",
    "cuda_memcpy_gpu_to_gpu",
}

# The walk stops here on purpose.  Both wrappers use cudaMallocAsync /
# cudaFreeAsync and fall back to the blocking cudaMalloc / cudaFree only on a
# device that reports no memory-pool support.  Every scratch function
# allocates, so descending into the fallback would report every scratch
# function on such a device.  This check tests what the code asks for, not
# what a device without memory pools does with it.
# cuda_setup_mempool is the only accepted synchronization on a scratch path.
# It grows the memory pool once per process and synchronizes to make sure the
# pool is grown, at device.cu:111, which the source marks as a deliberate
# exception to the release-ordering rule.  Every cuda_set_device call reaches
# it.  The walk does not stop at cuda_set_device itself, so any other
# synchronization added there is still reported.
SYNC_WALK_STOP_CALLS = {
    "cuda_malloc_with_size_tracking_async",
    "cuda_drop_with_size_tracking_async",
    "cuda_setup_mempool",
}

# Keywords, casts, assertion and profiling macros that the text scanner would
# otherwise read as function calls.
CPP_NON_CALL_WORDS = frozenset(
    "if for while switch return sizeof catch else new delete do try throw "
    "static_cast reinterpret_cast const_cast dynamic_cast decltype alignof "
    "defined namespace template typename operator constexpr assert "
    "static_assert GPU_ASSERT PANIC PANIC_IF_FALSE check_cuda_error "
    "PUSH_RANGE POP_RANGE".split()
)

CPP_NON_TYPE_WORDS = frozenset(
    "return const struct class using template typename else auto".split()
)

CPP_ACCESS_SPECIFIERS = frozenset(
    "public private protected virtual typename".split()
)

def _enclosing_struct(node):
    """Return the name of the nearest enclosing struct/class, or None."""
    cur = node.parent
    while cur:
        if cur.type in ("struct_specifier", "class_specifier"):
            for child in cur.children:
                if child.type == "type_identifier":
                    return child.text.decode("utf-8")
                if child.type == "template_type":
                    for tc in child.children:
                        if tc.type == "type_identifier":
                            return tc.text.decode("utf-8")
        cur = cur.parent
    return None


def index_cpp_definitions_ts(cpp_files):
    """Index every function, method and constructor body in cpp_files.

    Returns (definitions, aliases, bases, fields, trees).  Each definition
    records its name, enclosing struct, file, header line and the AST nodes
    that carry its calls.  The trees dict keeps tree-sitter trees alive so
    that AST node references remain valid.
    """
    definitions = []
    aliases, bases, fields = {}, defaultdict(set), defaultdict(dict)
    trees = {}

    for path in cpp_files:
        with open(path, errors="replace") as f:
            source_bytes = _strip_cuda_attrs(f.read().encode("utf-8"))
        tree = CPP_PARSER.parse(source_bytes)
        trees[path] = tree
        root = tree.root_node

        for node in find_all_nodes(root, {"alias_declaration"}):
            name_node, target_node = None, None
            for child in node.children:
                if child.type == "type_identifier" and name_node is None:
                    name_node = child
                elif child.type == "type_descriptor":
                    for tc in child.children:
                        if tc.type == "type_identifier":
                            target_node = tc
                            break
            if name_node and target_node:
                aliases.setdefault(
                    name_node.text.decode("utf-8"),
                    target_node.text.decode("utf-8"),
                )

        for node in find_all_nodes(
            root, {"struct_specifier", "class_specifier"}
        ):
            name_node = None
            for child in node.children:
                if child.type == "type_identifier":
                    name_node = child
                    break
                if child.type == "template_type":
                    for tc in child.children:
                        if tc.type == "type_identifier":
                            name_node = tc
                            break
                    break
            if name_node is None:
                continue
            struct_name = name_node.text.decode("utf-8")
            for child in node.children:
                if child.type == "base_class_clause":
                    for bc in child.children:
                        if bc.type == "type_identifier":
                            bases[struct_name].add(
                                bc.text.decode("utf-8")
                            )
            body = node.child_by_field_name("body")
            if body is None:
                continue
            for fdecl in body.children:
                if fdecl.type != "field_declaration":
                    continue
                type_name = None
                for child in fdecl.children:
                    if child.type in (
                        "type_identifier", "primitive_type",
                        "template_type", "sized_type_specifier",
                    ):
                        type_name = child.text.decode("utf-8")
                        break
                if type_name is None or type_name in CPP_NON_TYPE_WORDS:
                    continue
                for child in fdecl.children:
                    if child.type == "pointer_declarator":
                        for pc in child.children:
                            if pc.type == "field_identifier":
                                fields[struct_name].setdefault(
                                    pc.text.decode("utf-8"), type_name,
                                )

        bodies_seen = set()
        for node in find_all_nodes(root, {"function_definition"}):
            declarator = node.child_by_field_name("declarator")
            if declarator is None:
                continue
            name = _func_decl_name(declarator)
            if name is None or name in CPP_NON_CALL_WORDS:
                continue
            body = node.child_by_field_name("body")
            if body is None:
                continue
            if body.start_byte in bodies_seen:
                continue
            bodies_seen.add(body.start_byte)
            nodes = [body]
            for child in node.children:
                if child.type == "field_initializer_list":
                    nodes.append(child)
                    break
            definitions.append({
                "name": name,
                "struct": _enclosing_struct(node),
                "file": path,
                "line": node.start_point[0] + 1,
                "nodes": nodes,
            })

    return definitions, aliases, dict(bases), dict(fields), trees


def _extract_call_info(func):
    """Extract (receiver, operator, name, line) from the function child of a call_expression."""
    if func.type == "identifier":
        name = func.text.decode("utf-8")
        if name in CPP_NON_CALL_WORDS:
            return None
        return (None, None, name, func.start_point[0] + 1)

    if func.type == "template_function":
        for child in func.children:
            if child.type in ("identifier", "field_identifier"):
                name = child.text.decode("utf-8")
                if name in CPP_NON_CALL_WORDS:
                    return None
                return (None, None, name, child.start_point[0] + 1)
            if child.type == "field_expression":
                return _extract_field_call(child)
        return None

    if func.type == "field_expression":
        return _extract_field_call(func)

    if func.type == "qualified_identifier":
        last_id = None
        for child in func.children:
            if child.type in ("identifier", "field_identifier"):
                last_id = child
        if last_id:
            name = last_id.text.decode("utf-8")
            if name in CPP_NON_CALL_WORDS:
                return None
            return (None, None, name, last_id.start_point[0] + 1)

    return None


def _extract_field_call(field_expr):
    """Extract (receiver, operator, name, line) from a field_expression in a call."""
    arg_node = field_expr.child_by_field_name("argument")
    field_node = field_expr.child_by_field_name("field")
    operator = None
    for child in field_expr.children:
        if child.type in (".", "->"):
            operator = child.type
            break
    if field_node is None:
        return None
    name = field_node.text.decode("utf-8")
    if name in CPP_NON_CALL_WORDS:
        return None
    receiver = None
    if arg_node:
        if arg_node.type == "identifier":
            receiver = arg_node.text.decode("utf-8")
        elif arg_node.type == "this":
            receiver = "this"
        elif arg_node.type == "subscript_expression":
            for child in arg_node.children:
                if child.type == "identifier":
                    receiver = child.text.decode("utf-8")
                    break
        elif arg_node.type == "field_expression":
            field = arg_node.child_by_field_name("field")
            if field:
                receiver = field.text.decode("utf-8")
    return (receiver, operator, name, field_node.start_point[0] + 1)


class ScratchSyncWalker:
    """Reachability from a C++ definition to a host synchronization call."""

    def __init__(self, definitions, aliases, bases, fields, trees):
        self.definitions = definitions
        self.aliases = aliases
        self.bases = bases
        self.fields = fields
        self.trees = trees
        self.by_name = defaultdict(list)
        for key, d in enumerate(definitions):
            self.by_name[d["name"]].append(key)
        self._edge_cache = {}

    def resolve_alias(self, name):
        """Follow "using A = B" chains.  int_radix_lut is such an alias."""
        seen = set()
        while name in self.aliases and name not in seen:
            seen.add(name)
            name = self.aliases[name]
        return name

    def _base_chain(self, struct):
        chain, pending = set(), [struct]
        while pending:
            for base in sorted(self.bases.get(pending.pop(), ())):
                resolved = self.resolve_alias(base)
                if resolved not in chain:
                    chain.add(resolved)
                    pending.append(resolved)
        return sorted(chain)

    def _methods_of(self, struct, name):
        if not struct:
            return []
        for candidate in [struct] + self._base_chain(struct):
            hits = [
                key for key in self.by_name.get(name, ())
                if self.definitions[key]["struct"] == candidate
            ]
            if hits:
                return hits
        return []

    def _constructors_of(self, name):
        """A callee name that is also a type name means "its constructors"."""
        resolved = self.resolve_alias(name)
        return [
            key for key in self.by_name.get(resolved, ())
            if self.definitions[key]["struct"] == resolved
        ]

    def _any_definition_of(self, name):
        resolved = self.resolve_alias(name)
        return self.by_name.get(resolved) or self.by_name.get(name) or []

    def _call_sites(self, d):
        """Return (call sites, receiver types) of one definition.

        A call site is (receiver, operator, name, line).  The operator is
        None for an unqualified call.  The receiver is None when the call
        is made on an expression that is not a plain identifier.
        """
        calls, receiver_types = [], {}
        for node in d["nodes"]:
            for call_node in find_all_nodes(node, {"call_expression"}):
                func = call_node.child_by_field_name("function")
                if func is None:
                    continue
                info = _extract_call_info(func)
                if info:
                    calls.append(info)

            for init_node in find_all_nodes(node, {"field_initializer"}):
                for child in init_node.children:
                    if child.type == "field_identifier":
                        name = child.text.decode("utf-8")
                        if name not in CPP_NON_CALL_WORDS:
                            calls.append(
                                (None, None, name,
                                 child.start_point[0] + 1)
                            )
                        break

            for error_node in find_all_nodes(node, {"ERROR"}):
                for func_decl in find_all_nodes(
                    error_node, {"function_declarator"}
                ):
                    name = _func_decl_name(func_decl)
                    if name and name not in CPP_NON_CALL_WORDS:
                        calls.append(
                            (None, None, name,
                             func_decl.start_point[0] + 1)
                        )

            for decl_node in find_all_nodes(node, {"declaration"}):
                type_name = None
                for child in decl_node.children:
                    if child.type in ("type_identifier", "template_type"):
                        type_name = child.text.decode("utf-8")
                        break
                if type_name is None or type_name in CPP_NON_TYPE_WORDS:
                    continue
                for child in decl_node.children:
                    if child.type == "init_declarator":
                        for ic in child.children:
                            if ic.type == "pointer_declarator":
                                for pc in ic.children:
                                    if pc.type == "identifier":
                                        receiver_types.setdefault(
                                            pc.text.decode("utf-8"),
                                            type_name,
                                        )

            for new_node in find_all_nodes(node, {"new_expression"}):
                type_node = None
                for child in new_node.children:
                    if child.type == "type_identifier":
                        type_node = child
                        break
                if type_node is None:
                    continue
                type_name = type_node.text.decode("utf-8")
                parent = new_node.parent
                if parent is None:
                    continue
                if parent.type == "init_declarator":
                    for child in parent.children:
                        if child.type == "identifier":
                            receiver_types.setdefault(
                                child.text.decode("utf-8"), type_name,
                            )
                            break
                        if child.type == "pointer_declarator":
                            for pc in child.children:
                                if pc.type == "identifier":
                                    receiver_types.setdefault(
                                        pc.text.decode("utf-8"),
                                        type_name,
                                    )
                            break
                elif parent.type == "assignment_expression":
                    left = parent.child_by_field_name("left")
                    if left and left.type == "identifier":
                        receiver_types.setdefault(
                            left.text.decode("utf-8"), type_name,
                        )

        return calls, receiver_types

    def _edges(self, key):
        """Return (sync sites, callee keys) for one definition."""
        cached = self._edge_cache.get(key)
        if cached is not None:
            return cached

        d = self.definitions[key]
        calls, receiver_types = self._call_sites(d)
        sync_sites, callees = [], []

        def record(name, line):
            if name in HOST_SYNC_CALLS:
                sync_sites.append((name, d["file"], line))
                return True
            return name in SYNC_WALK_STOP_CALLS

        for receiver, operator, name, line in calls:
            if record(name, line):
                continue
            if operator is None:
                callees.extend(
                    self._constructors_of(name)
                    or self._methods_of(d["struct"], name)
                    or self._any_definition_of(name)
                )
                continue
            # 105 definitions are named release, so the receiver's static
            # type decides which one runs.
            if receiver == "this":
                receiver_type = d["struct"]
            elif receiver is None:
                receiver_type = None
            else:
                own_fields = self.fields.get(d["struct"], {})
                receiver_type = (
                    receiver_types.get(receiver) or own_fields.get(receiver)
                )
            hits = []
            if receiver_type:
                hits = self._methods_of(
                    self.resolve_alias(receiver_type), name
                )
            callees.extend(
                hits
                or self._methods_of(d["struct"], name)
                or self._any_definition_of(name)
            )

        sync_sites.sort(key=lambda site: (site[1], site[2], site[0]))
        ordered = list(dict.fromkeys(callees))
        self._edge_cache[key] = (sync_sites, ordered)
        return self._edge_cache[key]

    def label(self, key):
        d = self.definitions[key]
        if d["struct"] is None:
            return d["name"]
        if d["struct"] == d["name"]:
            return f"{d['struct']}::ctor"
        return f"{d['struct']}::{d['name']}"

    def reachable_sync_chains(self, start_key):
        """Breadth-first search for every reachable host synchronization.

        Returns a dict mapping (sync call name, file, line) to the shortest
        chain of labels that reaches it.  Breadth-first order means the first
        chain recorded for a site is the shortest one.
        """
        chains = {}
        seen = {start_key}
        queue = deque([(start_key, [self.label(start_key)])])
        while queue:
            key, chain = queue.popleft()
            sync_sites, callees = self._edges(key)
            for site in sync_sites:
                chains.setdefault(site, chain)
            for callee in callees:
                if callee in seen:
                    continue
                seen.add(callee)
                queue.append((callee, chain + [self.label(callee)]))
        return chains


def check_7_scratch_reaches_no_sync(scratch_set):
    """Check 7: no scratch entry point may reach a host synchronization.

    A scratch function only allocates and prepares device buffers, so it
    must stay asynchronous.  Check 4 looks at one function body; this walks
    every call, constructor, member-initializer list and method call below
    each scratch_cuda_* symbol declared in bindings.rs, and reports the
    nearest synchronization of every entry point that can reach one.

    The guarantee depends on two conventions of this backend.  A destructor
    here only asserts that release() was already called, so an implicit
    destructor call is not traced.  Operator overloads and functor calls
    through operator() are not traced either.
    """
    definitions, aliases, bases, fields, trees = index_cpp_definitions_ts(
        collect_cpp_files(SYNC_WALK_CPP_DIRS)
    )
    walker = ScratchSyncWalker(
        definitions, aliases, bases, fields, trees
    )

    entry_points = defaultdict(list)
    for key, d in enumerate(definitions):
        if d["struct"] is None and d["name"] in scratch_set:
            entry_points[d["name"]].append(key)

    violations = [
        f"  {name}: C++ definition not found in "
        f"{', '.join(SYNC_WALK_CPP_DIRS)}"
        for name in sorted(scratch_set - set(entry_points))
    ]

    # Several scratch names have more than one definition: an internal
    # template helper and the extern "C" entry point that calls it share the
    # name scratch_cuda_multi_bit_programmable_bootstrap_128_async.  A name
    # is clean only when none of its definitions reaches a synchronization.
    nearest = {}
    entry_points_per_site = defaultdict(set)
    for name, keys in entry_points.items():
        reachable = {}
        for key in keys:
            for site, chain in walker.reachable_sync_chains(key).items():
                previous = reachable.get(site)
                if previous is None or len(chain) < len(previous):
                    reachable[site] = chain
        for site in reachable:
            entry_points_per_site[site].add(name)
        if reachable:
            site = min(
                reachable, key=lambda s: (len(reachable[s]), s[1], s[2], s[0])
            )
            nearest[name] = (reachable[site],) + site

    sync_sites = sorted(
        (
            (len(names), site[0], site[1], site[2])
            for site, names in entry_points_per_site.items()
        ),
        key=lambda item: (-item[0], item[2], item[3]),
    )

    if len(nearest) > ALLOWED_CHECK7_SYNC_VIOLATIONS:
        grouped = defaultdict(list)
        for name, (chain, sync_name, path, line) in nearest.items():
            grouped[(tuple(chain[1:]), sync_name, path, line)].append(name)

        for (tail, sync_name, path, line), names in sorted(
            grouped.items(), key=lambda item: (-len(item[1]), item[0])
        ):
            names.sort()
            chain = " > ".join([names[0]] + list(tail))
            message = f"  {chain}  [{sync_name} at {path}:{line}]"
            if len(names) > 1:
                shared = ", ".join(names[1:])
                message += (
                    f"\n    same chain from {len(names) - 1} more entry "
                    f"point(s): {shared}"
                )
            violations.append(message)

    return (
        violations, len(entry_points), len(nearest), len(definitions),
        sync_sites,
    )


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

    # Check 7
    print(
        "\nCheck 7: scratch functions do not reach a host "
        "synchronization..."
    )
    v, n_entry7, n_reaching7, n_defs7, sync_sites = (
        check_7_scratch_reaches_no_sync(scratch_set)
    )
    all_violations.extend(v)
    print(
        f"  Walked {n_entry7} scratch entry points over "
        f"{n_defs7} C++ definitions"
    )
    if n_reaching7:
        print(
            f"  {n_reaching7} of {n_entry7} reach a host synchronization"
        )
        # Only the nearest synchronization is reported as a chain per entry
        # point, so list every reachable site: removing one uncovers the next.
        print(f"  {len(sync_sites)} synchronization site(s) to remove:")
        for count, sync_name, path, line in sync_sites:
            print(f"    {count:3d} entry point(s)  {sync_name}  {path}:{line}")
    print(f"  {'PASS' if not v else f'{len(v)} violation(s)'}")

    # Validate Check 7 entry-point count
    if n_entry7 != EXPECTED_CHECK7_SCRATCH_ENTRY_POINTS:
        all_violations.append(
            f"\n  *** SCRATCH ENTRY POINT COUNT CHANGED ***\n"
            f"  Expected {EXPECTED_CHECK7_SCRATCH_ENTRY_POINTS} scratch "
            f"entry points with a C++ definition, walked {n_entry7}.\n"
            f"  Either a scratch binding was added or removed, or a C++\n"
            f"  definition moved out of "
            f"{', '.join(SYNC_WALK_CPP_DIRS)}.\n"
            f"  If this is not a mistake, update "
            f"EXPECTED_CHECK7_SCRATCH_ENTRY_POINTS to {n_entry7}\n"
            f"  in {os.path.basename(__file__)}."
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
