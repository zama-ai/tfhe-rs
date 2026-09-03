"""Transitive reachability check: scratch entry points to host synchronizations.

Provides two public entry points:

  find_cpp_function_body(func_name, content)
      Tree-sitter-cpp based lookup of a C++ function body by name.
      Used by Check 4 in check_scratch_cleanup.py.

  check_7_scratch_reaches_no_sync(scratch_set, sync_whitelist)
      Walks the call graph from every scratch_cuda_* symbol in bindings.rs
      and reports any path that reaches a host synchronization, unless the
      entry point is named in sync_whitelist (CHECK7_SYNC_WHITELIST in
      check_scratch_cleanup.py).  A whitelisted name that does not reach a
      synchronization is reported too, so the whitelist cannot go stale.

To disable Check 7 without touching checks 1-6, remove its call from
check_scratch_cleanup.py.  If the tree-sitter-cpp dependency becomes
unmaintainable, revert find_cpp_function_body to the text-based version
in check_scratch_cleanup.py and delete this file.
"""

import os
import re
from collections import defaultdict, deque

import tree_sitter as ts
import tree_sitter_cpp as tscpp

# ---------------------------------------------------------------------------
# Tree-sitter C++ setup
# ---------------------------------------------------------------------------

CPP_LANG = ts.Language(tscpp.language())
CPP_PARSER = ts.Parser(CPP_LANG)

CPP_EXTENSIONS = {".cu", ".cuh", ".h", ".cpp"}

# Check 7 walks the shared CUDA runtime wrappers in addition to the backend
# directories.  Scratch paths call cuda_memcpy_with_size_tracking_async_to_gpu
# and friends there, each of which calls cuda_set_device.
SYNC_WALK_CPP_DIRS = [
    "backends/tfhe-cuda-backend/cuda/src",
    "backends/tfhe-cuda-backend/cuda/include",
    "backends/tfhe-cuda-common/cuda/src",
    "backends/tfhe-cuda-common/cuda/include",
]

# ---------------------------------------------------------------------------
# CUDA attribute stripping
#
# tree-sitter-cpp does not understand __device__, __host__, etc.  Replacing
# them with whitespace (same length to preserve byte offsets) lets it parse
# the file as standard C++.
# ---------------------------------------------------------------------------

_CUDA_ATTR_RE = re.compile(
    r"\b(?:__device__|__host__|__global__|__forceinline__|__noinline__)\b"
    r"|__launch_bounds__\s*\([^)]*\)"
)


def _strip_cuda_attrs(source_bytes):
    """Replace CUDA function attributes with equal-length spaces."""
    text = source_bytes.decode("utf-8", errors="replace")
    text = _CUDA_ATTR_RE.sub(lambda m: " " * len(m.group(0)), text)
    return text.encode("utf-8")


# ---------------------------------------------------------------------------
# Generic AST helpers
# ---------------------------------------------------------------------------

def find_all_nodes(root, node_types):
    """Yield every descendant whose type is in node_types (including ERROR children)."""
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in node_types:
            yield node
        stack.extend(reversed(node.children))


def _func_decl_name(declarator):
    """Extract the plain function name from a function_declarator AST node.

    Unwraps pointer/reference declarators, template wrappers, qualified
    identifiers and destructor names.
    """
    while declarator.type in ("pointer_declarator", "reference_declarator"):
        inner = next(
            (c for c in declarator.children
             if c.type in ("function_declarator", "pointer_declarator",
                           "reference_declarator")),
            None,
        )
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


# ---------------------------------------------------------------------------
# Public: find_cpp_function_body  (used by Check 4)
# ---------------------------------------------------------------------------

def find_cpp_function_body(func_name, content):
    """Find a C++ function definition body using tree-sitter.

    Returns the body text (between { and }) if found, None otherwise.
    """
    tree = CPP_PARSER.parse(_strip_cuda_attrs(content.encode("utf-8")))
    for node in find_all_nodes(tree.root_node, {"function_definition"}):
        declarator = node.child_by_field_name("declarator")
        if declarator is None:
            continue
        if _func_decl_name(declarator) == func_name:
            body = node.child_by_field_name("body")
            if body:
                return body.text.decode("utf-8")
    return None


# ---------------------------------------------------------------------------
# Check 7 constants
# ---------------------------------------------------------------------------

# Check 7 walks the call graph downwards from each scratch_cuda_* entry point
# and compares every call it meets against two sets of function names:
#
#   SYNC_SITE_NAMES: what a host synchronization looks like.  Meeting one
#     ends the walk and reports the chain that led to it.  The set is fixed,
#     it describes the CUDA runtime.
#
#   SYNC_WALK_STOP_CALLS: runtime helpers the walker does not enter, because
#     what they do is not the caller's decision (see each entry).  A
#     SYNC_SITE_NAMES call inside them is therefore never seen.
#
# Any call in neither set is entered and walked further.
#
# Accepted exceptions are never expressed as skipped subfunctions: skipping
# a subfunction would hide its synchronization and let every caller above
# it pass as asynchronous.  Instead, CHECK7_SYNC_WHITELIST in
# check_scratch_cleanup.py names the top-level scratch entry points that are
# known to synchronize.  Their chains are still walked, but not counted as
# violations.

# Calls that block the host thread until the device catches up: the explicit
# stream/device/event synchronizations, the CUDA runtime calls that are
# implicitly synchronous (cudaMemcpy, cudaMemset, cudaMalloc, cudaFree and the
# peer copy), and the backend wrappers around those runtime calls.
SYNC_SITE_NAMES = frozenset({
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
})

# cuda_setup_mempool synchronizes once per process to grow the memory pool
# (the source marks it as a deliberate exception).  Every cuda_set_device
# reaches it.
# cuda_malloc_with_size_tracking_async and cuda_drop_with_size_tracking_async
# use cudaMallocAsync/cudaFreeAsync and fall back to the blocking variants
# only on devices without memory-pool support.  This check tests what the
# code asks for, not what a fallback device does.
SYNC_WALK_STOP_CALLS = frozenset({
    "cuda_setup_mempool",
    "cuda_malloc_with_size_tracking_async",
    "cuda_drop_with_size_tracking_async",
})

# Tokens that look like function calls but are not.
_NON_CALL_WORDS = frozenset(
    "if for while switch return sizeof catch else new delete do try throw "
    "static_cast reinterpret_cast const_cast dynamic_cast decltype alignof "
    "defined namespace template typename operator constexpr assert "
    "static_assert GPU_ASSERT PANIC PANIC_IF_FALSE check_cuda_error "
    "PUSH_RANGE POP_RANGE".split()
)

_NON_TYPE_WORDS = frozenset(
    "return const struct class using template typename else auto".split()
)


# ---------------------------------------------------------------------------
# C++ call-graph indexing
# ---------------------------------------------------------------------------

def _collect_cpp_files(dirs):
    """Collect all C++ source files from the given directories."""
    files = []
    for d in dirs:
        for root, _, filenames in os.walk(d):
            for f in filenames:
                if os.path.splitext(f)[1] in CPP_EXTENSIONS:
                    files.append(os.path.join(root, f))
    return sorted(files)


def _index_definitions(cpp_files):
    """Parse every function/method/constructor in cpp_files.

    Returns:
        definitions: list of dicts with keys name, struct, file, line, nodes
        aliases:     dict mapping type alias names to their targets
        bases:       dict mapping struct name to its base class names
        fields:      dict mapping struct name to {field_name: type_name}
        trees:       dict keeping tree-sitter trees alive for AST references
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

        _collect_aliases(root, aliases)
        _collect_struct_info(root, bases, fields)
        _collect_function_defs(root, path, definitions)

    return definitions, aliases, dict(bases), dict(fields), trees


def _collect_aliases(root, aliases):
    """Collect 'using A = B' type aliases."""
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


def _collect_struct_info(root, bases, fields):
    """Collect base classes and pointer field types for structs/classes."""
    for node in find_all_nodes(root, {"struct_specifier", "class_specifier"}):
        struct_name = _struct_name(node)
        if struct_name is None:
            continue

        for child in node.children:
            if child.type == "base_class_clause":
                for bc in child.children:
                    if bc.type == "type_identifier":
                        bases[struct_name].add(bc.text.decode("utf-8"))

        body = node.child_by_field_name("body")
        if body is None:
            continue
        for fdecl in body.children:
            if fdecl.type != "field_declaration":
                continue
            type_name = _field_type_name(fdecl)
            if type_name is None:
                continue
            for child in fdecl.children:
                if child.type == "pointer_declarator":
                    for pc in child.children:
                        if pc.type == "field_identifier":
                            fields[struct_name].setdefault(
                                pc.text.decode("utf-8"), type_name,
                            )


def _struct_name(node):
    """Extract the struct/class name from a specifier node."""
    for child in node.children:
        if child.type == "type_identifier":
            return child.text.decode("utf-8")
        if child.type == "template_type":
            for tc in child.children:
                if tc.type == "type_identifier":
                    return tc.text.decode("utf-8")
    return None


def _field_type_name(field_decl):
    """Extract the type name from a field_declaration, or None."""
    for child in field_decl.children:
        if child.type in ("type_identifier", "primitive_type",
                          "template_type", "sized_type_specifier"):
            name = child.text.decode("utf-8")
            return None if name in _NON_TYPE_WORDS else name
    return None


def _collect_function_defs(root, path, definitions):
    """Collect function/method/constructor definitions from root."""
    bodies_seen = set()
    for node in find_all_nodes(root, {"function_definition"}):
        declarator = node.child_by_field_name("declarator")
        if declarator is None:
            continue
        name = _func_decl_name(declarator)
        if name is None or name in _NON_CALL_WORDS:
            continue
        body = node.child_by_field_name("body")
        if body is None or body.start_byte in bodies_seen:
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


# ---------------------------------------------------------------------------
# Call-site extraction from AST nodes
# ---------------------------------------------------------------------------

def _extract_call_info(func_node):
    """Extract (receiver, operator, callee_name, line) from a call_expression's function child.

    Returns None for non-call tokens (keywords, casts, macros).
    """
    if func_node.type == "identifier":
        name = func_node.text.decode("utf-8")
        if name in _NON_CALL_WORDS:
            return None
        return (None, None, name, func_node.start_point[0] + 1)

    if func_node.type == "template_function":
        for child in func_node.children:
            if child.type in ("identifier", "field_identifier"):
                name = child.text.decode("utf-8")
                if name in _NON_CALL_WORDS:
                    return None
                return (None, None, name, child.start_point[0] + 1)
            if child.type == "field_expression":
                return _extract_field_call(child)
        return None

    if func_node.type == "field_expression":
        return _extract_field_call(func_node)

    if func_node.type == "qualified_identifier":
        last_id = None
        for child in func_node.children:
            if child.type in ("identifier", "field_identifier"):
                last_id = child
        if last_id:
            name = last_id.text.decode("utf-8")
            if name in _NON_CALL_WORDS:
                return None
            return (None, None, name, last_id.start_point[0] + 1)

    return None


def _extract_field_call(field_expr):
    """Extract (receiver, operator, callee_name, line) from a field_expression in a call."""
    arg_node = field_expr.child_by_field_name("argument")
    field_node = field_expr.child_by_field_name("field")
    if field_node is None:
        return None

    name = field_node.text.decode("utf-8")
    if name in _NON_CALL_WORDS:
        return None

    operator = None
    for child in field_expr.children:
        if child.type in (".", "->"):
            operator = child.type
            break

    receiver = _receiver_name(arg_node)
    return (receiver, operator, name, field_node.start_point[0] + 1)


def _receiver_name(arg_node):
    """Best-effort extraction of the receiver variable name."""
    if arg_node is None:
        return None
    if arg_node.type == "identifier":
        return arg_node.text.decode("utf-8")
    if arg_node.type == "this":
        return "this"
    if arg_node.type == "subscript_expression":
        for child in arg_node.children:
            if child.type == "identifier":
                return child.text.decode("utf-8")
    if arg_node.type == "field_expression":
        field = arg_node.child_by_field_name("field")
        if field:
            return field.text.decode("utf-8")
    return None


# ---------------------------------------------------------------------------
# ScratchSyncWalker: breadth-first reachability from a definition to a sync
# ---------------------------------------------------------------------------

class ScratchSyncWalker:
    """Walks the call graph from a C++ definition looking for host syncs."""

    def __init__(self, definitions, aliases, bases, fields):
        self.definitions = definitions
        self.aliases = aliases
        self.bases = bases
        self.fields = fields

        self.by_name = defaultdict(list)
        for key, d in enumerate(definitions):
            self.by_name[d["name"]].append(key)

        self._edge_cache = {}

    # -- Alias and inheritance resolution --

    def _resolve_alias(self, name):
        seen = set()
        while name in self.aliases and name not in seen:
            seen.add(name)
            name = self.aliases[name]
        return name

    def _base_chain(self, struct):
        chain, pending = set(), [struct]
        while pending:
            for base in sorted(self.bases.get(pending.pop(), ())):
                resolved = self._resolve_alias(base)
                if resolved not in chain:
                    chain.add(resolved)
                    pending.append(resolved)
        return sorted(chain)

    # -- Definition lookup by name --

    def _methods_of(self, struct, name):
        if not struct:
            return []
        for candidate in [struct] + self._base_chain(struct):
            hits = [k for k in self.by_name.get(name, ())
                    if self.definitions[k]["struct"] == candidate]
            if hits:
                return hits
        return []

    def _constructors_of(self, name):
        resolved = self._resolve_alias(name)
        return [k for k in self.by_name.get(resolved, ())
                if self.definitions[k]["struct"] == resolved]

    def _any_definition_of(self, name):
        resolved = self._resolve_alias(name)
        return self.by_name.get(resolved) or self.by_name.get(name) or []

    # -- Edge computation (one definition → sync sites + callee keys) --

    def _edges(self, key):
        cached = self._edge_cache.get(key)
        if cached is not None:
            return cached

        d = self.definitions[key]
        calls, receiver_types = self._call_sites_of(d)
        sync_sites, callees = [], []

        for receiver, operator, name, line in calls:
            if name in SYNC_SITE_NAMES:
                sync_sites.append((name, d["file"], line))
                continue
            if name in SYNC_WALK_STOP_CALLS:
                continue

            if operator is None:
                # Unqualified call: try constructor, then same-struct method,
                # then any definition.
                callees.extend(
                    self._constructors_of(name)
                    or self._methods_of(d["struct"], name)
                    or self._any_definition_of(name)
                )
            else:
                # Member call (. or ->): resolve the receiver type to pick
                # the right overload (e.g. 105 definitions named "release").
                receiver_type = self._resolve_receiver_type(
                    d, receiver, receiver_types)
                hits = (self._methods_of(
                            self._resolve_alias(receiver_type), name)
                        if receiver_type else [])
                callees.extend(
                    hits
                    or self._methods_of(d["struct"], name)
                    or self._any_definition_of(name)
                )

        sync_sites.sort(key=lambda s: (s[1], s[2], s[0]))
        result = (sync_sites, list(dict.fromkeys(callees)))
        self._edge_cache[key] = result
        return result

    def _resolve_receiver_type(self, d, receiver, receiver_types):
        if receiver == "this":
            return d["struct"]
        if receiver is None:
            return None
        own_fields = self.fields.get(d["struct"], {})
        return receiver_types.get(receiver) or own_fields.get(receiver)

    def _call_sites_of(self, d):
        """Extract all call sites and local variable types from a definition."""
        calls, receiver_types = [], {}

        for node in d["nodes"]:
            # Regular function calls
            for call_node in find_all_nodes(node, {"call_expression"}):
                func = call_node.child_by_field_name("function")
                if func is None:
                    continue
                info = _extract_call_info(func)
                if info:
                    calls.append(info)

            # Member-initializer list entries (constructor: field(args))
            for init_node in find_all_nodes(node, {"field_initializer"}):
                for child in init_node.children:
                    if child.type == "field_identifier":
                        name = child.text.decode("utf-8")
                        if name not in _NON_CALL_WORDS:
                            calls.append((None, None, name,
                                          child.start_point[0] + 1))
                        break

            # Calls inside ERROR nodes (e.g. DISPATCH_POLY_SIZE macro args)
            for error_node in find_all_nodes(node, {"ERROR"}):
                for func_decl in find_all_nodes(error_node,
                                                {"function_declarator"}):
                    name = _func_decl_name(func_decl)
                    if name and name not in _NON_CALL_WORDS:
                        calls.append((None, None, name,
                                      func_decl.start_point[0] + 1))

            # Track local variable types for receiver resolution
            # Constructor calls through `new T<...>(...)`.  Scratch functions
            # build their buffer this way, so without this edge the walk
            # never enters a buffer constructor.
            for new_node in find_all_nodes(node, {"new_expression"}):
                type_name = self._new_type_name(new_node)
                if type_name:
                    calls.append((None, None, type_name,
                                  new_node.start_point[0] + 1))

            self._collect_local_types(node, receiver_types)

        return calls, receiver_types

    @staticmethod
    def _new_type_name(new_node):
        """Return the constructed type's name from a new_expression node.

        Handles both `new T(...)` (type_identifier) and `new T<...>(...)`
        (template_type wrapping a type_identifier).
        """
        for child in new_node.children:
            if child.type == "type_identifier":
                return child.text.decode("utf-8")
            if child.type == "template_type":
                for tc in child.children:
                    if tc.type == "type_identifier":
                        return tc.text.decode("utf-8")
        return None

    def _collect_local_types(self, node, receiver_types):
        """Record variable_name → type_name for pointer declarations and new-expressions."""
        for decl_node in find_all_nodes(node, {"declaration"}):
            type_name = None
            for child in decl_node.children:
                if child.type in ("type_identifier", "template_type"):
                    type_name = child.text.decode("utf-8")
                    break
            if type_name is None or type_name in _NON_TYPE_WORDS:
                continue
            for child in decl_node.children:
                if child.type == "init_declarator":
                    for ic in child.children:
                        if ic.type == "pointer_declarator":
                            for pc in ic.children:
                                if pc.type == "identifier":
                                    receiver_types.setdefault(
                                        pc.text.decode("utf-8"), type_name)

        for new_node in find_all_nodes(node, {"new_expression"}):
            type_name = self._new_type_name(new_node)
            if type_name is None:
                continue
            parent = new_node.parent
            if parent is None:
                continue
            var_name = self._var_from_new(parent)
            if var_name:
                receiver_types.setdefault(var_name, type_name)

    @staticmethod
    def _var_from_new(parent):
        """Extract the variable name being assigned from a new-expression's parent."""
        if parent.type == "init_declarator":
            for child in parent.children:
                if child.type == "identifier":
                    return child.text.decode("utf-8")
                if child.type == "pointer_declarator":
                    for pc in child.children:
                        if pc.type == "identifier":
                            return pc.text.decode("utf-8")
        elif parent.type == "assignment_expression":
            left = parent.child_by_field_name("left")
            if left and left.type == "identifier":
                return left.text.decode("utf-8")
        return None

    # -- Public API --

    def label(self, key):
        d = self.definitions[key]
        if d["struct"] is None:
            return d["name"]
        if d["struct"] == d["name"]:
            return f"{d['struct']}::ctor"
        return f"{d['struct']}::{d['name']}"

    def reachable_sync_chains(self, start_key):
        """BFS for every reachable host synchronization.

        Returns a dict mapping (sync_call, file, line) to the shortest
        call chain that reaches it.
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
                if callee not in seen:
                    seen.add(callee)
                    queue.append((callee, chain + [self.label(callee)]))
        return chains


# ---------------------------------------------------------------------------
# Public: check_7_scratch_reaches_no_sync
# ---------------------------------------------------------------------------

def check_7_scratch_reaches_no_sync(scratch_set, sync_whitelist):
    """Check 7: no scratch entry point may reach a host synchronization.

    Args:
        scratch_set: set of scratch_cuda_* function names from bindings.rs
        sync_whitelist: scratch entry points known to reach a host
            synchronization; their chains are reported but not counted as
            violations

    Returns:
        (violations, n_entry_points, n_reaching, n_whitelisted,
         n_definitions, sync_sites)
    """
    definitions, aliases, bases, fields, trees = _index_definitions(
        _collect_cpp_files(SYNC_WALK_CPP_DIRS)
    )
    walker = ScratchSyncWalker(definitions, aliases, bases, fields)

    # Map each scratch name to its definition key(s).
    entry_points = defaultdict(list)
    for key, d in enumerate(definitions):
        if d["struct"] is None and d["name"] in scratch_set:
            entry_points[d["name"]].append(key)

    # Missing definitions are violations.
    violations = [
        f"  {name}: C++ definition not found in "
        f"{', '.join(SYNC_WALK_CPP_DIRS)}"
        for name in sorted(scratch_set - set(entry_points))
    ]

    # Walk each entry point.  A name with multiple definitions (template
    # helper + extern "C" wrapper) is clean only when none reaches a sync.
    nearest = {}
    entry_points_per_site = defaultdict(set)
    for name, keys in entry_points.items():
        reachable = {}
        for key in keys:
            for site, chain in walker.reachable_sync_chains(key).items():
                prev = reachable.get(site)
                if prev is None or len(chain) < len(prev):
                    reachable[site] = chain
        for site in reachable:
            entry_points_per_site[site].add(name)
        if reachable:
            site = min(reachable,
                       key=lambda s: (len(reachable[s]), s[1], s[2], s[0]))
            nearest[name] = (reachable[site],) + site

    sync_sites = sorted(
        ((len(names), site[0], site[1], site[2])
         for site, names in entry_points_per_site.items()),
        key=lambda item: (-item[0], item[2], item[3]),
    )

    if nearest:
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
            if not all(n in sync_whitelist for n in names):
                violations.append(message)

    # A whitelisted name that reaches nothing is stale, whether it was fixed
    # or never existed as an entry point.
    for name in sorted(sync_whitelist - set(nearest)):
        violations.append(
            f"  {name} is in CHECK7_SYNC_WHITELIST but does not reach a "
            f"host synchronization: remove it from the whitelist"
        )

    n_whitelisted = len(set(nearest) & sync_whitelist)
    return (violations, len(entry_points), len(nearest), n_whitelisted,
            len(definitions), sync_sites)
