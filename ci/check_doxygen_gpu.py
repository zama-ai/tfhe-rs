#!/usr/bin/env python3
"""
Verify that newly added code in GPU source files has doxygen documentation.

Each new struct, member, and function must have a comment block with @brief and
@param (or @tparam) covering every parameter.

Scoped to:
  backends/tfhe-cuda-backend/cuda/include/integer/   (*.h)
  backends/tfhe-cuda-backend/cuda/src/integer/       (*.cuh, *.cu)
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

SCOPED_DIRS = [
    "backends/tfhe-cuda-backend/cuda/include/integer",
    "backends/tfhe-cuda-backend/cuda/src/integer",
]
EXTENSIONS = {".h", ".cuh", ".cu"}

# Function parameters that don't require @param documentation.
# Each entry is a (type_substring, param_name) pair.
SKIP_PARAMS = {
    ("CudaStreams", "streams"),
    ("int_radix_params", "params"),
    ("bool", "allocate_gpu_memory"),
    ("uint64_t", "size_tracker"),
    ("void", "bsks"),
    ("", "ksks"),
    ("cudaStream_t", "stream"),
    ("void *", "stream"),
    ("uint32_t", "gpu_index"),
    ("uint32_t", "message_modulus"),
    ("uint32_t", "carry_modulus"),
    ("buffer", "mem_ptr"),
}

# Struct/class members that don't require inline documentation.
# Each entry is a (type_substring, member_name) pair.
SKIP_MEMBERS = {
    ("int_radix_params", "params"),
    ("bool", "gpu_memory_allocated"),
    ("bool", "allocate_gpu_memory"),
}

# Template parameters that don't require @tparam documentation.
SKIP_TPARAMS = {"Torus", "KSTorus", "T"}

# Functions which don't require documentation (exact names).
SKIP_FUNCTIONS = {"release"}

# Functions whose names start with any of these prefixes don't require docs.
SKIP_FUNCTION_PREFIXES = {"scratch_", "cleanup_"}

# Files excluded from doxygen checks (relative to repo root).
SKIP_FILES = {
    "backends/tfhe-cuda-backend/cuda/include/integer/integer.h",
}


def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, check=True, **kwargs)


def repo_root():
    return Path(run(["git", "rev-parse", "--show-toplevel"]).stdout.strip())


def changed_files(root):
    out = run(["git", "diff", "FETCH_HEAD", "--name-only"], cwd=root)
    return [root / p for p in out.stdout.strip().splitlines() if p]


def added_line_numbers(root, filepath):
    """Return the set of line numbers (1-based) that were added in filepath."""
    rel = filepath.relative_to(root)
    out = run(["git", "diff", "FETCH_HEAD", "--", str(rel)], cwd=root)
    added = set()
    current = 0
    for line in out.stdout.splitlines():
        m = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if m:
            current = int(m.group(1))
            continue
        if line.startswith("+++"):
            continue
        if line.startswith("+"):
            added.add(current)
            current += 1
        elif not line.startswith("-"):
            current += 1
    return added


def run_doxygen_xml(root, files):
    """Run doxygen with EXTRACT_ALL=YES and XML output. Returns the output directory."""
    output_dir = tempfile.mkdtemp()
    input_paths = " \\\n    ".join(str(f) for f in files)
    doxyfile = f"""\
PROJECT_NAME      = tfhe-cuda-backend
INPUT             = {input_paths}
RECURSIVE         = NO
EXTENSION_MAPPING = cu=C++ cuh=C++
PREDEFINED        = __host__= __device__= __global__= __shared__= __constant__= __forceinline__=
GENERATE_HTML     = NO
GENERATE_LATEX    = NO
GENERATE_XML      = YES
EXTRACT_ALL       = YES
QUIET             = YES
WARNINGS          = NO
OUTPUT_DIRECTORY  = {output_dir}
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False) as f:
        f.write(doxyfile)
        cfg = f.name
    try:
        subprocess.run(["doxygen", cfg], capture_output=True, text=True, cwd=root)
    finally:
        os.unlink(cfg)
    return output_dir


def is_empty(elem):
    return elem is None or not "".join(elem.itertext()).strip()


def skip_param(type_str, name):
    return any(t in type_str and name == n for t, n in SKIP_PARAMS)


def skip_member(type_str, name):
    return any(t in type_str and name == n for t, n in SKIP_MEMBERS)


def check_entity(name, kind, memberdef, param_elems):
    """Return list of documentation issues for a function/struct member."""
    issues = []

    if is_empty(memberdef.find("briefdescription")):
        issues.append("missing @brief")
        return issues  # no point checking params without a brief

    # Collect declared parameter names, excluding well-known boilerplate params
    declared = [
        p.findtext("declname", "").strip()
        for p in param_elems
        if p.findtext("declname", "").strip()
        and not skip_param("".join(p.itertext()).strip(), p.findtext("declname", "").strip())
    ]

    # Collect documented @param names
    documented_params = set()
    for paramlist in memberdef.iter("parameterlist"):
        if paramlist.get("kind") == "param":
            for item in paramlist.findall("parameteritem"):
                for nl in item.findall("parameternamelist"):
                    for pname in nl.findall("parametername"):
                        if pname.text:
                            documented_params.add(pname.text.strip())

    missing_params = [p for p in declared if p not in documented_params]
    if missing_params:
        issues.append(f"missing @param for: {', '.join(missing_params)}")

    # Check @tparam for template parameters, excluding skipped ones
    tpl = memberdef.find("templateparamlist")
    if tpl is not None:
        declared_tparams = []
        for tp in tpl.findall("param"):
            # type is e.g. "typename Torus" or "class KSTorus"
            tname = tp.findtext("type", "").replace("typename", "").replace("class", "").strip()
            if tname and tname not in SKIP_TPARAMS:
                declared_tparams.append(tname)

        documented_tparams = set()
        for paramlist in memberdef.iter("parameterlist"):
            if paramlist.get("kind") == "templateparam":
                for item in paramlist.findall("parameteritem"):
                    for nl in item.findall("parameternamelist"):
                        for pname in nl.findall("parametername"):
                            if pname.text:
                                documented_tparams.add(pname.text.strip())

        missing_tparams = [t for t in declared_tparams if t not in documented_tparams]
        if missing_tparams:
            issues.append(f"missing @tparam for: {', '.join(missing_tparams)}")

    return issues


def resolve(path_str, root):
    p = Path(path_str)
    return p if p.is_absolute() else (root / p).resolve()


def parse_xml_issues(xml_dir, added, root):
    failures = []

    for xml_path in sorted(Path(xml_dir).glob("xml/*.xml")):
        if xml_path.name == "index.xml":
            continue
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError:
            continue
        doc_root = tree.getroot()

        # Constructors and destructors ignored.
        compound_names = {
            c.findtext("compoundname", "").split("::")[-1]
            for c in doc_root.iter("compounddef")
        }

        # Structs and classes
        for compound in doc_root.iter("compounddef"):
            if compound.get("kind") not in ("struct", "class"):
                continue
            loc = compound.find("location")
            if loc is None:
                continue
            fpath = resolve(loc.get("file", ""), root)
            line = int(loc.get("line", 0))
            if fpath not in added or line not in added[fpath]:
                continue
            cname = compound.findtext("compoundname", "")
            if is_empty(compound.find("briefdescription")):
                failures.append((fpath, line, f"struct/class '{cname}': missing @brief"))
                continue
            tpl = compound.find("templateparamlist")
            if tpl is not None:
                declared_tparams = []
                for tp in tpl.findall("param"):
                    tname = tp.findtext("type", "").replace("typename", "").replace("class", "").strip()
                    if tname and tname not in SKIP_TPARAMS:
                        declared_tparams.append(tname)
                documented_tparams = set()
                for paramlist in compound.iter("parameterlist"):
                    if paramlist.get("kind") == "templateparam":
                        for item in paramlist.findall("parameteritem"):
                            for nl in item.findall("parameternamelist"):
                                for pname in nl.findall("parametername"):
                                    if pname.text:
                                        documented_tparams.add(pname.text.strip())
                missing = [t for t in declared_tparams if t not in documented_tparams]
                if missing:
                    failures.append((fpath, line, f"struct/class '{cname}': missing @tparam for: {', '.join(missing)}"))

        # Functions and member variables
        for memberdef in doc_root.iter("memberdef"):
            kind = memberdef.get("kind")
            if kind not in ("function", "variable"):
                continue
            loc = memberdef.find("location")
            if loc is None:
                continue
            fpath = resolve(loc.get("file", ""), root)
            line = int(loc.get("line", 0))
            if fpath not in added or line not in added[fpath]:
                continue
            name = memberdef.findtext("name", "")
            if kind == "function":
                if (name in SKIP_FUNCTIONS
                        or any(name.startswith(p) for p in SKIP_FUNCTION_PREFIXES)
                        or name.lstrip("~") in compound_names):
                    continue
                issues = check_entity(name, kind, memberdef, memberdef.findall("param"))
                for issue in issues:
                    failures.append((fpath, line, f"function '{name}': {issue}"))
            else:
                type_str = "".join(memberdef.find("type").itertext()).strip() if memberdef.find("type") is not None else ""
                if not skip_member(type_str, name) and is_empty(memberdef.find("briefdescription")):
                    failures.append((fpath, line, f"member '{name}': missing documentation"))


    return failures


def main():
    base_ref = os.environ.get("GITHUB_BASE_REF", "main")
    root = repo_root()

    subprocess.run(
        ["git", "fetch", "origin", base_ref, "--depth=1"],
        cwd=root, capture_output=True
    )

    all_changed = changed_files(root)
    relevant = [
        f for f in all_changed
        if f.suffix in EXTENSIONS
        and any(str(f).startswith(str(root / d)) for d in SCOPED_DIRS)
        and not any(str(f) == str(root / s) for s in SKIP_FILES)
    ]

    if not relevant:
        print("No GPU files changed — skipping doxygen check.")
        return 0

    print(f"Running doxygen check on {len(relevant)} file(s):")
    for f in relevant:
        print(f"  {f.relative_to(root)}")

    added = {f: added_line_numbers(root, f) for f in relevant}

    xml_dir = run_doxygen_xml(root, relevant)
    try:
        failures = parse_xml_issues(xml_dir, added, root)
    finally:
        shutil.rmtree(xml_dir, ignore_errors=True)

    if failures:
        print("\nMissing doxygen documentation on newly added code:")
        for fpath, line, msg in failures:
            try:
                rel = fpath.relative_to(root)
            except ValueError:
                rel = fpath
            print(f"  {rel}:{line}: {msg}")
        print(
            "\nNew structs, members, and functions must have a doxygen block with"
            " @brief, @tparam for template parameters, and @param for each argument."
        )
        return 1

    print("OK: all newly added GPU code is documented.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
