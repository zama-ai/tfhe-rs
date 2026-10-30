#!/usr/bin/env bash

# Check that python is only ever run from a venv in the Makefiles and the GitHub workflows, so that
# nothing depends on, or installs into, the Python of the machine. Venvs are created by the
# setup_python_venv and install_python_requirements recipes of the Makefile.
#
# Tolerated:
#   - python called by name in a command that activates a venv first (activate_python_venv in
#     make/python.mk, continuation lines included), which is how packages are installed so that
#     Aikido Safe-Chain, which wraps commands by name, can check them
#   - 'shell: python' workflow steps: inline standard library snippets parsing the workflow inputs,
#     which run before any checkout, so no venv can exist yet, and run no repository code
#   - the data sender script of slab, which runs on slab runners with the Python environment that
#     slab sets up

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# A python, python3 or python3.X command, i.e. followed by an option, a quoted argument, a path or a
# .py file, not preceded by a path component (venv/bin/python is fine), comments stripped
awk '
    FNR == 1 { activated = 0 }
    {
        line = $0
        sub(/#.*/, "", line)
        # a command activating a venv, and its continuation lines, may call python by name
        if (line ~ /activate_python_venv|bin\/activate && /) activated = 1
        tolerated = activated
        if (line !~ /\\[[:space:]]*$/) activated = 0
    }
    !tolerated \
        && line ~ /(^|[^\/A-Za-z0-9_.-])python3?(\.[0-9]+)?[[:space:]]+(-|["\x27]|\.\/|[A-Za-z0-9_.-]+\/|[A-Za-z0-9_.\/-]*\.py)/ \
        && line !~ /shell: python[[:space:]]*$/ \
        && line !~ /slab\/scripts\// {
        printf "%s:%d: %s\n", FILENAME, FNR, $0
        status = 1
    }
    END { exit status }
' Makefile make/*.mk utils/tfhe-lints/Makefile .github/workflows/*.yml && exit 0

echo "python must be run from a venv, see setup_python_venv and install_python_requirements in the Makefile" >&2
exit 1
