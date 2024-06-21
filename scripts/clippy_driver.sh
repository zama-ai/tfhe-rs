#!/usr/bin/env bash

set -eu

exec clippy-driver ${CLIPPYFLAGS} $@
