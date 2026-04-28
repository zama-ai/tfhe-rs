#!/usr/bin/env bash
set -euo pipefail

MODE="${MODE:-production}"
DEVTOOL="${DEVTOOL:-}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$ROOT_DIR/../.." && pwd)"
TFHE_DIR="$REPO_ROOT/tfhe"
COORDINATOR_SRC="$REPO_ROOT/utils/wasm-par-mq/js/coordinator.js"
FIXTURES_SRC="$TFHE_DIR/tests/zk_wasm_x86_test"

cd "$ROOT_DIR"

# Step 0: clean dist/ to avoid stale artifacts. `cp -r src dest` when `dest`
# exists nests src inside dest instead of overwriting, so without this clean
# step a re-run would create dist/pkg/pkg/, dist/pkg-client/pkg-client/, etc.
echo "==> Cleaning dist/"
rm -rf dist

# Step 1: copy pkgs into ./ (overwrite for idempotency).
# pkg is required; pkg-client is optional (only built locally when comparing
# full vs client side-by-side — CI typically only builds the full pkg).
echo "==> Copying wasm pkgs from $TFHE_DIR"
rm -rf ./pkg
cp -r "$TFHE_DIR/pkg" ./pkg

rm -rf ./pkg-client
if [[ -d "$TFHE_DIR/pkg-client" ]]; then
	cp -r "$TFHE_DIR/pkg-client" ./pkg-client
	echo "    Copied pkg-client"
else
	# pkg-client missing — webpack still needs the path to resolve the static
	# imports in client/worker.js. Fall back to a copy of pkg so the bundle
	# builds. The ?client toggle then behaves like the default (CI never sets it).
	cp -r ./pkg ./pkg-client
	echo "    pkg-client not built — falling back to a copy of pkg (CI mode)"
fi

# Step 2: webpack bundle
echo "==> Bundling with webpack (mode=$MODE${DEVTOOL:+, devtool=$DEVTOOL})"
WEBPACK_ARGS=(
	build ./index.js
	--mode "$MODE"
	-o dist
	--output-filename index.js
)
if [[ -n "$DEVTOOL" ]]; then
	WEBPACK_ARGS+=(--devtool "$DEVTOOL")
fi
npx --no-install webpack "${WEBPACK_ARGS[@]}"

# Step 3: static assets
echo "==> Copying static assets into dist/"
cp index.html favicon.ico dist/
cp "$COORDINATOR_SRC" dist/

# Step 4: copy pkgs into dist/ (served as static files for dynamic imports).
# pkg-client always exists at this point (either real or the pkg fallback).
cp -r ./pkg dist/pkg
cp -r ./pkg-client dist/pkg-client

# Step 5: best-effort fixture copy.
# We don't generate them (that's `make prepare_fixtures`'s job, which runs the
# Rust test).
if [[ -f "$FIXTURES_SRC/public_key.bin" && -f "$FIXTURES_SRC/crs.bin" ]]; then
	mkdir -p dist/fixtures
	cp "$FIXTURES_SRC/public_key.bin" "$FIXTURES_SRC/crs.bin" dist/fixtures/
	echo "==> Reused existing fixtures from $FIXTURES_SRC/"
fi

echo "==> Done. Output in dist/"
if [[ ! -d dist/fixtures ]]; then
	echo "    Fixture-based bench buttons are disabled."
	echo "    Run \`make prepare_fixtures\` to generate + copy them."
fi
