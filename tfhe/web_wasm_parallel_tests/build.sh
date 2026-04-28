#!/usr/bin/env bash
set -euo pipefail

MODE="${MODE:-production}"
DEVTOOL="${DEVTOOL:-}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$ROOT_DIR/../.." && pwd)"
TFHE_DIR="$REPO_ROOT/tfhe"
COORDINATOR_SRC="$REPO_ROOT/utils/wasm-par-mq/js/coordinator.js"

cd "$ROOT_DIR"

# Clean dist/ so a re-run's `cp -r` doesn't nest into dist/pkg/pkg/, etc.
echo "==> Cleaning dist/"
rm -rf dist

# The full worker statically imports ./pkg, so webpack needs it locally.
echo "==> Copying wasm pkg from $TFHE_DIR"
rm -rf ./pkg
cp -r "$TFHE_DIR/pkg" ./pkg

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

echo "==> Copying static assets into dist/"
cp index.html favicon.ico dist/
cp "$COORDINATOR_SRC" dist/

# pkg / pkg-client are loaded at runtime via webpackIgnore dynamic imports, so
# they are served as static files. pkg-client is only present when built via
# `make build_web_js_api_parallel_client WEB_CLIENT_OUT_DIR=pkg-client`.
cp -r ./pkg dist/pkg
if [[ -d "$TFHE_DIR/pkg-client" ]]; then
	cp -r "$TFHE_DIR/pkg-client" dist/pkg-client
	echo "    Copied pkg-client into dist/ (?client mode available)"
else
	echo "    pkg-client not built — ?client mode unavailable in this bundle"
fi

echo "==> Done. Output in dist/"
echo "    Run \`make prepare_fixtures\` to enable the fixture-based bench buttons."
