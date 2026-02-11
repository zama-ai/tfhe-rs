#!/bin/bash
set -e

echo "Building WASM..."
# Use web target for ES modules (workers use dynamic import())
wasm-pack build --target web --out-dir pkg

echo "Copying JS files..."
# worker.js and sync_executor.js are embedded in the WASM (no need to copy)
# coordinator.js is imported by sw.js (the user's Service Worker)
cp ../../js/coordinator.js pkg/

echo ""
echo "Build complete! To run:"
echo "  python3 -m http.server 8080"
echo "  # or: npx serve ."
echo ""
echo "Then open http://localhost:8080 in your browser"
