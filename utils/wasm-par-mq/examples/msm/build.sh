#!/bin/bash
set -e

echo "Building WASM..."
# Use web target for ES modules (workers use dynamic import())
wasm-pack build --target web --out-dir pkg

echo "Copying coordinator service worker..."
cp ../../js/coordinator.js .

echo ""
echo "Build complete! To run:"
echo "  python3 -m http.server 8080"
echo "  # or: npx serve ."
echo ""
echo "Then open http://localhost:8080 in your browser"
