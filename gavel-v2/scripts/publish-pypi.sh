#!/usr/bin/env bash
# Publish gavel-governance to PyPI.
# Prerequisites:
#   1. PyPI account with API token
#   2. python -m pip install build twine
set -euo pipefail

PKG_DIR="packages/gavel-governance"

echo "=== Step 1: Clean previous builds ==="
rm -rf "${PKG_DIR}/dist" "${PKG_DIR}/build"

echo "=== Step 2: Build ==="
cd "${PKG_DIR}"
python -m build
echo "Built:"
ls -la dist/

echo "=== Step 3: Check ==="
python -m twine check dist/*

echo "=== Step 4: Upload to TestPyPI (dry run) ==="
echo "Run: python -m twine upload --repository testpypi dist/*"
echo "Then verify: pip install --index-url https://test.pypi.org/simple/ gavel-governance"

echo ""
echo "=== Step 5: Upload to PyPI (production) ==="
echo "Run: python -m twine upload dist/*"
echo ""
echo "Done. Package ready for publishing."
