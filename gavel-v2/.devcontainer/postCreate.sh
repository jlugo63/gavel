#!/usr/bin/env bash
# Post-create setup for the gavel devcontainer / Codespaces.
set -euo pipefail

echo "=== Installing gavel (editable, with dev extras) ==="
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

echo "=== Installing standalone gavel-governance package (editable) ==="
python -m pip install -e packages/gavel-governance

echo "=== Running test suites ==="
python -m pytest tests packages/gavel-governance/tests -q

echo ""
echo "=== Ready ==="
echo "Try the quickstart:"
echo "  python packages/gavel-governance/examples/quickstart.py"
echo ""
echo "Or run the governance gateway:"
echo "  python -m gavel.gateway"
