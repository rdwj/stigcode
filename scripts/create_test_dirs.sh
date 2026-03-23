#!/usr/bin/env bash
# Create test directory structure for stigcode
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p "$PROJECT_ROOT/tests/fixtures/ckl"
mkdir -p "$PROJECT_ROOT/tests/fixtures/sarif"
mkdir -p "$PROJECT_ROOT/tests/fixtures/reference"

echo "Created:"
find "$PROJECT_ROOT/tests" -type d | sort
