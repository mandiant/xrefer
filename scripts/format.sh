#!/usr/bin/env bash
set -euo pipefail

LINE_LENGTH=200

ruff format --line-length $LINE_LENGTH --exclude '.json' "$1"
isort -l $LINE_LENGTH "$1"
