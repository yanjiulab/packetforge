#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLES_DIR="$ROOT_DIR/examples"
PROTO_DIR="$ROOT_DIR/proto"

for psl in "$EXAMPLES_DIR"/*.psl; do
  [ -e "$psl" ] || continue  # 没有匹配文件时跳过
  echo "===== dry-run: $(basename "$psl") ====="
  ./pf -s "$psl" -p "$PROTO_DIR" -d
  echo
done