#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
OUT="${EVIDENCE_OUT:-docs/evidence/artifacts}"
LABEL="${EVIDENCE_LABEL:-baseline}"
ARGS=()
for item in "$@"; do
  ARGS+=(--input "$item")
done
python3 scripts/evidence/collect_artifacts.py \
  "${ARGS[@]}" \
  --output "$OUT" \
  --label "$LABEL"
