#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODE="baseline"
if [[ "${1:-}" == "--strict" ]]; then
  MODE="strict"
elif [[ "${1:-}" == "--baseline" || -z "${1:-}" ]]; then
  MODE="baseline"
else
  echo "用法: $0 [--baseline|--strict]" >&2
  exit 2
fi

required=(
  "docs/evidence/README.md"
  "docs/evidence/threat-model.md"
  "docs/evidence/attack-tree.md"
  "docs/evidence/trust-boundaries.md"
  "docs/evidence/metrics.md"
  "docs/evidence/experiment-matrix.md"
  "docs/evidence/chain-a-report.md"
  "docs/evidence/chain-b-report.md"
  "scripts/evidence/collect_artifacts.py"
  "scripts/evidence/recovery_benchmark.py"
  "scripts/evidence/differential_test.py"
  "scripts/evidence/runtime_plaintext_probe.py"
)
for file in "${required[@]}"; do
  test -s "$file" || { echo "缺少证据文件: $file" >&2; exit 1; }
done

grep -q "未验证" docs/evidence/chain-a-report.md || {
  echo "chain-a-report.md 必须列出未验证项" >&2
  exit 1
}
grep -q "未验证" docs/evidence/chain-b-report.md || {
  echo "chain-b-report.md 必须列出未验证项" >&2
  exit 1
}
grep -q "失败条件" docs/evidence/experiment-matrix.md || {
  echo "experiment-matrix.md 必须包含失败条件" >&2
  exit 1
}

if [[ -f docs/evidence/artifacts/manifest.json ]]; then
  python3 - <<'PY'
import json
from pathlib import Path
path = Path("docs/evidence/artifacts/manifest.json")
data = json.loads(path.read_text(encoding="utf-8"))
files = data.get("files")
assert data.get("schema_version") == 1, "manifest schema_version 必须为 1"
assert isinstance(files, list) and files, "manifest 必须包含 files"
for item in files:
    digest = item.get("sha256", "")
    assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest), "sha256 无效"
print(f"manifest 校验通过: {len(files)} 个文件")
PY
elif [[ "$MODE" == "strict" ]]; then
  echo "strict 模式要求 docs/evidence/artifacts/manifest.json" >&2
  exit 1
fi

if [[ "$MODE" == "strict" ]]; then
  grep -q "verified" docs/evidence/chain-a-report.md || {
    echo "strict 模式要求 Chain A 至少包含 verified 结果" >&2
    exit 1
  }
  grep -q "verified" docs/evidence/chain-b-report.md || {
    echo "strict 模式要求 Chain B 至少包含 verified 结果" >&2
    exit 1
  }
fi

echo "证据检查通过（${MODE}）"
