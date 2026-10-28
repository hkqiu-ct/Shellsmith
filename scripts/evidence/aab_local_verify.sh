#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

BUNDLE=""
OUTPUT_DIR="${AAB_EVIDENCE_DIR:-target/evidence/aab-local}"
BUNDLETOOL="${BUNDLETOOL:-bundletool}"
KS=""
ALIAS=""
KS_PASS_ENV=""
DEVICE=""
PACKAGE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle) BUNDLE="$2"; shift 2 ;;
    --output) OUTPUT_DIR="$2"; shift 2 ;;
    --bundletool) BUNDLETOOL="$2"; shift 2 ;;
    --ks) KS="$2"; shift 2 ;;
    --ks-key-alias) ALIAS="$2"; shift 2 ;;
    --ks-pass-env) KS_PASS_ENV="$2"; shift 2 ;;
    --device) DEVICE="$2"; shift 2 ;;
    --package) PACKAGE="$2"; shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

test -n "$BUNDLE" || { echo "需要 --bundle <protected.aab>" >&2; exit 2; }
test -f "$BUNDLE" || { echo "AAB 不存在: $BUNDLE" >&2; exit 2; }
mkdir -p "$OUTPUT_DIR"
LOG="$OUTPUT_DIR/commands.log"
: > "$LOG"

BUNDLETOOL_CMD=()
if [[ "$BUNDLETOOL" == *.jar ]]; then
  BUNDLETOOL_CMD=(java -jar "$BUNDLETOOL")
else
  BUNDLETOOL_CMD=("$BUNDLETOOL")
fi

run() {
  echo "+ $*" | tee -a "$LOG"
  "$@" 2>&1 | tee -a "$LOG"
}

run "${BUNDLETOOL_CMD[@]}" validate --bundle="$BUNDLE"

APKS="$OUTPUT_DIR/protected.apks"
SIGN_ARGS=()
PASS_FILE=""
cleanup() {
  [[ -n "$PASS_FILE" ]] && rm -f "$PASS_FILE"
}
trap cleanup EXIT
if [[ -n "$KS" ]]; then
  test -n "$ALIAS" || { echo "提供 --ks 时必须提供 --ks-key-alias" >&2; exit 2; }
  SIGN_ARGS+=(--ks="$KS" --ks-key-alias="$ALIAS")
  if [[ -n "$KS_PASS_ENV" ]]; then
    PASS_VALUE="${!KS_PASS_ENV:-}"
    test -n "$PASS_VALUE" || { echo "环境变量 $KS_PASS_ENV 为空" >&2; exit 2; }
    PASS_FILE="$OUTPUT_DIR/ks-pass.txt"
    (umask 077; printf '%s' "$PASS_VALUE" > "$PASS_FILE")
    SIGN_ARGS+=(--ks-pass="file:$PASS_FILE")
  fi
fi

run "${BUNDLETOOL_CMD[@]}" build-apks \
  --bundle="$BUNDLE" \
  --output="$APKS" \
  --overwrite \
  "${SIGN_ARGS[@]}"

if [[ -n "$DEVICE" ]]; then
  if [[ -n "$PACKAGE" ]]; then
    adb -s "$DEVICE" uninstall "$PACKAGE" >/dev/null 2>&1 || true
  fi
  run "${BUNDLETOOL_CMD[@]}" install-apks --apks="$APKS" --device-id="$DEVICE"
fi

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$BUNDLE" "$APKS" | tee "$OUTPUT_DIR/checksums-sha256.txt"
else
  sha256sum "$BUNDLE" "$APKS" | tee "$OUTPUT_DIR/checksums-sha256.txt"
fi

echo "AAB 本地验证完成：$OUTPUT_DIR"
