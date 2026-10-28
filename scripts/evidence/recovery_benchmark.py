#!/usr/bin/env python3
"""运行一个可重复的恢复/分析命令，记录耗时、输出和哈希。

示例：
  python3 scripts/evidence/recovery_benchmark.py \
    --name pvm2-art \
    --command "python3 tests/scripts/check-pvm2-art.py --min-api 26 --output target/evidence/pvm2-art" \
    --output docs/evidence/artifacts/pvm2-art-benchmark.json
"""

from __future__ import annotations


import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--command", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--cwd", default=".")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.repeat < 1:
        parser.error("--repeat 必须 >= 1")
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    cwd = Path(args.cwd).resolve()

    runs = []
    for index in range(args.repeat):
        started = time.monotonic()
        if args.dry_run:
            runs.append(
                {
                    "index": index + 1,
                    "dry_run": True,
                    "command": args.command,
                    "duration_ms": 0,
                }
            )
            continue
        completed = subprocess.run(
            args.command,
            shell=True,
            cwd=str(cwd),
            capture_output=True,
            timeout=args.timeout,
            env=dict(os.environ),
        )
        duration_ms = round((time.monotonic() - started) * 1000)
        runs.append(
            {
                "index": index + 1,
                "exit_code": completed.returncode,
                "duration_ms": duration_ms,
                "stdout_sha256": sha256_bytes(completed.stdout),
                "stderr_sha256": sha256_bytes(completed.stderr),
                "stdout_tail": completed.stdout.decode("utf-8", "replace")[-4000:],
                "stderr_tail": completed.stderr.decode("utf-8", "replace")[-4000:],
            }
        )
        if completed.returncode != 0:
            break

    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "name": args.name,
        "command": args.command,
        "cwd": str(cwd),
        "repeat": args.repeat,
        "dry_run": args.dry_run,
        "runs": runs,
        "all_succeeded": all(run.get("exit_code") == 0 for run in runs)
        if not args.dry_run
        else None,
    }
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(output)
    if not args.dry_run and not payload["all_succeeded"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
