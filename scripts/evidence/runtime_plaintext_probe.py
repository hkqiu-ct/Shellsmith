#!/usr/bin/env python3
"""采样应用私有目录中的明文 DEX/assets/SO 以及启动/PSS 数据。

要求测试包可调试（run-as 可用），否则只记录无法读取。该脚本不做提取攻击，
只用于验证明文生命周期和清理路径。
"""

from __future__ import annotations


import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def adb(serial: str, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["adb", "-s", serial, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_as(serial: str, package: str, command: str, timeout: int = 60):
    return adb(serial, "shell", "run-as", package, "sh", "-c", command, timeout=timeout)


def list_plaintext(serial: str, package: str) -> list[dict]:
    command = (
        "find . -type f \\( -name '*.dex' -o -name '*.so' -o -name '*.rtap' "
        "-o -name '*.txt' -o -name '*.bin' \\) -print 2>/dev/null"
    )
    found = run_as(serial, package, command)
    if found.returncode != 0:
        return [{"error": found.stderr.strip() or "run-as failed"}]
    results = []
    for path in sorted({line.strip() for line in found.stdout.splitlines() if line.strip()}):
        stat = run_as(serial, package, f"stat -c '%s' '{path}' 2>/dev/null")
        digest = run_as(serial, package, f"sha256sum '{path}' 2>/dev/null")
        size = None
        if stat.returncode == 0 and stat.stdout.strip().isdigit():
            size = int(stat.stdout.strip())
        results.append(
            {
                "path": path,
                "size_bytes": size,
                "sha256": digest.stdout.split()[0] if digest.returncode == 0 and digest.stdout else None,
            }
        )
    return results


def pss(serial: str, package: str) -> int | None:
    result = adb(serial, "shell", "dumpsys", "meminfo", package)
    if result.returncode != 0:
        return None
    match = re.search(r"TOTAL PSS:\s*(\d+)", result.stdout)
    if match:
        return int(match.group(1))
    match = re.search(r"TOTAL\s+(\d+)", result.stdout)
    return int(match.group(1)) if match else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--activity", help="可选：启动 Activity，例如 .MainActivity")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.dry_run:
        payload = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "dry_run": True,
            "package": args.package,
            "activity": args.activity,
        }
        output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(output)
        return 0

    startup_ms = None
    if args.activity:
        adb(args.serial, "shell", "am", "force-stop", args.package)
        started = adb(
            args.serial,
            "shell",
            "am",
            "start",
            "-W",
            "-n",
            f"{args.package}/{args.activity}",
        )
        match = re.search(r"TotalTime:\s*(\d+)", started.stdout)
        if match:
            startup_ms = int(match.group(1))

    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "package": args.package,
        "serial": args.serial,
        "startup_total_time_ms": startup_ms,
        "pss_kb": pss(args.serial, args.package),
        "plaintext_files": list_plaintext(args.serial, args.package),
    }
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
