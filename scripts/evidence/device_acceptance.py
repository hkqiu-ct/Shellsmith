#!/usr/bin/env python3
"""执行单台 Android 设备的安装、启动、PSS、日志和私有目录采样。

示例：
  python3 scripts/evidence/device_acceptance.py \
    --serial 12345678 \
    --apk target/signed.apk \
    --package com.example.app \
    --activity .MainActivity \
    --output docs/evidence/artifacts/device-12345678.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def adb(serial: str, *args: str, timeout: int = 120, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["adb", "-s", serial, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pss(serial: str, package: str) -> int | None:
    result = adb(serial, "shell", "dumpsys", "meminfo", package)
    if result.returncode != 0:
        return None
    match = re.search(r"TOTAL PSS:\s*(\d+)", result.stdout)
    if match:
        return int(match.group(1))
    match = re.search(r"TOTAL\s+(\d+)", result.stdout)
    return int(match.group(1)) if match else None


def startup(serial: str, package: str, activity: str) -> dict:
    adb(serial, "shell", "am", "force-stop", package)
    result = adb(
        serial,
        "shell",
        "am",
        "start",
        "-W",
        "-n",
        f"{package}/{activity}",
        timeout=180,
    )
    total = re.search(r"TotalTime:\s*(\d+)", result.stdout)
    wait = re.search(r"WaitTime:\s*(\d+)", result.stdout)
    return {
        "exit_code": result.returncode,
        "total_time_ms": int(total.group(1)) if total else None,
        "wait_time_ms": int(wait.group(1)) if wait else None,
        "stdout": result.stdout[-4000:],
        "stderr": result.stderr[-4000:],
    }


def plaintext_files(serial: str, package: str) -> list[dict]:
    command = (
        "find . -type f \\( -name '*.dex' -o -name '*.so' -o -name '*.rtap' "
        "-o -name '*.txt' -o -name '*.bin' \\) -print 2>/dev/null"
    )
    result = adb(serial, "shell", "run-as", package, "sh", "-c", command)
    if result.returncode != 0:
        return [{"error": result.stderr.strip() or "run-as failed"}]
    output = []
    for path in sorted({line.strip() for line in result.stdout.splitlines() if line.strip()}):
        stat = adb(serial, "shell", "run-as", package, "stat", "-c", "%s", path)
        size = int(stat.stdout.strip()) if stat.returncode == 0 and stat.stdout.strip().isdigit() else None
        output.append({"path": path, "size_bytes": size})
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--activity", default=".MainActivity")
    parser.add_argument("--apk")
    parser.add_argument("--output", required=True)
    parser.add_argument("--clear-data", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.dry_run:
        payload = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "dry_run": True,
            "serial": args.serial,
            "package": args.package,
            "activity": args.activity,
            "apk": args.apk,
        }
        output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(output)
        return 0

    steps: list[dict] = []
    apk_info = None
    if args.apk:
        apk = Path(args.apk)
        if not apk.is_file():
            parser.error(f"APK 不存在：{apk}")
        apk_info = {"path": str(apk), "sha256": sha256(apk), "size_bytes": apk.stat().st_size}
        installed = adb(args.serial, "install", "-r", "-t", str(apk), timeout=300)
        steps.append({"step": "install", "exit_code": installed.returncode, "output": installed.stdout[-2000:]})
        if installed.returncode != 0:
            steps.append({"step": "install_failed", "stderr": installed.stderr[-2000:]})
    if args.clear_data:
        cleared = adb(args.serial, "shell", "pm", "clear", args.package)
        steps.append({"step": "clear_data", "exit_code": cleared.returncode})
    start = startup(args.serial, args.package, args.activity)
    steps.append({"step": "start", **start})
    pid = adb(args.serial, "shell", "pidof", args.package)
    logcat = adb(args.serial, "logcat", "-d", "-v", "threadtime", timeout=180)
    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "serial": args.serial,
        "package": args.package,
        "activity": args.activity,
        "apk": apk_info,
        "pid": pid.stdout.strip(),
        "pss_kb": pss(args.serial, args.package),
        "plaintext_files": plaintext_files(args.serial, args.package),
        "steps": steps,
        "logcat_sha256": hashlib.sha256(logcat.stdout.encode()).hexdigest(),
        "logcat_tail": logcat.stdout[-8000:],
    }
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(output)
    return 0 if start.get("exit_code") == 0 and payload["pid"] else 1


if __name__ == "__main__":
    sys.exit(main())
