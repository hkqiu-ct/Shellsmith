#!/usr/bin/env python3
"""原包/加固包差分测试框架。

command 模式：
  对每个 case，分别运行原包命令和加固包命令，比较 stdout/stderr/exit code。
  命令通过环境变量 CASE_ID、CASE_JSON 接收输入。

adb 模式（需要可调试测试包）：
  安装原包/加固包，启动 Activity，传入 token，抓取 logcat 中的
  DIFF_OK <token> 标记。这里只提供最小执行器，业务夹具需自行提供。

示例：
  python3 scripts/evidence/differential_test.py \
    --original-cmd "python3 tests/fixtures/evidence/run_case.py --apk original.apk" \
    --protected-cmd "python3 tests/fixtures/evidence/run_case.py --apk protected.apk" \
    --cases tests/fixtures/evidence/cases.json \
    --output target/evidence/diff.json
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


def load_cases(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("cases", [])
    if not isinstance(data, list) or not data:
        raise ValueError("cases 必须是非空数组")
    for index, case in enumerate(data):
        if not isinstance(case, dict):
            raise ValueError(f"case[{index}] 必须是对象")
    return data


def run_command(command: str, case: dict, timeout: int) -> dict:
    env = dict(os.environ)
    env["CASE_ID"] = str(case.get("id", "case"))
    env["CASE_JSON"] = json.dumps(case, ensure_ascii=False, sort_keys=True)
    started = time.monotonic()
    completed = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        timeout=timeout,
        env=env,
    )
    return {
        "exit_code": completed.returncode,
        "duration_ms": round((time.monotonic() - started) * 1000),
        "stdout": completed.stdout.decode("utf-8", "replace"),
        "stderr": completed.stderr.decode("utf-8", "replace"),
    }


def normalized(result: dict) -> dict:
    return {
        "exit_code": result["exit_code"],
        "stdout_sha256": hashlib.sha256(result["stdout"].encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(result["stderr"].encode()).hexdigest(),
    }


def run_adb_case(
    serial: str,
    apk: Path,
    package: str,
    activity: str,
    case: dict,
    timeout: int,
) -> dict:
    adb = os.environ.get("ADB", "adb")
    subprocess.run([adb, "-s", serial, "install", "-r", str(apk)], check=True, capture_output=True)
    token = f"diff-{case.get('id', 'case')}-{int(time.time() * 1000)}"
    subprocess.run(
        [
            adb,
            "-s",
            serial,
            "shell",
            "am",
            "start",
            "-W",
            "-n",
            f"{package}/{activity}",
            "--es",
            "token",
            token,
        ],
        check=True,
        capture_output=True,
    )
    deadline = time.monotonic() + timeout
    output = ""
    while time.monotonic() < deadline:
        result = subprocess.run(
            [adb, "-s", serial, "logcat", "-d", "-s", "DiffProbe:I", "*:S"],
            capture_output=True,
            text=True,
        )
        output = result.stdout
        if f"DIFF_OK {token}" in output:
            return {"exit_code": 0, "stdout": output, "stderr": ""}
        time.sleep(1)
    return {"exit_code": 1, "stdout": output, "stderr": "timeout waiting for DIFF_OK"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--original-cmd")
    mode.add_argument("--dry-run", action="store_true")
    parser.add_argument("--protected-cmd")
    parser.add_argument("--cases", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--serial")
    parser.add_argument("--original-apk")
    parser.add_argument("--protected-apk")
    parser.add_argument("--package")
    parser.add_argument("--activity", default=".MainActivity")
    args = parser.parse_args()

    cases = load_cases(Path(args.cases))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    if args.dry_run:
        payload = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "dry-run",
            "case_count": len(cases),
            "cases": [case.get("id", f"case-{i}") for i, case in enumerate(cases)],
        }
        output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(output)
        return 0

    if args.original_cmd and not args.protected_cmd:
        parser.error("command 模式需要同时提供 --original-cmd 和 --protected-cmd")

    results = []
    failed = 0
    for case in cases:
        if args.original_cmd:
            original = run_command(args.original_cmd, case, args.timeout)
            protected = run_command(args.protected_cmd, case, args.timeout)
        else:
            if not all([args.serial, args.original_apk, args.protected_apk, args.package]):
                parser.error("adb 模式需要 --serial/--original-apk/--protected-apk/--package")
            original = run_adb_case(
                args.serial, Path(args.original_apk), args.package, args.activity, case, args.timeout
            )
            protected = run_adb_case(
                args.serial, Path(args.protected_apk), args.package, args.activity, case, args.timeout
            )
        same = normalized(original) == normalized(protected)
        if not same:
            failed += 1
        results.append(
            {
                "id": case.get("id", f"case-{len(results)}"),
                "same": same,
                "original": normalized(original),
                "protected": normalized(protected),
            }
        )

    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "command" if args.original_cmd else "adb",
        "case_count": len(cases),
        "failed": failed,
        "results": results,
    }
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(output)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
