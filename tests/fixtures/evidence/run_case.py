#!/usr/bin/env python3
"""差分测试夹具：按 CASE_JSON 产生确定性输出，用于验证 harness 本身。"""

import argparse
import json
import os
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", help="仅用于标记被测包；夹具不读取 APK")
    args = parser.parse_args()
    case = json.loads(os.environ["CASE_JSON"])
    data = case.get("input", {})
    a = data.get("a")
    b = data.get("b")
    if a is None:
        value = None
    else:
        value = (int(a) + int(b or 0)) & 0xFFFFFFFF
        if value >= 0x80000000:
            value -= 0x100000000
    print(json.dumps({"id": case.get("id"), "value": value}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
