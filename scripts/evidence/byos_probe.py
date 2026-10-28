#!/usr/bin/env python3
"""BYOS 协议负面探测：检查鉴权、严格 JSON、响应头和错误码。

不实现设备签名/Play 证明的完整流程；完整取钥需要测试设备或 Play token。
敏感值通过参数或环境变量传入，脚本输出会脱敏。
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ZERO32 = base64.urlsafe_b64encode(b"\0" * 32).rstrip(b"=").decode()


def post(url, api_key, body, content_type="application/json", raw=False):
    data = body if raw else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("Content-Type", content_type)
    if api_key:
        request.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, dict(response.headers), response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read().decode("utf-8", "replace")
    except Exception as error:  # noqa: BLE001 - probe must record transport failures
        return 0, {}, str(error)


def check_body(auth_mode):
    return {"auth_mode": auth_mode, "fetch_protocol": 2, "request_id": ZERO32}


def fetch_body(base_url, token, package, cert, auth_mode):
    return {
        "server_url": base_url,
        "token_id": token,
        "package_name": package,
        "cert_sha256": cert,
        "auth_mode": auth_mode,
        "fetch_protocol": 2,
        "timestamp": int(datetime.now(timezone.utc).timestamp()),
        "request_id": ZERO32,
        "nonce": ZERO32,
        "response_public_key": "invalid",
        "device_public_key": "invalid",
        "device_signature": "invalid",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--api-key", default=os.environ.get("SHELLSMITH_BYOS_API_KEY", ""))
    parser.add_argument("--token-id", default="")
    parser.add_argument("--package", default="")
    parser.add_argument("--cert-sha256", default="")
    parser.add_argument("--auth-mode", default="device_approval")
    parser.add_argument("--output", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    cases = []
    if args.dry_run:
        cases = [
            {"name": "check-valid-shape", "path": "/v1/keys/check"},
            {"name": "check-missing-auth", "path": "/v1/keys/check"},
            {"name": "check-wrong-content-type", "path": "/v1/keys/check"},
            {"name": "check-duplicate-json", "path": "/v1/keys/check"},
            {"name": "fetch-missing-auth", "path": "/v1/keys/fetch"},
            {"name": "fetch-invalid-request", "path": "/v1/keys/fetch"},
        ]
        payload = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "dry_run": True,
            "base_url": base,
            "cases": cases,
        }
        output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(output)
        return 0

    results = []

    def record(name, status, headers, body, expected):
        lowered = body.lower()
        results.append(
            {
                "name": name,
                "status": status,
                "expected": expected,
                "pass": status in expected,
                "cache_control": headers.get("Cache-Control", ""),
                "body_has_ikm": '"ikm"' in lowered,
                "body_tail": body[-1000:],
            }
        )

    status, headers, body = post(f"{base}/v1/keys/check", args.api_key, check_body(args.auth_mode))
    record("check-valid-shape", status, headers, body, {200, 400, 401, 403})
    status, headers, body = post(f"{base}/v1/keys/check", "", check_body(args.auth_mode))
    record("check-missing-auth", status, headers, body, {401})
    status, headers, body = post(
        f"{base}/v1/keys/check", args.api_key, check_body(args.auth_mode), "text/plain"
    )
    record("check-wrong-content-type", status, headers, body, {400, 415})
    status, headers, body = post(
        f"{base}/v1/keys/check",
        args.api_key,
        b'{"auth_mode":"device_approval","auth_mode":"play_integrity"}',
        raw=True,
    )
    record("check-duplicate-json", status, headers, body, {400})
    status, headers, body = post(
        f"{base}/v1/keys/check",
        args.api_key,
        {"auth_mode": args.auth_mode, "fetch_protocol": 2, "request_id": ZERO32, "unknown": True},
    )
    record("check-unknown-field", status, headers, body, {400})
    status, headers, body = post(
        f"{base}/v1/keys/fetch",
        "",
        fetch_body(base, args.token_id, args.package, args.cert_sha256, args.auth_mode),
    )
    record("fetch-missing-auth", status, headers, body, {401, 403})
    status, headers, body = post(
        f"{base}/v1/keys/fetch",
        args.api_key,
        fetch_body(base, "invalid-token", args.package, args.cert_sha256, args.auth_mode),
    )
    record("fetch-invalid-request", status, headers, body, {400, 403})

    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "base_url": base,
        "auth_mode": args.auth_mode,
        "results": results,
    }
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(output)
    return 0 if all(item["pass"] for item in results) else 1


if __name__ == "__main__":
    sys.exit(main())
