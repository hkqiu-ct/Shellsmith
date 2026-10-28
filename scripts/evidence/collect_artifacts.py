#!/usr/bin/env python3
"""采集原始产物的哈希和结构信息，生成可复现的 manifest.json。

不复制业务 APK/AAB，不读取密钥文件内容；只记录路径、大小、哈希和 ZIP 结构。
"""

from __future__ import annotations


import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 1


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_tool(explicit, name):
    if explicit:
        return explicit
    return shutil.which(name)


def cert_fingerprints(apk: Path, apksigner: str | None) -> list[str] | None:
    if not apksigner:
        return None
    result = subprocess.run(
        [apksigner, "verify", "--print-certs", str(apk)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        return None
    values = []
    for line in result.stdout.splitlines():
        match = re.search(r"SHA-256 digest:\s*([0-9a-fA-F:]+)", line)
        if match:
            values.append(match.group(1).replace(":", "").upper())
    return values or None


def zip_summary(path: Path) -> dict:
    summary = {
        "entry_count": 0,
        "dex_entries": [],
        "native_libs": {},
        "asset_entries": 0,
        "has_manifest": False,
        "has_bundle_config": False,
    }
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            summary["entry_count"] = len(names)
            for name in names:
                if re.fullmatch(r"classes\d*\.dex", name) or re.fullmatch(
                    r"base/dex/classes\d*\.dex", name
                ):
                    summary["dex_entries"].append(name)
                match = re.match(r"lib/([^/]+)/[^/]+\.so$", name)
                if match:
                    summary["native_libs"][match.group(1)] = (
                        summary["native_libs"].get(match.group(1), 0) + 1
                    )
                if name.startswith("assets/"):
                    summary["asset_entries"] += 1
                if name in ("AndroidManifest.xml", "base/manifest/AndroidManifest.xml"):
                    summary["has_manifest"] = True
                if name == "BundleConfig.pb":
                    summary["has_bundle_config"] = True
    except zipfile.BadZipFile:
        summary["error"] = "not a valid zip"
    return summary


def file_entry(path: Path, label: str, apksigner: str | None) -> dict:
    data = {
        "path": str(path),
        "name": path.name,
        "label": label,
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "suffix": path.suffix.lower(),
    }
    if path.suffix.lower() in (".apk", ".aab", ".apks", ".zip"):
        data["zip"] = zip_summary(path)
    if path.suffix.lower() == ".apk":
        certs = cert_fingerprints(path, apksigner)
        if certs is not None:
            data["signer_sha256"] = certs
    return data


def git_commit(repo: Path) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", required=True, help="原始产物路径，可重复")
    parser.add_argument("--output", required=True, help="输出目录")
    parser.add_argument("--label", default="baseline")
    parser.add_argument("--apksigner", help="apksigner jar 路径")
    parser.add_argument("--git-commit", help="显式记录 commit；默认取当前仓库")
    parser.add_argument("--json-name", default="manifest.json")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    apksigner = find_tool(args.apksigner, "apksigner")
    commit = args.git_commit or git_commit(root)

    files = []
    for raw in args.input:
        path = Path(raw).expanduser()
        if not path.is_file():
            parser.error(f"输入不存在或不是文件：{path}")
        files.append(file_entry(path, args.label, apksigner))

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "label": args.label,
        "git_commit": commit,
        "source_root": str(root),
        "files": files,
    }
    target = output / args.json_name
    target.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
