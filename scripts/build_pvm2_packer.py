#!/usr/bin/env python3
"""复用锁定的已分发依赖，从仓库源码完整重建 PVM2 打包器。"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "third_party/xopprotector/packer/src/main/java"
PROVENANCE = "META-INF/shellsmith-packer-build.json"


def digest(entries):
    result = hashlib.sha256()
    for name, data in sorted(entries.items()):
        encoded = name.encode("utf-8")
        result.update(len(encoded).to_bytes(4, "big"))
        result.update(encoded)
        result.update(len(data).to_bytes(8, "big"))
        result.update(data)
    return result.hexdigest()


def dependencies(path):
    with zipfile.ZipFile(path) as jar:
        entries = {}
        for item in jar.infolist():
            name = item.filename
            upper = name.upper()
            if item.is_dir() or name.startswith("com/yqsh/") or name == PROVENANCE:
                continue
            if upper == "META-INF/MANIFEST.MF" or upper.endswith((".SF", ".RSA", ".DSA")):
                continue
            if name in entries:
                raise ValueError(f"依赖 JAR 条目重复：{name}")
            entries[name] = jar.read(item)
        return entries


def write_jar(path, entries):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as jar:
        for name, data in sorted(entries.items()):
            item = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            item.compress_type = zipfile.ZIP_DEFLATED
            item.external_attr = 0o100644 << 16
            jar.writestr(item, data)


def build(dependency_jar, output):
    deps = dependencies(dependency_jar)
    dependency_hash = digest(deps)
    expected = (ROOT / "third_party/xopprotector/dependencies.sha256").read_text().strip()
    if dependency_hash != expected:
        raise ValueError("打包器依赖摘要与锁定值不符；拒绝复用未知依赖")
    sources = {p.relative_to(SOURCE).as_posix(): p.read_bytes() for p in sorted(SOURCE.rglob("*.java"))}
    if not sources:
        raise ValueError("未找到打包器源码")
    javac = shutil.which("javac")
    if not javac:
        raise ValueError("需要 JDK 17+ 的 javac")
    compiler = subprocess.check_output([javac, "-version"], text=True, stderr=subprocess.STDOUT).strip()
    output.parent.mkdir(parents=True, exist_ok=True)
    # ponytail: 复用已锁定 fat JAR 的外部依赖，排除全部 com/yqsh 类；升级依赖时须重新审核锁定摘要。
    with tempfile.TemporaryDirectory(prefix="pvm2-build-", dir=output.parent) as directory:
        work = Path(directory)
        classpath = work / "dependencies.jar"
        classes = work / "classes"
        classes.mkdir()
        write_jar(classpath, deps)
        source_root = work / "src"
        for name, data in sources.items():
            source = source_root / name
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(data)
        source_list = work / "sources.txt"
        source_list.write_text("\n".join('"' + str(source_root / name).replace("\\", "\\\\").replace('"', '\\"') + '"' for name in sources), encoding="utf-8")
        subprocess.run([javac, "--release", "17", "-encoding", "UTF-8", "-cp", str(classpath), "-d", str(classes), "@" + str(source_list)], check=True)
        compiled = {p.relative_to(classes).as_posix(): p.read_bytes() for p in classes.rglob("*.class")}
        if "com/yqsh/protector/packer/PackerMain.class" not in compiled:
            raise ValueError("本次构建未生成 PackerMain")
        runtime = ROOT / "third_party/xopprotector/native/src/main/cpp"
        runtime_sources = {p.relative_to(runtime).as_posix(): p.read_bytes() for p in runtime.rglob("*") if p.is_file()}
        provenance = {
            "schema_version": 1,
            "compiler": compiler,
            "sources_sha256": digest(sources),
            "dependencies_sha256": dependency_hash,
            "classes_sha256": digest(compiled),
            "runtime_sources_sha256": digest(runtime_sources),
        }
        entries = {**deps, **compiled}
        entries["META-INF/MANIFEST.MF"] = b"Manifest-Version: 1.0\r\nMain-Class: com.yqsh.protector.packer.PackerMain\r\n\r\n"
        entries[PROVENANCE] = json.dumps(provenance, sort_keys=True, indent=2).encode() + b"\n"
        result = work / "packer.jar"
        write_jar(result, entries)
        result.replace(output)
    print(f"打包器已从 {len(sources)} 个源码文件重建：{output}")
    print(f"源码 SHA-256：{provenance['sources_sha256']}")


def verify(path):
    with zipfile.ZipFile(path) as jar:
        provenance = json.loads(jar.read(PROVENANCE))
        compiled = {name: jar.read(name) for name in jar.namelist() if name.startswith("com/yqsh/") and name.endswith(".class")}
    sources = {p.relative_to(SOURCE).as_posix(): p.read_bytes() for p in SOURCE.rglob("*.java")}
    expected = (ROOT / "third_party/xopprotector/dependencies.sha256").read_text().strip()
    if provenance["schema_version"] != 1 or provenance["sources_sha256"] != digest(sources) or provenance["classes_sha256"] != digest(compiled) or provenance["dependencies_sha256"] != expected or digest(dependencies(path)) != expected:
        raise ValueError("分发 JAR 与源码或依赖锁定不一致，请运行 make build-pvm2")
    print("分发打包器源码、类文件和依赖摘要一致")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dependencies", type=Path, default=ROOT / "tools/xop-pvm2-packer.jar")
    parser.add_argument("--output", type=Path, default=ROOT / "tools/xop-pvm2-packer.jar")
    parser.add_argument("--check", action="store_true", help="只检查分发 JAR 是否对应当前源码和依赖")
    args = parser.parse_args()
    if args.check:
        verify(args.output.resolve())
    else:
        build(args.dependencies.resolve(), args.output.resolve())
