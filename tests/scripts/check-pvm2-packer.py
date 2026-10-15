#!/usr/bin/env python3
"""从源码构建并验证 PVM2，测试不使用旧 JAR 中的业务实现。"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("packer_build", ROOT / "scripts/build_pvm2_packer.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
with tempfile.TemporaryDirectory(prefix="pvm2-check-") as directory:
    work = Path(directory)
    jar = work / "packer.jar"
    builder.verify(ROOT / "tools/xop-pvm2-packer.jar")
    builder.build(ROOT / "tools/xop-pvm2-packer.jar", jar)
    with zipfile.ZipFile(jar) as archive:
        provenance = json.loads(archive.read(builder.PROVENANCE))
        compiled = {name: archive.read(name) for name in archive.namelist() if name.startswith("com/yqsh/") and name.endswith(".class")}
    assert provenance["classes_sha256"] == builder.digest(compiled)
    assert provenance["sources_sha256"] == builder.digest({p.relative_to(builder.SOURCE).as_posix(): p.read_bytes() for p in builder.SOURCE.rglob("*.java")})
    classes = work / "classes"
    classes.mkdir()
    subprocess.run(["javac", "--release", "17", "-cp", str(jar), "-d", str(classes),
                    str(ROOT / "tests/java/com/yqsh/protector/packer/Pvm2ProtectionCheck.java"),
                    str(ROOT / "tests/java/com/yqsh/protector/packer/Pvm2RuntimeImages.java"),
                    str(ROOT / "tests/java/com/yqsh/protector/packer/ApkRecoveryCheck.java")], check=True)
    subprocess.run(["java", "-ea", "-cp", str(classes) + os.pathsep + str(jar), "com.yqsh.protector.packer.Pvm2ProtectionCheck", str(work)], check=True)
    subprocess.run(["java", "-ea", "-cp", str(classes) + os.pathsep + str(jar), "com.yqsh.protector.packer.ApkRecoveryCheck", "--self-test"], check=True)
    # 依赖包被改动时必须拒绝，且不能覆盖上一次可用的产物。
    broken = work / "broken.jar"
    builder.write_jar(broken, {"unknown.class": b"bad"})
    before = jar.read_bytes()
    try:
        builder.build(broken, jar)
        raise AssertionError("未拒绝未知依赖")
    except ValueError:
        pass
    assert before == jar.read_bytes()
