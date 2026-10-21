#!/usr/bin/env python3
"""将 BYOS 和 Google 依赖一起混淆，生成单一、内部重命名的运行时 JAR。"""
from pathlib import Path
import subprocess
import sys
import zipfile
import re

root, build, sdk = map(Path, sys.argv[1:])
stage = build / 'byos-r8'
stage.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(build / 'outputs/aar/shield-stub-release.aar') as aar:
    (stage / 'stub.jar').write_bytes(aar.read('classes.jar'))
versions = sorted((sdk / 'build-tools').iterdir(), key=lambda p: tuple(int(v) for v in p.name.split('.') if v.isdigit()))
platform = sdk / 'platforms/android-35/android.jar'
deps = build / 'byos-dependencies'
# JAR 内的 META-INF/proguard 也会被 R8 自动加载；统一只合并类文件，
# 与下面显式声明的 Classic 路径保留规则配套，杜绝宿主级规则悄悄重新引入 SDK 公共类。
with zipfile.ZipFile(stage / 'input.jar', 'w') as combined:
    entries = set()
    for archive in [stage / 'stub.jar', *sorted(deps.rglob('*.jar'))]:
        with zipfile.ZipFile(archive) as jar:
            for name in jar.namelist():
                if not name.endswith('.class') or name.startswith('META-INF/'):
                    continue
                if name in entries:
                    raise RuntimeError('BYOS 编译输入包含重复类：' + name)
                entries.add(name)
                combined.writestr(name, jar.read(name))
output = build / 'byos-runtime.jar'
output.unlink(missing_ok=True)
mapping = build / 'outputs/mapping/release/mapping.txt'
mapping.parent.mkdir(parents=True, exist_ok=True)
rules = stage / 'compile-only.pro'
# 注解无运行时语义；类文件中的 lambda 引导引用由后续 D8 脱糖，不是 Android 运行依赖。
rules.write_text('-dontwarn androidx.annotation.ChecksSdkIntAtLeast\n'
                 '-dontwarn java.lang.invoke.LambdaMetafactory\n'
                 '-dontwarn com.google.errorprone.annotations.**\n'
                 '-dontwarn javax.annotation.**\n'
                 '-dontwarn org.checkerframework.**\n'
                 '-keepclassmembers class * implements android.os.Parcelable { public static final *** CREATOR; }\n', encoding='utf-8')
# 只开放 ByosKeyClient 的 Classic 路径。宿主级 consumer 规则会强制带入未使用的
# AndroidX/Lifecycle/动态模块，且保留原包名，与业务 APK 的 SDK 冲突。
# 当前路径的跨进程数据使用系统 Bundle/PendingIntent，Parcelable 的 CREATOR 仍保留。
main_rules = stage / 'runtime.pro'
main_rules.write_text((root / 'shield-stub/proguard-rules.pro').read_text(encoding='utf-8')
                     .replace('-keepnames class * extends java.lang.Exception',
                              '-keepnames class dev.mocika.** extends java.lang.Exception'), encoding='utf-8')
command = ['java', '-cp', str(versions[-1] / 'lib/d8.jar'), 'com.android.tools.r8.R8',
           '--release', '--classfile', '--lib', str(platform),
           '--output', str(output), '--pg-map-output', str(mapping),
           '--pg-conf', str(main_rules), '--pg-conf', str(rules)]
command += [str(stage / 'input.jar')]
subprocess.run(command, check=True)
# JNI 按固定名称注册/回调的入口必须与最终 R8 映射一致；缺失时在打包前失败。
block = re.search(r'^dev\.mocika\.shield\.loader\.Ld -> [^\n]+:\n(.*?)(?=^[^ #\s]|\Z)',
                  mapping.read_text(encoding='utf-8'), re.M | re.S)
if not block:
    raise RuntimeError('BYOS R8 缺少 JNI 类映射')
for method in ('s', 't', 'y', 'fetchRemoteIkm'):
    names = re.findall(r'\b' + method + r'\([^\n]*\)[^\n]* -> (\S+)', block[1])
    if not names or set(names) != {method}:
        raise RuntimeError('BYOS 固定 JNI 入口被删除或重命名：' + method)
with zipfile.ZipFile(output) as jar:
    exposed = [name for name in jar.namelist() if name.endswith('.class')
               and not name.startswith(('msk/', 'dev/mocika/shield/'))]
    if exposed:
        raise RuntimeError('BYOS 依赖未隔离，可能与宿主 SDK 冲突：' + ', '.join(exposed[:5]))
