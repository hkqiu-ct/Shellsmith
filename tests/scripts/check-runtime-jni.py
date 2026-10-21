#!/usr/bin/env python3
"""在指定测试设备加载分发 ZIP 中原样的 DEX/SO，验证混淆后的 JNI 注册，不请求密钥服务。"""
import argparse
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zipfile

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('resources', type=Path)
parser.add_argument('--serial', required=True)
args = parser.parse_args()
sdk = Path(os.environ['ANDROID_HOME'])
bt = sdk / 'build-tools/35.0.0'
android = sdk / 'platforms/android-35/android.jar'
adb = [str(sdk / 'platform-tools/adb'), '-s', args.serial]


def run(command):
    return subprocess.check_output([str(x) for x in command], text=True, stderr=subprocess.STDOUT)


# 仅从最终 DEX 的 method_ids 查找固定 JNI 回调归属，不依赖可能过期的 mapping.txt。
def callback_class(dex):
    def u32(offset):
        return struct.unpack_from('<I', dex, offset)[0]
    strings = []
    for i in range(u32(56)):
        offset = u32(u32(60) + i * 4)
        while dex[offset] & 128:
            offset += 1
        offset += 1
        strings.append(dex[offset:dex.index(0, offset)].decode('utf-8', errors='replace'))
    types = [strings[u32(u32(68) + i * 4)] for i in range(u32(64))]
    owners = set()
    for i in range(u32(88)):
        owner, _, name = struct.unpack_from('<HHI', dex, u32(92) + i * 8)
        if strings[name] == 'fetchRemoteIkm':
            owners.add(types[owner])
    assert len(owners) == 1, '固定 JNI 回调归属不唯一或不存在'
    owner = owners.pop()
    assert re.fullmatch(r'L[\w/$]+;', owner), 'JNI 类名无效'
    return owner[1:-1].replace('/', '.')


abi = run(adb + ['shell', 'getprop', 'ro.product.cpu.abi']).strip()
package = 'dev.mocika.shield.runtimejniprobe'
with tempfile.TemporaryDirectory(prefix='shellsmith-jni-') as tmp:
    work = Path(tmp)
    with zipfile.ZipFile(args.resources) as archive:
        dex = archive.read('stub-classes.dex')
        library = archive.read(f'lib/{abi}/libmocikashield.so')
    owner = callback_class(dex)
    (work / 'Probe.java').write_text('''package dev.mocika.shield.runtimejniprobe;
public final class Probe extends android.app.Instrumentation {
    @Override public void onCreate(android.os.Bundle args) {
        super.onCreate(args);
        android.os.Bundle report = new android.os.Bundle();
        try {
            // 触发实际 System.loadLibrary 与 JNI_OnLoad，注册任一方法错配都会失败。
            Class<?> owner = Class.forName("''' + owner + '''");
            owner.getDeclaredMethod("s", android.content.Context.class, byte[].class);
            owner.getDeclaredMethod("t", android.content.Context.class, byte[].class);
            owner.getDeclaredMethod("y", int.class);
            owner.getDeclaredMethod("fetchRemoteIkm", android.content.Context.class,
                    String.class, String.class, String.class);
            report.putString("stream", "RUNTIME_JNI_OK"); finish(-1, report);
        } catch (Throwable error) {
            report.putString("stream", "RUNTIME_JNI_FAILED " + error.toString()); finish(0, report);
        }
    }
}
''')
    (work / 'AndroidManifest.xml').write_text(f'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package}">
<uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35"/>
<application android:extractNativeLibs="true"/>
<instrumentation android:name="{package}.Probe" android:targetPackage="{package}"/>
</manifest>''')
    for name in ['classes', 'dex']:
        (work / name).mkdir()
    run(['javac', '--release', '8', '-cp', android, '-d', work / 'classes', work / 'Probe.java'])
    run(['jar', 'cf', work / 'classes.jar', '-C', work / 'classes', '.'])
    run([bt / 'd8', '--lib', android, '--min-api', '26', '--output', work / 'dex', work / 'classes.jar'])
    run([bt / 'aapt2', 'link', '-I', android, '--manifest', work / 'AndroidManifest.xml', '-o', work / 'probe.apk'])
    with zipfile.ZipFile(work / 'probe.apk', 'a') as apk:
        apk.writestr('classes.dex', dex)
        apk.write(work / 'dex/classes.dex', 'classes2.dex')
        apk.writestr(f'lib/{abi}/libmocikanativeslot.so', library)
    # ponytail: 固定测试证书只用于这个隔离探针，禁止用于业务产物。
    key = root / 'target/runtime-jni-probe.p12'
    if not key.exists():
        run(['keytool', '-genkeypair', '-noprompt', '-keystore', key, '-storetype', 'PKCS12',
             '-storepass', 'shellsmith-test', '-keypass', 'shellsmith-test', '-alias', 'probe',
             '-keyalg', 'RSA', '-validity', '3650', '-dname', 'CN=Shellsmith JNI Probe'])
    run(['java', '-jar', root / 'tools/apksigner.jar', 'sign', '--ks', key,
         '--ks-pass', 'pass:shellsmith-test', work / 'probe.apk'])
    run(adb + ['install', '-r', str(work / 'probe.apk')])
    result = run(adb + ['shell', 'am', 'instrument', '--user', '0', '-w', package + '/' + package + '.Probe'])
    print(result.strip())
    assert 'RUNTIME_JNI_OK' in result and 'RUNTIME_JNI_FAILED' not in result, '分发资源 JNI 加载失败'
    print(f'{args.resources.name}: {abi} 通过')
