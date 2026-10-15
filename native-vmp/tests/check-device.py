#!/usr/bin/env python3
"""在指定 Android 设备执行仓库 conditional_feature 的已核验 Native 库。"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--serial', required=True)
parser.add_argument('--cc', required=True, help='NDK 对应 ABI/API 的 Clang 驱动')
parser.add_argument('--llvm-bin', required=True)
parser.add_argument('--library', required=True)
parser.add_argument('--report', required=True)
parser.add_argument('--output', required=True)
args = parser.parse_args()
adb = ['adb', '-s', args.serial]
root = Path(__file__).resolve().parents[1]
subprocess.run([sys.executable, str(root/'cmake/mocika_vmp_evidence.py'), 'verify',
                '--readobj', str(Path(args.llvm_bin)/'llvm-readobj'),
                '--library', args.library, '--report', args.report], check=True)

source = r'''
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
static int32_t (*protected_score)(void *, void *, int32_t);
static int32_t reference(int32_t value) {
    for (int32_t i = 0; i < 4; ++i) value = (value * 17 + i) ^ (value >> 2);
    return value;
}
static void *check(void *unused) {
    (void)unused;
    /* 输入限定为 0..999，原 C 样本的有符号乘法不会溢出。 */
    for (int32_t i = 0; i < 1000; ++i)
        if (protected_score(NULL, NULL, i) != reference(i)) return (void *)(uintptr_t)1;
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 2; }
    protected_score = dlsym(library, "Java_dev_mocika_shield_featurefixture_conditional_ConditionalProbe_nativeScore");
    if (!protected_score || check(NULL)) return 3;
    pthread_t threads[8];
    for (int i = 0; i < 8; ++i) if (pthread_create(&threads[i], NULL, check, NULL)) return 4;
    for (int i = 0; i < 8; ++i) {
        void *result;
        if (pthread_join(threads[i], &result) || result) return 5;
    }
    dlclose(library);
    puts("NATIVE_VMP_DEVICE_OK sequential=1000 threads=8 calls_per_thread=1000");
    return 0;
}
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


with tempfile.TemporaryDirectory(prefix='native-vmp-device-') as directory:
    work = Path(directory)
    cfile, runner = work/'probe.c', work/'probe'
    cfile.write_text(source)
    subprocess.run([args.cc, '-O2', '-Wall', '-Werror', '-pthread', str(cfile), '-ldl', '-o', str(runner)], check=True)
    remote = '/data/local/tmp/mocika-native-vmp-'+uuid.uuid4().hex
    subprocess.run(adb+['shell', 'mkdir', remote], check=True)
    try:
        for local, name in ((args.library, 'library.so'), (runner, 'probe')):
            subprocess.run(adb+['push', str(local), remote+'/'+name], check=True)
            actual = subprocess.check_output(adb+['exec-out', 'cat', remote+'/'+name])
            if sha(actual) != sha(Path(local).read_bytes()): raise ValueError('设备文件与宿主构建不一致')
        subprocess.run(adb+['shell', 'chmod', '700', remote+'/probe'], check=True)
        transcript = subprocess.check_output(adb+['shell', remote+'/probe', remote+'/library.so'], text=True)
        if 'NATIVE_VMP_DEVICE_OK' not in transcript: raise ValueError('设备未返回成功标志')
        device = {key: subprocess.check_output(adb+['shell', 'getprop', key], text=True).strip()
                  for key in ('ro.product.model', 'ro.build.version.sdk', 'ro.product.cpu.abilist', 'ro.build.fingerprint')}
        device['page_size'] = subprocess.check_output(adb+['shell', 'getconf', 'PAGESIZE'], text=True).strip()
        report = dict(schema_version=1, status='executed', scope='conditional_feature_native_sample',
                      library_sha256=sha(Path(args.library).read_bytes()),
                      link_report_sha256=sha(Path(args.report).read_bytes()),
                      probe_source_sha256=sha(source.encode()), probe_sha256=sha(runner.read_bytes()),
                      device=device, transcript=transcript.strip())
        output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=output.parent, delete=False) as temp:
            temporary = Path(temp.name)
            json.dump(report, temp, ensure_ascii=False, indent=2); temp.write('\n')
        try: temporary.replace(output)
        finally: temporary.unlink(missing_ok=True)
        print(transcript.strip())
        print('设备执行记录：'+str(output))
    finally:
        subprocess.run(adb+['shell', 'rm', '-rf', remote], check=True)
