#!/usr/bin/env python3
"""构建模拟 TheRouter 协议的离线注册样本；指定 --serial 后验证真机，不覆盖已有测试包。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = 'dev.mocika.shield.theroutercompat'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--serial')
parser.add_argument('--cli', type=Path, default=ROOT / 'target/release/shield')
parser.add_argument('--output', type=Path, default=ROOT / 'target/therouter-compat/apk')
args = parser.parse_args()
sdk = Path(os.environ.get('ANDROID_HOME') or os.environ['ANDROID_SDK_ROOT'])
bt = sdk / 'build-tools/35.0.0'
android = sdk / 'platforms/android-35/android.jar'
work = args.output.resolve()
work.mkdir(parents=True, exist_ok=True)
env = dict(os.environ, MOCIKA_SHIELD_KS_PASS='public-test-password')
log = (work / 'commands.log').open('w')


def run(command, check=True):
    result = subprocess.run([str(x) for x in command], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=180)
    log.write(result.stdout + result.stderr)
    log.flush()
    if check and result.returncode:
        raise RuntimeError('命令失败，详见 ' + str(work / 'commands.log'))
    return result.stdout + result.stderr


key = work / 'test.p12'
if not key.exists():
    run(['keytool', '-genkeypair', '-noprompt', '-keystore', key, '-storetype', 'PKCS12',
         '-storepass:env', 'MOCIKA_SHIELD_KS_PASS', '-alias', 'probe', '-keyalg', 'RSA',
         '-validity', '7', '-dname', 'CN=Shellsmith Compatibility Test'])
key.chmod(0o600)


def sign(source, output):
    run([args.cli, 'sign', '-i', source, '-o', output, '--ks', key, '--key-alias', 'probe',
         '--ks-type', 'pkcs12', '--apksigner', ROOT / 'tools/apksigner.jar'])


base = 'package ' + PACKAGE + ';\n'
results = []
adb = [sdk / 'platform-tools/adb', '-s', args.serial] if args.serial else None
if adb and 'package:' in run(adb + ['shell', 'pm', 'path', PACKAGE], check=False):
    raise SystemExit('设备已存在同名测试包，拒绝覆盖')
for mode in ['asm', 'index', 'unknown']:
    directory = work / mode
    classes, dex = directory / 'classes', directory / 'dex'
    classes.mkdir(parents=True, exist_ok=True)
    dex.mkdir(exist_ok=True)
    sources = {
        'Business': base + 'public class Business { public static int calc(int n) { return n * 7 + 3; } }',
        'Target': base + 'public class Target { public int value; }',
        'State': base + 'public class State { public static int routes, services; }',
        'Target__TheRouter__Autowired': base + 'public class Target__TheRouter__Autowired { public static void inject(Object o) { ((Target)o).value=47; } }',
        'ServiceProvider__TheRouter__test': 'package a; public class ServiceProvider__TheRouter__test { public void init() { ' + PACKAGE + '.State.services++; } }',
        'RouterMap__TheRouter__test': 'package a; public class RouterMap__TheRouter__test { public void init() { ' + PACKAGE + '.State.routes++; } }',
        'TheRouterServiceProvideInjecter': 'package a; public class TheRouterServiceProvideInjecter { public static final boolean asm=' + str(mode == 'asm').lower() + '; }',
    }
    if mode == 'index':
        sources['RenamedIndex'] = base + '''public class RenamedIndex {
          private static final java.util.List<Object> s=new java.util.ArrayList<>(), r=new java.util.ArrayList<>();
          private static final java.util.Map<Class<?>,java.lang.reflect.Method> a=new java.util.HashMap<>();
          public static java.util.List<Object> getServiceProviderIndex(){return s;}
          public static java.util.List<Object> getRouterMapIndex(){return r;}
          public static java.util.Map<Class<?>,java.lang.reflect.Method> getAutowiredIndex(){return a;}
        }'''
        registration = '''
          if (RenamedIndex.getServiceProviderIndex().isEmpty()) {
            // 模拟上游 sourceDir 扫描；加固后必须由兼容索引补齐，不能继续依赖 Stub APK 的类表。
            dalvik.system.DexFile file=new dalvik.system.DexFile(getApplicationInfo().sourceDir);
            java.util.Enumeration<String> names=file.entries();
            while(names.hasMoreElements()) {
              String name=names.nextElement();
              if(name.startsWith("a.ServiceProvider__TheRouter__")) RenamedIndex.getServiceProviderIndex().add(Class.forName(name).newInstance());
              if(name.startsWith("a.RouterMap__TheRouter__")) RenamedIndex.getRouterMapIndex().add(Class.forName(name).newInstance());
              if(name.endsWith("__TheRouter__Autowired")) RenamedIndex.getAutowiredIndex().put(Target.class,Class.forName(name).getMethod("inject",Object.class));
            }
            file.close();
          }
          for(Object o:RenamedIndex.getServiceProviderIndex()) o.getClass().getMethod("init").invoke(o);
          for(Object o:RenamedIndex.getRouterMapIndex()) o.getClass().getMethod("init").invoke(o);
          RenamedIndex.getAutowiredIndex().get(Target.class).invoke(null,target);
        '''
    else:
        registration = '''new a.ServiceProvider__TheRouter__test().init();
          new a.RouterMap__TheRouter__test().init(); Target__TheRouter__Autowired.inject(target);'''
    sources['MainActivity'] = base + '''public class MainActivity extends android.app.Activity {
      @Override public void onCreate(android.os.Bundle state) { super.onCreate(state); try {
        Target target=new Target();
    ''' + registration + '''
        if(State.services!=1 || State.routes!=1 || target.value!=47 || Business.calc(7)!=52) throw new AssertionError("注册结果不一致");
        android.util.Log.i("RouterCompatProbe","THEROUTER_OK "+getIntent().getStringExtra("token"));
      } catch(Exception e) { throw new RuntimeException(e); } }
    }'''
    files = []
    for name, source in sources.items():
        path = directory / (name + '.java')
        path.write_text(source)
        files.append(path)
    run(['javac', '--release', '8', '-cp', android, '-d', classes, *files])
    run(['jar', 'cf', directory / 'classes.jar', '-C', classes, '.'])
    run([bt / 'd8', '--release', '--lib', android, '--min-api', '21', '--output', dex, directory / 'classes.jar'])
    manifest = directory / 'AndroidManifest.xml'
    manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="' + PACKAGE + '"><uses-sdk android:minSdkVersion="21" android:targetSdkVersion="35"/><application android:label="路由兼容回归"><activity android:name=".MainActivity" android:exported="true"/></application></manifest>')
    run([bt / 'aapt2', 'link', '-o', directory / 'base.apk', '--manifest', manifest, '-I', android])
    with zipfile.ZipFile(directory / 'base.apk') as base_apk, zipfile.ZipFile(directory / 'unsigned.apk', 'w') as output:
        for item in base_apk.infolist():
            output.writestr(item, base_apk.read(item.filename))
        output.write(dex / 'classes.dex', 'classes.dex')
    original, protected = directory / 'input.apk', directory / 'protected.apk'
    sign(directory / 'unsigned.apk', original)
    command = [args.cli, 'protect', '-i', original, '-o', protected,
               '--resources', ROOT / 'shield-stub/build/outputs/resources/resources.zip',
               '--apktool', ROOT / 'tools/apktool_3.0.3.jar', '--apksigner', ROOT / 'tools/apksigner.jar',
               '--profile', 'strict', '--ai-resistance', 'high', '--environment-policy', 'strict',
               '--xop-pvm2-packer', ROOT / 'tools/xop-pvm2-packer.jar',
               '--xop-true-vmp-prefix', 'L' + PACKAGE.replace('.', '/') + '/Business;']
    output = run(command, check=mode != 'unknown')
    if mode == 'unknown':
        assert 'THEROUTER_REGISTRATION_UNRESOLVED' in output and not protected.exists()
        results.append({'mode': mode, 'result': 'rejected'})
        continue
    sign(protected, directory / 'signed.apk')
    report = json.loads((directory / 'signed.apk.protection.json').read_text())
    assert report['output_sha256'] == hashlib.sha256((directory / 'signed.apk').read_bytes()).hexdigest()
    assert any(row['descriptor'].endswith('->calc(I)I') and row['artifact_verified'] for row in report['methods'])
    with zipfile.ZipFile(protected) as apk:
        assert ('assets/therouter_registry.txt' in apk.namelist()) == (mode == 'index')
    scenarios = []
    installed = False
    try:
        if adb:
            for scenario, apk in [('baseline', original), ('first', directory / 'signed.apk'), ('cached', None)]:
                if apk:
                    assert 'Success' in run(adb + ['install', '-r', apk])
                    installed = True
                run(adb + ['shell', 'am', 'force-stop', PACKAGE])
                token = uuid.uuid4().hex
                run(adb + ['shell', 'am', 'start', '-W', '-n', PACKAGE + '/.MainActivity', '--es', 'token', token])
                logs = ''
                for _ in range(10):
                    logs = run(adb + ['logcat', '-d', '-s', 'RouterCompatProbe:I', 'AndroidRuntime:E', '*:S'])
                    if 'THEROUTER_OK ' + token in logs:
                        break
                    time.sleep(1)
                (directory / (scenario + '.log')).write_text(logs)
                assert 'THEROUTER_OK ' + token in logs, mode + '/' + scenario
                assert run(adb + ['shell', 'pidof', PACKAGE]).strip()
                scenarios.append(scenario)
    finally:
        if installed:
            assert 'Success' in run(adb + ['uninstall', PACKAGE])
    results.append({'mode': mode, 'result': 'passed', 'scenarios': scenarios})
    print(mode + '：加固、签名、注册与 PVM2 检查通过', flush=True)
(work / 'result.json').write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n')
print('TheRouter 兼容回归通过，未知注册模式保持拒绝。')
