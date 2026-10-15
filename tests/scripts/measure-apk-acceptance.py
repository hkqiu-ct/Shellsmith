#!/usr/bin/env python3
"""对独立测试包记录分块轮换的进程冷启动/PSS；只使用 Python 标准库和 Android 工具。"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import random
import re
import shlex
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone


def sha256(path):
    with Path(path).open('rb') as stream:
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def launch_time(text, component):
    fields = dict(re.findall(r'^(\w+):\s*(.*)$', text, re.M))
    if fields.get('Status') != 'ok' or fields.get('LaunchState') != 'COLD':
        raise ValueError('未取得正常进程冷启动：' + text)
    if fields.get('Activity') != component:
        raise ValueError('启动组件与预期不一致：' + text)
    value = int(fields.get('TotalTime', ''))
    if value <= 0:
        raise ValueError('启动时间必须大于零')
    return value


def capture_failure(adb, package, entry, save):
    entry['captured_at'] = datetime.now(timezone.utc).isoformat()
    save()
    # ponytail: 只保留末尾 400 条指定标签日志；长时间挂起需另行持续采集，不能据此排除未捕获的故障。
    for name, command in [('exit_info', ('shell', 'dumpsys', 'activity', 'exit-info', package)),
                          ('logcat', ('logcat', '-d', '-t', '400', '-v', 'threadtime',
                                      'ActivityManager:I', 'AndroidRuntime:E', 'libc:F', 'DEBUG:F', '*:S')),
                          ('crash_logcat', ('logcat', '-b', 'crash', '-d', '-t', '100', '-v', 'threadtime')),
                          ('uptime', ('shell', 'cat', '/proc/uptime'))]:
        try:
            entry[name] = adb(*command, timeout=10)
        except Exception as diagnostic_error:
            entry[name + '_error'] = str(diagnostic_error)
        save()

    # 厂商清理决策可能只写 main；按 system_server 进程取末尾日志，避免标签白名单漏证据。
    try:
        pid = adb('shell', 'pidof', 'system_server', timeout=10).strip()
        if not re.fullmatch(r'[1-9][0-9]*', pid):
            raise ValueError('无法唯一确定 system_server 进程')
        entry['system_server_logcat'] = adb('logcat', '-b', 'main', '-b', 'system', '-d',
                '-t', '400', '--pid=' + pid, '-v', 'threadtime', timeout=10)
    except Exception as diagnostic_error:
        entry['system_server_logcat_error'] = str(diagnostic_error)
    save()


def launch_once(adb, component, report, save, **identity):
    """先固定失败当时的诊断，再由调用者决定停止或重试；不清空设备日志。"""
    raw = ''
    entry = dict(identity, started_at=datetime.now(timezone.utc).isoformat(),
                 started_monotonic_ns=time.monotonic_ns(), status='running')
    report.setdefault('launches', []).append(entry)
    save()
    try:
        raw = adb('shell', 'am', 'start', '-W', '-n', component)
        elapsed = launch_time(raw, component)
        entry.update(status='measured', launch_ms=elapsed, raw_launch=raw)
        save()
        return elapsed, raw
    except (ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        entry.update(status='failed', raw_launch=raw, error=str(error))
        report['invalid_starts'].append(entry)
        capture_failure(adb, component.split('/', 1)[0], entry, save)
        raise


def summary(rows):
    result = {}
    for name in sorted({r['variant'] for r in rows}):
        group = [r for r in rows if r['variant'] == name]
        result[name] = {'samples': len(group)}
        for key in ('launch_ms', 'pss_kb', 'battery_temperature_tenths_c'):
            values = sorted(r[key] for r in group)
            result[name][key] = {'median': statistics.median(values),
                                 'p95': values[math.ceil(len(values) * .95) - 1],
                                 'min': values[0], 'max': values[-1]}
    return result


def self_test():
    component = 'dev.test.shieldtest/dev.test.Main'
    good = f'Status: ok\nLaunchState: COLD\nActivity: {component}\nTotalTime: 321\n'
    assert launch_time(good, component) == 321
    for bad in (good.replace('COLD', 'WARM'), good.replace('321', '0'),
                good.replace('Status: ok', 'Status: error'), good.replace('TotalTime: 321', '')):
        try:
            launch_time(bad, component)
        except ValueError:
            pass
        else:
            raise AssertionError('错误样本被接受')
    rows = [dict(variant='a', launch_ms=n, pss_kb=n, battery_temperature_tenths_c=n) for n in range(1, 31)]
    assert summary(rows)['a']['launch_ms'] == dict(median=15.5, p95=29, min=1, max=30)
    for failure in (good.replace('COLD', 'UNKNOWN'), RuntimeError('设备不可用'),
                    subprocess.TimeoutExpired('am start', 120)):
        report = {'invalid_starts': []}
        saves, commands = [], []
        def fake_adb(*command, **kwargs):
            commands.append(command)
            if command[:3] == ('shell', 'am', 'start'):
                if isinstance(failure, Exception): raise failure
                return failure
            if command == ('shell', 'pidof', 'system_server'): return '2580\n'
            if command[0] == 'logcat': raise RuntimeError('诊断日志不可读')
            return '退出证据'
        try:
            launch_once(fake_adb, component, report, lambda: saves.append(True), phase='sample')
            raise AssertionError('启动失败没有上抛')
        except (ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
            if isinstance(failure, Exception): assert error is failure
        assert len(report['invalid_starts']) == 1 and len(saves) == 7
        entry = report['invalid_starts'][0]
        assert report['launches'] == [entry] and entry['status'] == 'failed'
        assert entry['started_monotonic_ns'] > 0 and entry['started_at']
        assert entry['exit_info'] == '退出证据' and entry['logcat_error'] == '诊断日志不可读'
        assert entry['crash_logcat_error'] == '诊断日志不可读'
        assert entry['system_server_logcat_error'] == '诊断日志不可读'
        assert any('--pid=2580' in c and 'main' in c and 'system' in c for c in commands)
        assert not any('force-stop' in c or '-c' in c for c in commands)
    report, saves = {'invalid_starts': []}, []
    assert launch_once(lambda *a, **k: good, component, report, lambda: saves.append(True), phase='sample') == (321, good)
    assert not report['invalid_starts'] and len(saves) == 2
    assert report['launches'][0]['launch_ms'] == 321 and report['launches'][0]['status'] == 'measured'
    for pid in ('2580', '2580 2581'):
        commands, entry = [], {}
        def diagnostic_adb(*command, **kwargs):
            commands.append(command)
            return pid if command == ('shell', 'pidof', 'system_server') else '厂商决策日志'
        capture_failure(diagnostic_adb, 'dev.test.shieldtest', entry, lambda: None)
        if pid == '2580':
            assert entry['system_server_logcat'] == '厂商决策日志'
        else:
            assert 'system_server_logcat_error' in entry
            assert not any(any(arg.startswith('--pid=') for arg in c) for c in commands)
    with tempfile.TemporaryDirectory() as directory:
        invalid = subprocess.run([sys.executable, __file__, '--adb', 'missing-adb', '--aapt2', 'missing-aapt2',
                                  '--apksigner', 'missing.jar', '--serial', 'test', '--package', 'dev.test.shieldtest',
                                  '--component', 'dev.test.shieldtest/Bad;false', '--apk', 'a=missing.apk',
                                  '--apk', 'b=missing.apk', '--output', str(Path(directory) / 'report.json')],
                                 capture_output=True, text=True)
        assert invalid.returncode == 2 and '组件' in invalid.stderr
    print('验收统计自检通过')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--self-test', action='store_true')
    p.add_argument('--adb', default='adb')
    p.add_argument('--aapt2')
    p.add_argument('--apksigner')
    p.add_argument('--serial')
    p.add_argument('--package')
    p.add_argument('--component')
    p.add_argument('--apk', action='append', default=[], metavar='NAME=PATH')
    p.add_argument('--output', type=Path)
    p.add_argument('--samples', type=int, default=30)
    p.add_argument('--block', type=int, default=5)
    p.add_argument('--interval-seconds', type=float, default=12, help='每次停止后等待秒数，默认 12；设备高频重启策略需要预先校准')
    p.add_argument('--resume', action='store_true', help='核对输入与参数后继续已有部分记录')
    p.add_argument('--max-invalid-starts', type=int, default=0, help='显式允许的无计时启动次数；仍记录为异常，不判稳定性通过')
    args = p.parse_args()
    if args.self_test:
        self_test()
        return
    if not all((args.aapt2, args.apksigner, args.serial, args.package, args.component, args.output)) or len(args.apk) < 2:
        p.error('需要工具路径、设备、测试包、组件、输出文件和至少两个 APK')
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\.shieldtest', args.package):
        p.error('只接受显式以 .shieldtest 结尾的独立测试包')
    if (not re.fullmatch(re.escape(args.package) + r'/[A-Za-z_$][A-Za-z0-9_.$]*', args.component)
            or args.samples < 5 or args.block < 1 or args.samples % args.block):
        p.error('组件或样本/分块参数无效')
    if args.output.exists() and not args.resume:
        p.error('输出文件已存在，拒绝覆盖')
    if args.resume and not args.output.is_file():
        p.error('没有可继续的记录')
    if args.max_invalid_starts < 0 or args.max_invalid_starts > 5:
        p.error('无效启动预算必须在 0 到 5 之间')
    if not math.isfinite(args.interval_seconds) or args.interval_seconds < 1:
        p.error('采样间隔至少为 1 秒')

    def run(command, timeout=120, missing_ok=False):
        done = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        if done.returncode and not (missing_ok and done.returncode == 1):
            raise RuntimeError(done.stdout + done.stderr)
        return done.stdout

    def adb(*command, timeout=120, missing_ok=False):
        if command[0] == 'shell':
            command = ('shell', shlex.join(command[1:]))
        return run([args.adb, '-s', args.serial, *command], timeout, missing_ok)

    apks, certs = {}, set()
    for entry in args.apk:
        name, path = entry.split('=', 1)
        if not re.fullmatch(r'[a-zA-Z0-9_-]+', name) or name in apks:
            p.error('配置名称无效或重复')
        badging = run([args.aapt2, 'dump', 'badging', path])
        if re.search(r"^package: name='([^']+)'", badging, re.M).group(1) != args.package:
            p.error('APK 包名与独立测试包不一致')
        signatures = run(['java', '-jar', args.apksigner, 'verify', '--print-certs', path])
        cert = sorted(set(re.findall(r'^.*certificate SHA-256 digest: ([0-9a-fA-F]{64})$', signatures, re.M)))
        if len(cert) != 1:
            p.error('当前检查要求单签名 APK')
        certs.add(cert[0])
        apks[name] = dict(path=str(Path(path).resolve()), sha256=sha256(path), bytes=Path(path).stat().st_size)
    if len(certs) != 1:
        p.error('对照 APK 签名不一致')
    installed = adb('shell', 'pm', 'path', args.package, missing_ok=True).strip()
    if installed:
        paths = installed.splitlines()
        if len(paths) != 1 or not paths[0].startswith('package:'):
            p.error('不覆盖已有 split 应用')
        with tempfile.TemporaryDirectory(prefix='apk-acceptance-') as temp:
            old = Path(temp) / 'installed.apk'
            adb('pull', paths[0][8:], str(old))
            if sha256(old) not in {v['sha256'] for v in apks.values()}:
                p.error('设备上已有不同测试包，拒绝覆盖或清数据')
    report = dict(schema_version=1, package=args.package, component=args.component,
                  serial=args.serial, fingerprint=adb('shell', 'getprop', 'ro.build.fingerprint').strip(),
                  signer_sha256=next(iter(certs)), apks=apks, samples_per_variant=args.samples,
                  block=args.block, interval_seconds=args.interval_seconds, seed=20261014, compilation='reset_then_verify',
                  scope='进程冷启动到指定首屏；1 秒后主进程 PSS；不代表 TTFD、峰值内存或业务 SLA',
                  rows=[], blocks=[], warmups=[], launches=[], invalid_starts=[], status='running')
    if args.resume:
        previous = json.loads(args.output.read_text())
        for key in ('schema_version', 'package', 'component', 'serial', 'fingerprint', 'signer_sha256',
                    'apks', 'samples_per_variant', 'block', 'interval_seconds', 'seed', 'compilation'):
            if previous.get(key) != report[key]:
                p.error('继续记录的输入或参数不同：' + key)
        if previous['status'] != 'failed':
            p.error('只能继续失败的部分记录')
        seen = set()
        for row in previous['rows']:
            identity = (row['variant'], row['block'], row['sample'])
            if (identity in seen or row['variant'] not in apks or not 0 <= row['block'] < args.samples // args.block
                    or not 0 <= row['sample'] < args.block or row['launch_ms'] <= 0 or row['pss_kb'] <= 0):
                p.error('已有样本无效或重复')
            seen.add(identity)
        report = previous
        report.setdefault('invalid_starts', []).append({'phase': 'previous_run', 'error': report.pop('error', '未知失败')})
        report['status'] = 'running'
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def save():
        report['summary'] = summary(report['rows'])
        file = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=args.output.parent, delete=False)
        pending = Path(file.name)
        try:
            with file:
                file.write(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
            pending.replace(args.output)
        finally:
            pending.unlink(missing_ok=True)

    def start_activity(name, block, sample, phase):
        while True:
            try:
                return launch_once(adb, args.component, report, save,
                                   variant=name, block=block, sample=sample, phase=phase)
            except ValueError:
                start = report['invalid_starts'][-1]['raw_launch']
                if 'LaunchState: UNKNOWN' not in start or 'TotalTime:' in start or len(report['invalid_starts']) > args.max_invalid_starts:
                    raise
                print('记录无计时启动，冷却 30 秒后重试；不计为稳定性通过', flush=True)
                adb('shell', 'am', 'force-stop', args.package)
                time.sleep(30)

    randomizer = random.Random(report['seed'])
    try:
        for block in range(args.samples // args.block):
            names = list(apks)
            randomizer.shuffle(names)
            for name in names:
                completed = [r['sample'] for r in report['rows'] if r['variant'] == name and r['block'] == block]
                if sorted(completed) != list(range(len(completed))):
                    raise RuntimeError('已有分块样本不连续')
                if len(completed) == args.block:
                    continue
                print(f'第 {block + 1} 轮，{name}', flush=True)
                adb('shell', 'am', 'force-stop', args.package)
                installed = adb('install', '--no-incremental', '-r', apks[name]['path'])
                if 'Success' not in installed or adb('shell', 'pm', 'clear', args.package).strip() != 'Success':
                    raise RuntimeError('测试包安装或清理失败')
                reset = adb('shell', 'cmd', 'package', 'compile', '--reset', args.package)
                verify = adb('shell', 'cmd', 'package', 'compile', '-f', '-m', 'verify', args.package)
                if 'Success' not in reset or 'Success' not in verify:
                    raise RuntimeError('无法统一编译状态')
                # ponytail: 只测已建立缓存后的进程冷启动；每块 3 次预热，不冒充清缓存首启。
                for warmup in range(3):
                    adb('shell', 'am', 'force-stop', args.package)
                    time.sleep(args.interval_seconds)
                    elapsed, start = start_activity(name, block, warmup, 'warmup')
                    report.setdefault('warmups', []).append(dict(variant=name, block=block, warmup=warmup,
                            first_after_clear=warmup == 0, launch_ms=elapsed, raw_launch=start))
                    save()
                    time.sleep(1)
                report['blocks'].append(dict(block=block, variant=name, reset=reset, verify=verify))
                for sample in range(len(completed), args.block):
                    power = adb('shell', 'dumpsys', 'power')
                    window = adb('shell', 'dumpsys', 'window', 'policy')
                    if 'mWakefulness=Awake' not in power or not re.search(r'^\s*showing=false\s*$', window, re.M):
                        raise RuntimeError('屏幕未唤醒或处于锁屏，停止采样')
                    thermal = adb('shell', 'dumpsys', 'thermalservice')
                    match = re.search(r'Thermal Status:\s*(\d+)', thermal)
                    if not match or int(match[1]) >= 2:
                        raise RuntimeError('热状态未知或达到 MODERATE，停止采样')
                    battery = adb('shell', 'dumpsys', 'battery')
                    temperature = int(re.search(r'^\s*temperature:\s*(-?\d+)', battery, re.M)[1])
                    adb('shell', 'am', 'force-stop', args.package)
                    if adb('shell', 'pidof', args.package, missing_ok=True).strip():
                        raise RuntimeError('进程未停止')
                    time.sleep(args.interval_seconds)
                    elapsed, start = start_activity(name, block, sample, 'sample')
                    time.sleep(1)
                    pid = adb('shell', 'pidof', args.package).strip()
                    if not re.fullmatch(r'\d+', pid):
                        raise RuntimeError('目标主进程不存在或不唯一')
                    memory = adb('shell', 'dumpsys', 'meminfo', pid)
                    pss = re.search(r'TOTAL PSS:\s*(\d+)', memory)
                    if not pss:
                        raise RuntimeError('无法读取主进程 PSS')
                    report['rows'].append(dict(variant=name, block=block, sample=sample,
                                              launch_ms=elapsed, pss_kb=int(pss[1]), pid=int(pid),
                                              thermal_status=int(match[1]),
                                              battery_temperature_tenths_c=temperature, raw_launch=start))
                    save()
        report['status'] = 'measured_with_invalid_starts' if report['invalid_starts'] else 'measured'
    except BaseException as error:
        report['status'] = 'failed'
        report['error'] = str(error)
        if not report['invalid_starts'] or report['invalid_starts'][-1].get('error') != str(error):
            report['failure_diagnostics'] = dict(error=str(error))
            capture_failure(adb, args.package, report['failure_diagnostics'], save)
        raise
    finally:
        try:
            adb('shell', 'am', 'force-stop', args.package)
        finally:
            save()


if __name__ == '__main__':
    main()
