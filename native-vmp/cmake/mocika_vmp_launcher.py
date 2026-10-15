#!/usr/bin/env python3
"""以同版本 LLVM 转换 CMake 编译输入，并原子发布对象及编译证据。"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

SOURCE_SUFFIXES = {'.c', '.cc', '.cpp', '.cxx', '.m', '.mm'}


def response_tokens(text: str, windows: bool) -> list[str]:
    if windows:
        # 复用宿主的 Windows 引号/反斜杠规则，不用 POSIX shell 拆 Windows 路径。
        from ctypes import wintypes
        parser = ctypes.windll.shell32.CommandLineToArgvW
        parser.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
        parser.restype = ctypes.POINTER(wintypes.LPWSTR)
        count = ctypes.c_int()
        args = parser('clang ' + text, ctypes.byref(count))
        if not args:
            raise ValueError('无法解析 Windows 响应文件')
        try:
            return list(args[1:count.value])
        finally:
            ctypes.windll.kernel32.LocalFree.argtypes = [ctypes.c_void_p]
            ctypes.windll.kernel32.LocalFree(args)
    # LLVM GNU 响应文件的反斜杠在引号内外都转义下一字符；不是 shell 展开。
    result, token, quote, escaped, started = [], [], None, False, False
    for char in text:
        if escaped:
            token.append(char); escaped = False
        elif char == '\\':
            escaped = True; started = True
        elif quote:
            if char == quote: quote = None
            else: token.append(char)
        elif char in "\"'":
            quote = char; started = True
        elif char.isspace():
            if started: result.append(''.join(token))
            token, started = [], False
        else:
            token.append(char); started = True
    if quote or escaped: raise ValueError('响应文件存在未闭合引号或转义')
    if started: result.append(''.join(token))
    return result


def expand_response(arguments: list[str], active=(), windows=None) -> list[str]:
    if windows is None:
        mode = next((a.split('=', 1)[1] for a in arguments if a.startswith('--rsp-quoting=')), None)
        if mode not in (None, 'windows', 'posix'): raise ValueError('未知响应文件引号模式')
        windows = mode == 'windows' or (mode is None and os.name == 'nt')
        if windows and os.name != 'nt': raise ValueError('Windows 响应文件需要 Windows 宿主')
    expanded = []
    for arg in arguments:
        if not arg.startswith('@'):
            expanded.append(arg); continue
        path = Path(arg[1:]).resolve()
        if path in active or len(active) >= 16: raise ValueError('响应文件循环或嵌套过深')
        data = path.read_bytes()
        if len(data) > 1024 * 1024: raise ValueError('响应文件超过 1 MiB')
        encoding = 'utf-16' if data.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig'
        text = data.decode(encoding)
        if '\x00' in text: raise ValueError('响应文件包含空字节')
        expanded.extend(expand_response(response_tokens(text, windows), active + (path,), windows))
        if len(expanded) > 100000: raise ValueError('编译参数超过预算')
    return expanded


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def version(tool):
    text = subprocess.check_output([tool, '--version'], text=True)
    match = re.search(r'(?:clang|LLVM) version (\d+)\.', text)
    if not match or int(match[1]) != 21: raise ValueError('Native VMP 编译器与 opt 必须同为 LLVM 21')
    return text.splitlines()[0]


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--opt', required=True)
    parser.add_argument('--plugin', required=True)
    options, command = parser.parse_known_args(argv)
    if command and command[0] == '--': command.pop(0)
    if not command: raise ValueError('缺少编译命令')
    command = [command[0], *expand_response(command[1:])]
    # 此入口只属于编译启动器；不识别的编译形式必须拒绝，不能直接交回 Clang。
    if '-c' not in command or command.count('-o') != 1: raise ValueError('需要单源文件 -c/-o 编译命令')
    if any(a.startswith(('-flto', '-fpass-plugin', '-fembed-bitcode')) or a in ('-emit-llvm', '-S', '-E', '-Xclang', '-mllvm', '--config') or a.startswith('--config=') for a in command):
        raise ValueError('Native VMP 不接受 LTO、额外 Pass 或隐藏的编译阶段选项')
    source_positions = []
    skip = False
    # 跳过带文件路径的选项，不能把 -include helper.c 当作编译输入。
    value_options = {'-o', '-MF', '-MT', '-MQ', '-I', '-isystem', '-iquote', '-include', '-imacros', '-isysroot', '--sysroot', '-target', '--target', '-x', '-arch', '-D', '-U'}
    for index in range(1, len(command)):
        arg = command[index]
        if skip: skip = False; continue
        if arg in value_options:
            if index+1 == len(command): raise ValueError('编译选项缺少参数：'+arg)
            skip = True; continue
        if not arg.startswith('-') and Path(arg).suffix.lower() in SOURCE_SUFFIXES:
            source_positions.append(index)
    if len(source_positions) != 1: raise ValueError('无法确定唯一 C/C++ 编译输入')
    source_at = source_positions[0]
    final_output = Path(command[command.index('-o') + 1]).resolve()
    source = Path(command[source_at]).resolve()
    compiler_version, opt_version = version(command[0]), version(options.opt)
    final_output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='mocika-vmp-', dir=final_output.parent) as directory:
        work = Path(directory)
        original, transformed, output = work/'original.bc', work/'transformed.bc', work/'object.o'
        emit = list(command); emit[emit.index('-o')+1] = str(original)
        # 依赖文件仍指向正式对象，而不是随后删除的临时 bitcode。
        if not any(a.startswith(('-MT', '-MQ')) for a in emit): emit += ['-MQ', str(final_output)]
        # 禁止前端先传播标注函数的常量/原始计算；普通优化在原体替换后执行。
        run(emit + ['-Xclang', '-disable-llvm-passes', '-emit-llvm'])
        pass_report = work/'pass.json'
        run([options.opt, '--strip-debug', '-load-pass-plugin='+options.plugin, '-passes=mocika-native-vmp', str(original), '-o', str(transformed)],
            env=dict(os.environ, MOCIKA_VMP_COMPILE_REPORT=str(pass_report)))
        report = json.loads(pass_report.read_text())
        if report['schema_version'] != 1: raise ValueError('Native VMP Pass 报告不兼容')
        # 第二阶段只生成机器码，不能重复预包含源码或把 bitcode 强制当成 C/C++。
        object_args, skip = [], False
        for arg in command:
            if skip: skip = False; continue
            if arg in {'-MF', '-MT', '-MQ', '-include', '-imacros', '-x'}: skip = True; continue
            if arg.startswith(('-MF', '-MT', '-MQ', '-imacros', '-xc', '-xobjective-')): continue
            if arg.startswith('-include') and not arg.startswith('-include-'): continue
            if arg in {'-MD', '-MMD', '-MP'}: continue
            object_args.append(arg)
        object_args[object_args.index(command[source_at])] = str(transformed)
        object_args[object_args.index('-o')+1] = str(output)
        run(object_args + ['-Wno-unused-command-line-argument'])
        report.update(source=str(source), source_sha256=digest(source), object=str(final_output),
                      object_sha256=digest(output), original_bc_sha256=digest(original), transformed_bc_sha256=digest(transformed),
                      compiler=compiler_version, opt=opt_version, plugin_sha256=digest(options.plugin), launcher_sha256=digest(__file__),
                      config_sha256=hashlib.sha256(json.dumps(command, ensure_ascii=False).encode()).hexdigest())
        # 工具也是每个对象的依赖；只靠 CMake 重新配置会漏掉同一秒内的工具更新。
        depfile = None
        for index, arg in enumerate(command):
            if arg == '-MF': depfile = command[index+1]
            elif arg.startswith('-MF'): depfile = arg[3:]
        if depfile:
            def dependency_path(path):
                value = Path(path).resolve().as_posix()
                if '\n' in value or '\r' in value: raise ValueError('依赖路径不能包含换行')
                return value.replace('\\', '\\\\').replace('$', '$$').replace('#', '\\#').replace(' ', '\\ ')
            with open(depfile, 'a', encoding='utf-8') as dependencies:
                dependencies.write('\n'+dependency_path(final_output)+': '+
                    ' '.join(dependency_path(p) for p in (options.plugin, __file__))+'\n')
        receipt = work/'receipt.json'; receipt.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
        # 对象和报告使用摘要相互约束；进程在两个替换之间中断只会导致后续核验拒绝。
        os.replace(receipt, str(final_output)+'.mocika-vmp.json')
        os.replace(output, final_output)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        sys.exit('Native VMP 构建失败：'+str(error))
