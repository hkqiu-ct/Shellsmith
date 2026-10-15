#!/usr/bin/env python3
"""用同一 LLVM IR 的原生/虚拟实现核对标量语义，另做可复用恢复检查；不依赖业务方法。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--plugin', required=True)
parser.add_argument('--llvm-bin', required=True)
parser.add_argument('--output', required=True)
parser.add_argument('--cc', help='可选 NDK Clang；指定后以 --serial 在 Android 运行')
parser.add_argument('--serial')
args = parser.parse_args()
assert bool(args.cc) == bool(args.serial)
root = Path(__file__).resolve().parents[1]
work = Path(args.output).resolve(); work.mkdir(parents=True, exist_ok=True)
# 失败的本轮不能留下上一轮成功的摘要；原始生成文件保留用于诊断。
(work/'result.json').unlink(missing_ok=True)
llvm = Path(args.llvm_bin)
cc = args.cc or ('/usr/bin/clang' if sys.platform == 'darwin' else str(llvm/'clang'))
# 由目标 C 编译器声明窄整数 ABI；Darwin/ARMv7 的 zeroext 不能套到 Android ARM64。
abi_ir = subprocess.check_output([cc, '-S', '-emit-llvm', '-x', 'c', '-', '-o', '-'], text=True, timeout=30,
    input='_Bool abi_i1(_Bool x) {return x;}\nunsigned char abi_i8(unsigned char x) {return x;}\n')
abi = {ty: ('zeroext ' if 'zeroext' in ret else '', 'zeroext ' if 'zeroext' in param else '')
       for ret, ty, param in re.findall(r'^define (.*?) @abi_(i1|i8)\((.*?)\)', abi_ir, re.M)}
assert set(abi) == {'i1', 'i8'}, '无法确定目标编译器的窄整数 ABI'
(work/'abi.ll').write_text(abi_ir)
functions, prototypes, checks, annotations = [], [], [], []
ctype = {'float': 'float', 'double': 'double', 'i1': '_Bool', 'i8': 'uint8_t', 'i32': 'uint32_t', 'i64': 'uint64_t'}


def add(name, ret, params, body, call, exact=False):
    for prefix in ('ref', 'vmp'):
        symbol = prefix+'_'+name
        abi_ret = abi.get(ret, ('', ''))[0]+ret
        abi_params = re.sub(r'\b(i1|i8) %', lambda m: m[1]+' '+abi[m[1]][1]+'%', params)
        functions.append(f'define {abi_ret} @{symbol}({abi_params}) noinline {{\n{body}\n}}')
        prototypes.append(f'{ctype[ret]} {symbol}('+', '.join(ctype[p.split()[0]] for p in params.split(', '))+');')
    annotations.append('{ptr, ptr, ptr, i32, ptr} {ptr @vmp_'+name+', ptr @tag, ptr @file, i32 1, ptr null}')
    equal = (f'bits{32 if ret == "float" else 64}(ref_{name}({call})) == bits{32 if ret == "float" else 64}(vmp_{name}({call}))' if exact else
             f'equal{32 if ret == "float" else 64}(ref_{name}({call}), vmp_{name}({call}))' if ret in ('float', 'double') else
             f'ref_{name}({call}) == vmp_{name}({call})')
    checks.append(f'CHECK({equal}, "{name}");')


for ty, short in [('float', 'f32'), ('double', 'f64')]:
    a, b = ('af', 'bf') if ty == 'float' else ('ad', 'bd')
    for op in ('fadd', 'fsub', 'fmul', 'fdiv', 'frem'):
        add(short+'_'+op, ty, f'{ty} %a, {ty} %b', f'  %r = {op} {ty} %a, %b\n  ret {ty} %r', a+', '+b)
    for intrinsic in ('fma', 'fmuladd'):
        functions.append(f'declare {ty} @llvm.{intrinsic}.{short}({ty}, {ty}, {ty})')
        add(short+'_'+intrinsic, ty, f'{ty} %a, {ty} %b', f'  %r = call {ty} @llvm.{intrinsic}.{short}({ty} %a, {ty} %b, {ty} %a)\n  ret {ty} %r', a+', '+b)
        if intrinsic == 'fmuladd':
            # LLVM 允许融合或两次舍入；ARMv7 原生通常分步，不能用单一位模式误判另一合法结果。
            width, math = (32, 'fmaf') if ty == 'float' else (64, 'fma')
            checks[-1] = f'CHECK(equal{width}(ref_{short}_{intrinsic}({a},{b}),vmp_{short}_{intrinsic}({a},{b})) || equal{width}({math}({a},{b},{a}),vmp_{short}_{intrinsic}({a},{b})), "{short}_{intrinsic}");'

    for predicate in ('false', 'oeq', 'ogt', 'oge', 'olt', 'ole', 'one', 'ord', 'uno', 'ueq', 'ugt', 'uge', 'ult', 'ule', 'une', 'true'):
        add(short+'_'+predicate, 'i1', f'{ty} %a, {ty} %b', f'  %r = fcmp {predicate} {ty} %a, %b\n  ret i1 %r', a+', '+b)
    add(short+'_neg', ty, f'{ty} %a', f'  %r = fneg {ty} %a\n  ret {ty} %r', a, True)
    add(short+'_select', ty, f'{ty} %a, {ty} %b', f'  %c = fcmp ogt {ty} %a, %b\n  %r = select i1 %c, {ty} %a, {ty} %b\n  ret {ty} %r', a+', '+b, True)
    add(short+'_loop', ty, f'{ty} %a, {ty} %b', f'''entry:
  br label %loop
loop:
  %i = phi i32 [0, %entry], [%next, %loop]
  %x = phi {ty} [%a, %entry], [%sum, %loop]
  %sum = fadd {ty} %x, %b
  %next = add i32 %i, 1
  %again = icmp ult i32 %next, 5
  br i1 %again, label %loop, label %exit
exit:
  ret {ty} %sum''', a+', '+b)
    for width in (32, 64):
        for op in ('sitofp', 'uitofp'):
            add(short+'_'+op+str(width), ty, f'i{width} %a', f'  %r = {op} i{width} %a to {ty}\n  ret {ty} %r', f'(uint{width}_t)state')
        for op in ('fptosi', 'fptoui'):
            # 语义对照仅调用定义域内输入；越界由单独运行时拒绝检查覆盖。
            value = f'({ctype[ty]})((int32_t)(state % 100000) - 50000)' if op == 'fptosi' else f'({ctype[ty]})(state % 100000)'
            add(short+'_'+op+str(width), 'i'+str(width), f'{ty} %a', f'  %r = {op} {ty} %a to i{width}\n  ret i{width} %r', value)
    width = 32 if ty == 'float' else 64
    add(short+'_bits', 'i'+str(width), f'{ty} %a', f'  %r = bitcast {ty} %a to i{width}\n  ret i{width} %r', a)
    add(short+'_frombits', ty, f'i{width} %a', f'  %r = bitcast i{width} %a to {ty}\n  ret {ty} %r', f'(uint{width}_t)state', True)
add('extend', 'double', 'float %a', '  %r = fpext float %a to double\n  ret double %r', 'af')
add('truncate', 'float', 'double %a', '  %r = fptrunc double %a to float\n  ret float %r', 'ad')
# 两输入漏斗移位和同输入循环移位；j 覆盖零、位宽及其倍数，窄整数另覆盖截断。
for width in (1, 8, 32, 64):
    ty = 'i'+str(width)
    for intrinsic in ('fshl', 'fshr'):
        functions.append(f'declare {ty} @llvm.{intrinsic}.{ty}({ty}, {ty}, {ty})')
        for rotate in (False, True):
            name = intrinsic+str(width)+('_rotate' if rotate else '')
            rhs = '%a' if rotate else '%b'
            add(name, ty, f'{ty} %a, {ty} %b, {ty} %s',
                f'  %r = call {ty} @llvm.{intrinsic}.{ty}({ty} %a, {ty} {rhs}, {ty} %s)\n  ret {ty} %r',
                f'({ctype[ty]})(i<16?integers[i]:state), ({ctype[ty]})(state*73), ({ctype[ty]})j')
# 每种位宽分别包含连续/稀疏 case、共享目标、默认路径、符号边界及循环回边。
for width in (8, 32, 64):
    ty = 'i'+str(width)
    for intrinsic in ('smin', 'smax', 'umin', 'umax'):
        functions.append(f'declare {ty} @llvm.{intrinsic}.{ty}({ty}, {ty})')
        add(intrinsic+str(width), ty, f'{ty} %a, {ty} %b',
            f'  %r = call {ty} @llvm.{intrinsic}.{ty}({ty} %a, {ty} %b)\n  ret {ty} %r',
            f'(uint{width}_t)(i<16?integers[i]:state), (uint{width}_t)(j<16?integers[j]:state*73)')
    for dense in (True, False):
        cases = [-3, -2, -1, 0, 1, 2] if dense else [-(1 << (width-1)), -1, 0, 17, 73, (1 << (width-1))-1]
        name = 'switch_'+str(width)+('_dense' if dense else '_sparse')
        add(name, ty, f'{ty} %a, {ty} %b', f'''entry:
  switch {ty} %a, label %fallback [
    {ty} {cases[0]}, label %low
    {ty} {cases[1]}, label %low
    {ty} {cases[2]}, label %middle
    {ty} {cases[3]}, label %top
    {ty} {cases[4]}, label %top
    {ty} {cases[5]}, label %bottom
  ]
low:
  %x = add {ty} %b, 19
  br label %join
middle:
  %y = mul {ty} %b, 5
  br label %join
top:
  %z = xor {ty} %b, -1
  br label %join
bottom:
  %w = sub {ty} %b, 73
  br label %join
fallback:
  %d = xor {ty} %a, %b
  br label %join
join:
  %r = phi {ty} [%x, %low], [%y, %middle], [%z, %top], [%w, %bottom], [%d, %fallback]
  ret {ty} %r''', f'(uint{width}_t)(i<16?integers[i]:state), (uint{width}_t)(j<16?integers[j]:state*73)')
    add('switch_'+str(width)+'_loop', ty, f'{ty} %a, {ty} %b', f'''entry:
  br label %loop
loop:
  %i = phi {ty} [0, %entry], [%next, %join]
  %x = phi {ty} [%a, %entry], [%r, %join]
  %selector = and {ty} %x, 7
  switch {ty} %selector, label %fallback [{ty} 0, label %low {ty} 1, label %low {ty} 3, label %high {ty} 5, label %high]
low:
  %l = add {ty} %x, %b
  br label %join
high:
  %h = xor {ty} %x, 73
  br label %join
fallback:
  %d = sub {ty} %x, 1
  br label %join
join:
  %r = phi {ty} [%l, %low], [%h, %high], [%d, %fallback]
  %next = add {ty} %i, 1
  %again = icmp ult {ty} %next, 5
  br i1 %again, label %loop, label %exit
exit:
  ret {ty} %r''', f'(uint{width}_t)(i<16?integers[i]:state), (uint{width}_t)(j<16?integers[j]:state*73)')
source = work/'scalars.ll'
triple = subprocess.check_output([args.cc or str(llvm/'clang'), '-dumpmachine'], text=True).strip()
source.write_text(f'target triple = "{triple}"\n'+'source_filename = "mocika-scalar-check"\n@tag = private constant [11 x i8] c"mocika_vmp\\00"\n@file = private constant [8 x i8] c"test.ll\\00"\n'
                  +f'@llvm.global.annotations = appending global [{len(annotations)} x {{ptr, ptr, ptr, i32, ptr}}] ['+',\n'.join(annotations)+'], section "llvm.metadata"\n'+'\n'.join(functions))


def run(command, **kw):
    result = subprocess.run([str(c) for c in command], text=True, capture_output=True, timeout=180, **kw)
    if result.returncode: raise RuntimeError(result.stdout+result.stderr)
    return result.stdout


def recover(program):
    """按公开格式解码并统一 opcode；故意证明编码不构成保密。"""
    assert program[:5] == b'MVMP\x02'
    seed = int.from_bytes(program[10:18], 'little'); data = bytearray(program); mask = (1 << 64)-1
    for i in range(18, len(data)):
        x = (seed+i*0x9e3779b97f4a7c15) & mask
        x = ((x ^ (x >> 30))*0xbf58476d1ce4e5b9) & mask
        x = ((x ^ (x >> 27))*0x94d049bb133111eb) & mask
        data[i] ^= (x ^ (x >> 31)) & 255
    pc, ops = 18, set()
    def value(pc):
        assert data[pc] in (0, 1)
        return pc+(9 if data[pc] else 3)
    while pc < len(data):
        op = data[pc] ^ data[5]; data[pc] = op; ops.add(op); pc += 1
        if op == 1: pc += 2
        elif op == 2:
            count = int.from_bytes(data[pc+3:pc+5], 'little'); pc += 5
            for _ in range(count): pc = value(pc+2)
        elif op in range(3, 16) or op in range(24, 29): pc = value(value(pc+3))
        elif op in (16, 30): pc = value(value(pc+4))
        elif op in (17, 38): pc = value(value(value(pc+3)))
        elif op in (18, 19, 20) or op in range(31, 38): pc = value(pc+4)
        elif op == 21: pc += 4
        elif op == 22: pc = value(pc)+8
        elif op == 23: pc = value(pc+1)
        elif op == 29: pc = value(pc+3)
        else: raise AssertionError(op)
    assert pc == len(data)
    return bytes(data[18:]), ops


variants, raw_variants, programs, opcode_set = [], [], None, set()
for seed in ('scalar-check-A', 'scalar-check-B'):
    transformed = work/(seed+'.ll')
    env = dict(os.environ, MOCIKA_VMP_SEED=seed, MOCIKA_VMP_COMPILE_REPORT=str(work/(seed+'.json')))
    run([llvm/'opt', '-load-pass-plugin='+args.plugin, '-passes=mocika-native-vmp', '-S', source, '-o', transformed], env=env)
    text = transformed.read_text()
    found = re.findall(r'@(__mocika_vmp_program_[^ ]+) = private constant \[\d+ x i8\] c"([^\"]*)"', text)
    assert len(found) == len(annotations), (len(found), len(annotations))
    parsed = {}
    for name, escaped in found:
        raw = bytearray(); i = 0
        while i < len(escaped):
            if escaped[i:i+2] == '\\\\': raw.append(92); i += 2
            elif escaped[i] == '\\': raw.append(int(escaped[i+1:i+3], 16)); i += 3
            else: raw.append(ord(escaped[i])); i += 1
        decoded, ops = recover(raw); parsed[name] = decoded; opcode_set |= ops
    variants.append(parsed)
    raw_variants.append(found)
    if programs is None: programs = found
    # 参数擦除必须在优化后的 IR 中保留，且发生在返回/失败分支之前。
    assert text.count('i1 true)') >= len(annotations), '缺少 volatile 参数擦除'
assert raw_variants[0] != raw_variants[1], '构建种子未改变实际字节码'
assert variants[0] == variants[1], '独立恢复器应能消除每次构建的位置编码'
assert set(range(24, 39)) <= opcode_set, opcode_set
# 旧格式与越界输入直接交给生产运行时，覆盖拒绝路径而非只检查编译器输出。
legacy = b'MVMP'+bytes([1,1,1,0,0,0,0,0,0,22,64,1])+struct.pack('<Q',73)
malformed_checks = ['uint32_t ok; uint64_t unused = 0;']
malformed_checks += ['const uint8_t legacy[] = {'+','.join(map(str,legacy))+'};',
    'if (mocika_vmp_exec_i64(legacy,sizeof(legacy),&unused,0,&ok)!=73 || !ok) return 2;',
    'for (unsigned n=0;n<sizeof(legacy);n++) {ok=1; mocika_vmp_exec_i64(legacy,n,&unused,0,&ok); if(ok) return 3;}']
for index,(value,expected) in enumerate([(1.75,1),(-128.9,128),(128.0,None),(float('nan'),None),(float('inf'),None)]):
    program = b'MVMP'+bytes([1,1,1,0,0,0,0,0,0,35,0,0,64,8,1])+struct.pack('<d',value)+bytes([22,8,0,0,0])
    malformed_checks += ['const uint8_t cast'+str(index)+'[] = {'+','.join(map(str,program))+'};',
        'uint64_t result'+str(index)+' = mocika_vmp_exec_i64(cast'+str(index)+',sizeof(cast'+str(index)+'),&unused,0,&ok);',
        'if ('+('ok' if expected is None else '!ok || result'+str(index)+' != '+str(expected))+') return 4;']
runner = work/'runner.c'
runner.write_text('''#include "mocika_native_vmp.h"
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
static uint32_t bits32(float v) {uint32_t b; memcpy(&b,&v,4);return b;}
static uint64_t bits64(double v) {uint64_t b; memcpy(&b,&v,8);return b;}
static int equal32(float a,float b) {return (isnan(a)&&isnan(b)) || bits32(a)==bits32(b);}
static int equal64(double a,double b) {return (isnan(a)&&isnan(b)) || bits64(a)==bits64(b);}
#define CHECK(c,n) do { calls++; if(!(c)){fprintf(stderr,"failed %s i=%u j=%u\\n",n,i,j);return 1;} } while(0)
'''+ '\n'.join(prototypes)+'''
int main(void) {
'''+ '\n'.join(malformed_checks)+'''
  uint64_t values[] = {0,0x8000000000000000ULL,0x3ff0000000000000ULL,0xbff0000000000000ULL,0x7ff0000000000000ULL,0xfff0000000000000ULL,0x7ff8000000000073ULL,0x7ff0000000000073ULL,1,0x0010000000000000ULL,0x7fefffffffffffffULL};
  uint32_t floats[] = {0,0x80000000U,0x3f800000U,0xbf800000U,0x7f800000U,0xff800000U,0x7fc00073U,0x7f800073U,1,0x00800000U,0x7f7fffffU};
  uint64_t integers[] = {0,1,2,17,73,127,128,0x7fffffffULL,0x80000000ULL,0x7fffffffffffffffULL,0x8000000000000000ULL,UINT64_MAX,UINT64_MAX-1,UINT64_MAX-2,74,18};
  errno=73; (void)vmp_f32_fma(INFINITY,0.0f); if(errno!=73) return 5;
  errno=73; (void)vmp_f64_fmuladd(INFINITY,0.0); if(errno!=73) return 5;
  uint64_t state=0x62a9d9ed799705f5ULL, calls=0;
  for(unsigned i=0;i<128;i++) for(unsigned j=0;j<128;j++) {
    state^=state<<13;state^=state>>7;state^=state<<17;
    uint64_t ai=i<11?values[i]:state, bi=j<11?values[j]:state*73;
    uint32_t fi=i<11?floats[i]:(uint32_t)(state>>32), fj=j<11?floats[j]:(uint32_t)state;
    double ad,bd; float af,bf; memcpy(&ad,&ai,8);memcpy(&bd,&bi,8);memcpy(&af,&fi,4);memcpy(&bf,&fj,4);
'''+ '\n'.join(checks)+'''
  }
  printf("NATIVE_SCALARS_OK methods=%u comparisons=%llu\\n", '''+str(len(annotations))+''', (unsigned long long)calls);
  return 0;
}
''')
obj = work/'scalars.o'
run([args.cc or str(llvm/'clang'), '-O2', '-ffp-contract=off', '-c', work/'scalar-check-A.ll', '-o', obj])
exe = work/'scalars-check'
compile_args = [cc, '-O2', '-ffp-contract=off', '-I'+str(root/'include'), runner, obj, root/'runtime/mocika_native_vmp.c', '-lm', '-o', exe]
if not args.cc: compile_args += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
run(compile_args)
runtime_ir = work/'runtime.ll'
run([cc, '-O2', '-I'+str(root/'include'), '-S', '-emit-llvm', root/'runtime/mocika_native_vmp.c', '-o', runtime_ir])
assert 'store volatile i64 0' in runtime_ir.read_text(), '优化后缺少寄存器擦除'
env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0', UBSAN_OPTIONS='halt_on_error=1')
device_info = None
if args.serial:
    adb = ['adb', '-s', args.serial]; remote = '/data/local/tmp/mocika-scalars-'+uuid.uuid4().hex
    try:
        run(adb+['push', exe, remote])
        uploaded = subprocess.check_output(adb+['exec-out', 'cat', remote], timeout=30)
        assert hashlib.sha256(uploaded).digest() == hashlib.sha256(exe.read_bytes()).digest(), '设备探针与本地构建不一致'
        run(adb+['shell','chmod','700',remote]); transcript = run(adb+['shell',remote])
        device_info = {key: run(adb+['shell', 'getprop', key]).strip()
                       for key in ('ro.product.model', 'ro.build.version.sdk', 'ro.product.cpu.abilist', 'ro.build.fingerprint')}
        device_info['page_size'] = run(adb+['shell', 'getconf', 'PAGESIZE']).strip()
    finally: run(adb+['shell','rm','-f',remote])
else: transcript = run([exe], env=env)
assert 'NATIVE_SCALARS_OK' in transcript
result = dict(methods=len(annotations), comparisons=len(checks)*128*128, transcript=transcript.strip(),
              opcodes=sorted(opcode_set), recovery='public_seed_reusable_decoder_succeeds',
              binary_sha256=hashlib.sha256(exe.read_bytes()).hexdigest(), device=args.serial, target=triple,
              source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(), legacy_and_invalid_inputs='passed', volatile_wipe_ir='present',
              device_info=device_info, narrow_integer_abi=abi, inputs_sha256={str(path.relative_to(root)) if path.is_relative_to(root) else str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in (root/'tests/check-scalars.py', root/'runtime/mocika_native_vmp.c', root/'include/mocika_native_vmp.h', Path(args.plugin).resolve(), runner)})
(work/'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
print(transcript.strip())
print('两次构建均可由公开信息恢复规范化程序；位置编码不计为抗静态恢复通过。')
