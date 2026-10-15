#!/usr/bin/env python3
"""真实工具链检查：响应文件、优化顺序、失败保留对象、ELF/归档绑定。"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import zipfile

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--plugin', required=True)
parser.add_argument('--llvm-bin', required=True)
parser.add_argument('--library')
parser.add_argument('--report')
args = parser.parse_args()
suffix = '.exe' if os.name == 'nt' else ''
llvm = Path(args.llvm_bin)
launcher = [sys.executable, str(root/'cmake/mocika_vmp_launcher.py'), '--opt', str(llvm/('opt'+suffix)), '--plugin', args.plugin, '--']
evidence = [sys.executable, str(root/'cmake/mocika_vmp_evidence.py'), 'verify', '--readobj', str(llvm/('llvm-readobj'+suffix))]


def run(command, success=True):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if (result.returncode == 0) != success: raise AssertionError(result.stdout)
    return result


def rsp(path, arguments):
    path.write_text(subprocess.list2cmdline(arguments) if os.name == 'nt' else shlex.join(arguments))


with tempfile.TemporaryDirectory(prefix='native vmp check ') as directory:
    work = Path(directory)
    source, output = work/'source with space.c', work/'protected.o'
    header = work/'included helper.c'; header.write_text('#define VALUE 73\n')
    source.write_text('#include "mocika_native_vmp.h"\nMOCIKA_VMP int fixed_value(void) { return VALUE; }\nint call_fixed(void) { return fixed_value(); }\n'
                      'MOCIKA_VMP unsigned char dispatch(unsigned char kind, unsigned char value) {\n'
                      '  switch(kind) { case 0: value ^= 73; break; case 1: case 17: value += 5; break;\n'
                      '    case 255: value *= 13; break; default: value -= 7; } return value; }\n'
                      'MOCIKA_VMP int bounded(int x) { int low=x < -17 ? -17 : x; return low > 73 ? 73 : low; }\n')
    command = ['-O2', '-I', str(root/'include'), '-include', str(header), '-x', 'c', '-MMD', '-MF', str(work/'dependency.d'), '-c', str(source), '-o', str(output)]
    nested, outer = work/'nested.rsp', work/'outer.rsp'
    rsp(nested, command); rsp(outer, ['@'+str(nested)])
    run(launcher+[str(llvm/('clang'+suffix)), '@'+str(outer)])
    receipt = Path(str(output)+'.mocika-vmp.json')
    report = json.loads(receipt.read_text())
    assert [f['symbol'] for f in report['functions']] == ['fixed_value', 'dispatch', 'bounded']
    assert report['object_sha256'] == hashlib.sha256(output.read_bytes()).hexdigest()
    assert str(output.resolve()).replace(' ', '\\ ') in (work/'dependency.d').read_text()
    assert str(Path(args.plugin).resolve()).replace(' ', '\\ ') in (work/'dependency.d').read_text()
    assert str(root/'cmake/mocika_vmp_launcher.py').replace(' ', '\\ ') in (work/'dependency.d').read_text()
    # 临时 bitcode 目录每次变化，同一源码和固定种子仍须产生同一虚拟程序。
    original_seed = os.environ.get('MOCIKA_VMP_SEED')
    os.environ['MOCIKA_VMP_SEED'] = 'build-contract-check'
    programs = []
    for _ in range(2):
        run(launcher+[str(llvm/('clang'+suffix))]+command)
        programs.append(json.loads(receipt.read_text())['functions'])
    assert programs[0] == programs[1]
    if original_seed is None: del os.environ['MOCIKA_VMP_SEED']
    else: os.environ['MOCIKA_VMP_SEED'] = original_seed
    run(launcher+[str(llvm/('clang'+suffix))]+command+['-xc', '-include'+str(header), '-MF'+str(work/'joined.d')])
    main = work/'main.c'; main.write_text('int call_fixed(void); int bounded(int); unsigned char dispatch(unsigned char, unsigned char);\n'
        'int main(void) { if(call_fixed()!=73) return 1;\n'
        '  for(int x=-128;x<128;x++) if(bounded(x)!=(x < -17 ? -17 : x > 73 ? 73 : x)) return 3;\n'
        '  for(unsigned k=0;k<256;k++) for(unsigned v=0;v<256;v++) {\n'
        '    unsigned char expected=k==0 ? v^73 : (k==1 || k==17) ? v+5 : k==255 ? v*13 : v-7;\n'
        '    if(dispatch(k,v)!=expected) return 2; } return 0; }\n')
    exe = work/('check'+suffix)
    run([str(llvm/('clang'+suffix)), '-O2', '-I', str(root/'include'), str(main), str(output), str(root/'runtime/mocika_native_vmp.c'), *([] if os.name == 'nt' else ['-lm']), '-o', str(exe)])
    run([str(exe)])
    # 调用方不能在转换前得到明文常量；直接加载 Pass 的入口也遵守相同顺序。
    ir = work/'protected.ll'
    run([str(llvm/('clang'+suffix)), '-O2', '-fpass-plugin='+args.plugin, '-I', str(root/'include'), '-include', str(header), '-S', '-emit-llvm', str(source), '-o', str(ir)])
    body = ir.read_text().split('@call_fixed(', 1)[1].split('\n}', 1)[0]
    assert '@fixed_value(' in body and 'ret i32 73' not in body, body
    before = output.read_bytes(), receipt.read_bytes()
    for extra in [['-flto=thin'], ['-emit-llvm'], ['-fpass-plugin='+args.plugin]]:
        run(launcher+[str(llvm/('clang'+suffix))]+command+extra, False)
        assert before == (output.read_bytes(), receipt.read_bytes())
    rsp(outer, ['@'+str(outer)])
    run(launcher+[str(llvm/('clang'+suffix)), '@'+str(outer)], False)
    assert before == (output.read_bytes(), receipt.read_bytes())
    source.write_text('#include "mocika_native_vmp.h"\nMOCIKA_VMP int bad(int *p) { return *p; }\n')
    run(launcher+[str(llvm/('clang'+suffix))]+command, False)
    assert before == (output.read_bytes(), receipt.read_bytes())
    source.write_text('#include "mocika_native_vmp.h"\nMOCIKA_VMP __attribute__((weak)) int weak_value(void) { return 1; }\n')
    run(launcher+[str(llvm/('clang'+suffix))]+command, False)
    assert before == (output.read_bytes(), receipt.read_bytes())
    # 已标注的超出子集语义必须失败，不能把它计入保护覆盖率。
    for body in [
        'MOCIKA_VMP double bad(double x) { return __builtin_sin(x); }',
        'MOCIKA_VMP _Float16 bad(_Float16 x) { return x; }',
        '#pragma STDC FENV_ACCESS ON\nMOCIKA_VMP double bad(double x) { return x + 1; }',
        'typedef float V __attribute__((ext_vector_type(4))); MOCIKA_VMP V bad(V x) { return x; }',
    ]:
        source.write_text('#include "mocika_native_vmp.h"\n'+body+'\n')
        run(launcher+[str(llvm/('clang'+suffix))]+command, False)
        assert before == (output.read_bytes(), receipt.read_bytes())
    # 不同编译单元的同名内部函数不能合并、导出或使证据混淆。
    symbols, objects = [], []
    for index in range(2):
        peer, obj = work/f'peer{index}.c', work/f'peer{index}.o'
        peer.write_text('#include "mocika_native_vmp.h"\n'
                        f'MOCIKA_VMP static int same(int x) {{ return x + {index}; }}\n'
                        f'int peer{index}(int x) {{ return same(x); }}\n')
        run(launcher+[str(llvm/('clang'+suffix)), '-O2', '-I', str(root/'include'), '-c', str(peer), '-o', str(obj)])
        symbols.append(json.loads(Path(str(obj)+'.mocika-vmp.json').read_text())['functions'][0]['symbol'])
        nm = run([str(llvm/('llvm-nm'+suffix)), '--format=posix', str(obj)]).stdout
        assert any(symbols[-1] in line and ' t ' in line for line in nm.splitlines()), nm
        objects.append(str(obj))
    assert symbols[0] != symbols[1]
    main.write_text('int peer0(int); int peer1(int); int main(void) { return peer0(7) != 7 || peer1(7) != 8; }\n')
    run([str(llvm/('clang'+suffix)), '-O2', '-I', str(root/'include'), str(main), *objects, str(root/'runtime/mocika_native_vmp.c'), *([] if os.name == 'nt' else ['-lm']), '-o', str(exe)])
    run([str(exe)])
    # 条件源和接入后追加的源也必须随工具更新重编译，不能只靠最终链接拒绝旧证据。
    sdk, project = work/'sdk', work/'incremental'
    for directory in ('cmake', 'runtime', 'include'):
        shutil.copytree(root/directory, sdk/directory)
    project.mkdir()
    (project/'conditional.c').write_text('#include "mocika_native_vmp.h"\nMOCIKA_VMP int conditional(int x) {return x+73;}\n')
    (project/'later.c').write_text('#include "mocika_native_vmp.h"\nMOCIKA_VMP int later(int x) {return x+17;}\n')
    (project/'main.c').write_text('int conditional(int); int later(int); int main(void) {return conditional(1)!=74 || later(1)!=18;}\n')
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.20)\nproject(Incremental LANGUAGES C)\n'
        f'include("{(sdk/"cmake/MocikaNativeVmp.cmake").as_posix()}")\n'
        'add_executable(probe main.c "$<$<CONFIG:Release>:conditional.c>")\n'
        'if(UNIX AND NOT APPLE)\n  target_link_libraries(probe m)\nendif()\n'
        'mocika_enable_native_vmp(probe PLUGIN "${VMP_PLUGIN}" LLVM_OPT "${VMP_OPT}")\n'
        'target_sources(probe PRIVATE later.c)\n')
    generators = (['Ninja'] if shutil.which('ninja') else []) + (['Unix Makefiles'] if os.name != 'nt' and shutil.which('make') else [])
    assert generators, '增量构建检查需要 Ninja 或 Unix Makefiles'
    cmake = os.environ.get('CMAKE', 'cmake')
    checked_generators = []
    for generator in generators:
        build = project/generator
        legacy_make = generator == 'Unix Makefiles' and re.search(r'GNU Make [123]\.', run(['make', '--version']).stdout)
        run([cmake, '-S', str(project), '-B', str(build), '-G', generator, '-DCMAKE_BUILD_TYPE=Release',
             '-DCMAKE_C_COMPILER='+str(llvm/('clang'+suffix)), '-DVMP_PLUGIN='+str(Path(args.plugin).resolve()), '-DVMP_OPT='+str(llvm/('opt'+suffix))], not legacy_make)
        if legacy_make:
            print('旧 GNU Make 配置被拒绝：不接受会漏掉同秒工具更新的构建')
            continue
        checked_generators.append(generator)
        run([cmake, '--build', str(build)])
        local_launcher = sdk/'cmake/mocika_vmp_launcher.py'
        local_launcher.write_text(local_launcher.read_text()+'\n# 工具升级的等价内容变化\n')
        run([cmake, '--build', str(build)])
        receipts = [json.loads(p.read_text()) for p in build.rglob('*.mocika-vmp.json')]
        assert {'conditional.c', 'later.c', 'main.c'} <= {Path(r['source']).name for r in receipts}
        assert all(r['launcher_sha256'] == hashlib.sha256(local_launcher.read_bytes()).hexdigest() for r in receipts), generator
        run([str(build/('probe'+suffix))])
    assert checked_generators, '需要 Ninja 或 GNU Make 4+ 完成增量构建验证'
    print('增量构建通过：工具内容变化自动重编译条件源与后追加源，生成器 '+', '.join(checked_generators))
    print('编译链通过：嵌套响应文件、空格路径、预包含、显式语言、常量传播阻断、失败保留对象和报告')
    if args.library:
        if not args.report: raise ValueError('--library 需要 --report')
        verify = evidence+['--report', args.report]
        linked = json.loads(Path(args.report).read_text())
        receipts_dir = work/'receipts'; receipts_dir.mkdir()
        source_list = work/'sources.txt'
        source_list.write_text('\n'.join(r['source'] for r in linked['compilation']))
        for index, receipt_row in enumerate(linked['compilation']):
            (receipts_dir/f'{index}.mocika-vmp.json').write_text(json.dumps(receipt_row))
        sealed = work/'sealed.json'
        seal = [sys.executable, str(root/'cmake/mocika_vmp_evidence.py'), 'seal',
                '--readobj', str(llvm/('llvm-readobj'+suffix)), '--objdump', str(llvm/('llvm-objdump'+suffix)),
                '--plugin', args.plugin, '--library', args.library, '--output', str(sealed),
                '--objects', str(receipts_dir), '--sources', str(source_list), '--source-dir', str(work)]
        run(seal)
        before_seal = sealed.read_bytes()
        altered_receipt = dict(linked['compilation'][0], plugin_sha256='0'*64)
        (receipts_dir/'0.mocika-vmp.json').write_text(json.dumps(altered_receipt))
        run(seal, False)
        assert sealed.read_bytes() == before_seal
        (receipts_dir/'0.mocika-vmp.json').unlink()
        run(seal, False)
        assert sealed.read_bytes() == before_seal
        stripped = work/'stripped.so'
        run([str(llvm/('llvm-strip'+suffix)), '--strip-all', args.library, '-o', str(stripped)])
        run(verify+['--library', args.library]); run(verify+['--library', str(stripped)])
        original = stripped.read_bytes()
        # 修改加载入口不改变节内容，但必须被段/ELF 头绑定发现。
        altered = bytearray(original); altered[24] ^= 1
        stripped.write_bytes(altered)
        run(verify+['--library', str(stripped)], False)
        stripped.write_bytes(original)
        archive = work/'sample.aab'
        entry = 'unrelated_module/lib/arm64-v8a/arbitrary.so'
        with zipfile.ZipFile(archive, 'w') as out: out.writestr(entry, stripped.read_bytes())
        run(verify+['--archive', str(archive), '--entry', entry])
        run(verify+['--archive', str(archive), '--entry', 'missing.so'], False)
        readobj = json.loads(run([str(llvm/('llvm-readobj'+suffix)), '--elf-output-style=JSON', '--sections', str(stripped)]).stdout)[0]
        section = next(r['Section'] for r in readobj['Sections'] if r['Section']['Name']['Name'] == '.mocika.vmp')
        altered = bytearray(stripped.read_bytes()); altered[section['Offset']+6] ^= 1
        stripped.write_bytes(altered)
        run(verify+['--library', str(stripped)], False)
        print('最终库核验通过：剥离符号、跨模块归档条目；篡改和错误条目被拒绝')
