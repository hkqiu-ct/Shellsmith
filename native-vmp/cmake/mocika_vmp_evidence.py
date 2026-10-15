#!/usr/bin/env python3
"""将编译记录绑定到已链接 ELF，并核验剥离符号后的库或 APK/AAB 内条目。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inspect(path, readobj):
    if Path(path).stat().st_size > 512*1024*1024: raise ValueError('库超过 512 MiB 核验预算')
    data = Path(path).read_bytes()
    if data[:6] not in (b'\x7fELF\x01\x01', b'\x7fELF\x02\x01'):
        raise ValueError('只支持小端 ELF32/ELF64')
    info = json.loads(subprocess.check_output([readobj, '--elf-output-style=JSON', '--file-headers', '--program-headers', '--sections', '--symbols', str(path)], text=True))[0]
    sections = {}
    for row in info['Sections']:
        s = row['Section']
        if not s['Flags']['Value'] & 2: continue
        name = s['Name']['Name']
        if name in sections: raise ValueError('ELF 可加载节名称重复')
        start, size = s['Offset'], s['Size']
        nobits = s['Type']['Value'] == 8
        if not nobits and (start < 0 or size < 0 or start + size > len(data)):
            raise ValueError('ELF 节范围超出文件')
        sections[name] = dict(address=s['Address'], size=size, flags=s['Flags']['Value'],
                              type=s['Type']['Value'], sha256=None if nobits else sha(data[start:start+size]))
    if not sections: raise ValueError('ELF 没有可加载节')
    # strip 可以删除非加载节，只忽略对应的节表位置/数量；加载头、段权限和段间字节仍须一致。
    header = bytearray(data[:64 if data[4] == 2 else 52])
    for start, end in ((40, 48), (58, 64)) if data[4] == 2 else ((32, 36), (46, 52)):
        header[start:end] = bytes(end-start)
    segments = []
    for row in info['ProgramHeaders']:
        segment = row['ProgramHeader']
        if segment['Type']['Value'] != 1: continue
        start, size = segment['Offset'], segment['FileSize']
        end = start+size
        if start < 0 or size < 0 or end > len(data): raise ValueError('ELF 加载段超出文件')
        digest = hashlib.sha256()
        digest.update(header[start:min(end, len(header))])
        digest.update(data[max(start, len(header)):end])
        segments.append(digest.hexdigest())
    if not segments: raise ValueError('ELF 没有加载段')
    elf = info['ElfHeader']
    start = elf['ProgramHeaderOffset']
    end = start + elf['ProgramHeaderEntrySize']*elf['ProgramHeaderCount']
    if start < len(header) or end > len(data): raise ValueError('ELF 程序头表越界')
    # 可移植摘要供桌面核心核验，不依赖 LLVM JSON 的展示格式。
    fingerprint = hashlib.sha256(header)
    fingerprint.update(data[start:end])
    for digest in segments: fingerprint.update(bytes.fromhex(digest))
    image = dict(header_sha256=sha(header), program_headers=info['ProgramHeaders'], segments_sha256=segments,
                 sha256=fingerprint.hexdigest())
    return data, info, sections, image


def seal(args):
    library = Path(args.library).resolve()
    data, info, sections, image = inspect(library, args.readobj)
    source_dir = Path(args.source_dir)
    plugin_sha = sha(Path(args.plugin).read_bytes())
    launcher_sha = sha(Path(__file__).with_name('mocika_vmp_launcher.py').read_bytes())
    sources = {(source_dir / name).resolve() for name in Path(args.sources).read_text().splitlines()
               if Path(name).suffix.lower() in ('.c', '.cc', '.cpp', '.cxx', '.m', '.mm')}
    receipts = {}
    for path in Path(args.objects).rglob('*.mocika-vmp.json'):
        r = json.loads(path.read_text())
        source = Path(r['source']).resolve()
        if source not in sources: continue
        if source in receipts: raise ValueError('同一源文件存在多个编译记录')
        if r.get('plugin_sha256') != plugin_sha or r.get('launcher_sha256') != launcher_sha:
            raise ValueError('编译记录来自旧版 Pass 或启动器，请清理构建目录后重建')
        if r['schema_version'] != 1 or sha(Path(r['object']).read_bytes()) != r['object_sha256']:
            raise ValueError('对象文件与编译记录不匹配')
        if sha(source.read_bytes()) != r['source_sha256']: raise ValueError('源码在编译后已改变')
        receipts[source] = r
    if set(receipts) != sources: raise ValueError('目标缺少完整编译记录，请清理构建目录后重建')
    functions = []
    vmp_sections = [s['Section'] for s in info['Sections'] if s['Section']['Name']['Name'] == '.mocika.vmp']
    if len(vmp_sections) != 1 or '.mocika.vmp' not in sections: raise ValueError('ELF 未包含唯一可加载 Native VMP 字节码节')
    section = vmp_sections[0]
    program_data = data[section['Offset']:section['Offset']+section['Size']]
    symbols = [s['Symbol'] for s in info['Symbols']]
    for receipt in receipts.values():
        for function in receipt['functions']:
            name, length = function['symbol'], function['program_bytes']
            candidates = [s for s in symbols if s['Name']['Name'] == name and s['Type']['Value'] == 2 and s['Size'] > 0]
            if len(candidates) != 1: raise ValueError('已标注函数在最终 ELF 中缺失或重名：'+name)
            symbol = candidates[0]
            matches = []
            offset = program_data.find(b'MVMP')
            while offset >= 0:
                if length >= 10 and offset+length <= len(program_data) and sha(program_data[offset:offset+length]) == function['program_sha256']:
                    matches.append(section['Address']+offset)
                offset = program_data.find(b'MVMP', offset+1)
            if not matches: raise ValueError('最终 ELF 缺少对应虚拟字节码：'+name)
            # 审计真实链接后的函数，不能只凭字节码节的存在宣布原体已替换。
            disassembly = subprocess.check_output([args.objdump, '-d', '--no-show-raw-insn', '--disassemble-symbols='+name, str(library)], text=True)
            if not re.search(r'\b(?:blx?|call[ql]?)\s+[^\n]*<mocika_vmp_exec_i64(?:@plt)?>', disassembly):
                raise ValueError('最终函数没有可核验的解释器直接调用：'+name)
            functions.append(dict(function, source=receipt['source'], wrapper_address=symbol['Value'],
                                  wrapper_bytes=symbol['Size'], program_addresses=matches,
                                  linked_dispatch_verified=True))
    if not functions: raise ValueError('没有实际转换并链接的 Native VMP 函数')
    report = dict(schema_version=2, status='linked_verified', execution='not_recorded',
                  library=library.name, library_sha256=sha(data), machine=info['ElfHeader']['Machine']['Value'],
                  elf_class=data[4], load_sections=sections, load_image=image, functions=functions,
                  compilation=list(receipts.values()))
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=destination.parent, delete=False) as temp:
        temporary = Path(temp.name)
        json.dump(report, temp, ensure_ascii=False, indent=2); temp.write('\n')
    try: temporary.replace(destination)
    finally: temporary.unlink(missing_ok=True)
    print('Native VMP 链接核验通过：'+str(destination))


def verify(args):
    if Path(args.report).stat().st_size > 16*1024*1024: raise ValueError('报告超过 16 MiB 核验预算')
    report = json.loads(Path(args.report).read_text())
    if report['schema_version'] != 2 or report['status'] != 'linked_verified' or report['execution'] != 'not_recorded' or not report['functions']:
        raise ValueError('Native VMP 链接证据不完整')
    with tempfile.TemporaryDirectory(prefix='native-vmp-verify-') as directory:
        library = args.library
        if args.archive:
            if not args.entry: raise ValueError('归档核验必须指定完整 --entry')
            with zipfile.ZipFile(args.archive) as archive:
                matches = [entry for entry in archive.infolist() if entry.filename == args.entry]
                if len(matches) != 1: raise ValueError('归档库条目缺失或重复')
                if matches[0].file_size > 512*1024*1024: raise ValueError('库超过 512 MiB 核验预算')
                library = Path(directory)/'library.so'
                library.write_bytes(archive.read(matches[0]))
        if not library: raise ValueError('必须指定库或归档')
        data, info, sections, image = inspect(library, args.readobj)
        if info['ElfHeader']['Machine']['Value'] != report['machine'] or data[4] != report['elf_class'] or sections != report['load_sections'] or image != report['load_image']:
            raise ValueError('最终库的 ABI、可加载节或代码与链接证据不一致')
        print(json.dumps(dict(status='verified', library_sha256=sha(data),
                              functions=len(report['functions']), execution=report['execution']), ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('seal')
    for flag in ('library', 'sources', 'source-dir', 'objects', 'output', 'readobj', 'objdump', 'plugin'):
        build.add_argument('--'+flag, required=True)
    check = commands.add_parser('verify')
    check.add_argument('--report', required=True)
    check.add_argument('--readobj', required=True)
    inputs = check.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--library'); inputs.add_argument('--archive')
    check.add_argument('--entry')
    args = parser.parse_args()
    (seal if args.command == 'seal' else verify)(args)


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        sys.exit('Native VMP 证据核验失败：'+str(error))
