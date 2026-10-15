//! 核验可信本地 Native 构建记录，并追踪 PSO2 与最终归档；不把链接通过写成设备执行通过。
use crate::protection_report::{file_sha256, sha256};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

const LIBRARY_LIMIT: u64 = 512 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct NativeRecord {
    pub entry: String,
    pub input_sha256: String,
    pub output_sha256: String,
    pub postprocess: String,
    pub key_table_sha256: Option<String>,
    evidence_sha256: String,
    evidence: Value,
}

impl NativeRecord {
    pub(crate) fn function_count(&self) -> usize {
        self.evidence["functions"].as_array().map_or(0, Vec::len)
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct NativeTransition {
    pub input_sha256: String,
    pub output_sha256: String,
    pub roundtrip_verified: bool,
}

fn bounded_read(reader: impl Read, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "Native 证据或库超过读取预算");
    Ok(bytes)
}

fn word(bytes: &[u8], offset: usize, width: usize) -> Result<u64> {
    let part = bytes
        .get(offset..offset.checked_add(width).context("ELF 偏移溢出")?)
        .context("ELF 头部截断")?;
    let mut number = [0u8; 8];
    number[..width].copy_from_slice(part);
    Ok(u64::from_le_bytes(number))
}

/// 与 SDK schema 2 一致：规范化 ELF 头、原始程序头表、各 PT_LOAD 摘要依次参与 SHA-256。
fn load_fingerprint(bytes: &[u8]) -> Result<String> {
    ensure!(
        bytes.get(..4) == Some(b"\x7fELF") && bytes.get(5) == Some(&1),
        "需要小端 ELF"
    );
    let (header_size, phoff_at, width, phsize_at, phcount_at, expected_phsize, shoff_at, shmeta_at) =
        match bytes.get(4) {
            Some(1) => (52, 28, 4, 42, 44, 32, 32, 46),
            Some(2) => (64, 32, 8, 54, 56, 56, 40, 58),
            _ => anyhow::bail!("ELF 位数无效"),
        };
    let mut header = bytes.get(..header_size).context("ELF 头部截断")?.to_vec();
    header[shoff_at..shoff_at + width].fill(0);
    header[shmeta_at..shmeta_at + 6].fill(0);
    let start = usize::try_from(word(bytes, phoff_at, width)?)?;
    let size = usize::try_from(word(bytes, phsize_at, 2)?)?;
    let count = usize::try_from(word(bytes, phcount_at, 2)?)?;
    ensure!(
        size == expected_phsize && count > 0 && count < 65535 && start >= header_size,
        "ELF 程序头表无效"
    );
    let end = start
        .checked_add(size.checked_mul(count).context("ELF 表大小溢出")?)
        .context("ELF 表范围溢出")?;
    let table = bytes.get(start..end).context("ELF 程序头表越界")?;
    let mut digest = Sha256::new();
    digest.update(&header);
    digest.update(table);
    let mut loads = 0;
    for ph in table.chunks_exact(size) {
        if word(ph, 0, 4)? != 1 {
            continue;
        }
        let offset = usize::try_from(word(ph, if width == 8 { 8 } else { 4 }, width)?)?;
        let length = usize::try_from(word(ph, if width == 8 { 32 } else { 16 }, width)?)?;
        let end = offset.checked_add(length).context("ELF 加载段范围溢出")?;
        let segment = bytes.get(offset..end).context("ELF 加载段越界")?;
        let mut loaded = Sha256::new();
        if offset < header_size {
            let prefix_end = end.min(header_size);
            loaded.update(&header[offset..prefix_end]);
            loaded.update(&segment[prefix_end - offset..]);
        } else {
            loaded.update(segment);
        }
        digest.update(loaded.finalize());
        loads += 1;
    }
    ensure!(loads > 0, "ELF 没有加载段");
    Ok(format!("{:x}", digest.finalize()))
}

fn validate_entry(entry: &str) -> Result<(&str, &str, &str)> {
    let parts = entry.split('/').collect::<Vec<_>>();
    ensure!(
        parts.len() == 4 && parts[1] == "lib",
        "Native 条目必须为 模块/lib/ABI/库名.so"
    );
    ensure!(
        !parts[0].is_empty()
            && parts[0]
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_'),
        "Native 模块名无效"
    );
    ensure!(
        matches!(parts[2], "arm64-v8a" | "armeabi-v7a" | "x86" | "x86_64"),
        "Native ABI 不受支持"
    );
    ensure!(
        parts[3].starts_with("lib")
            && parts[3].ends_with(".so")
            && parts[3]
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._+-".contains(&c)),
        "Native 库名无效"
    );
    Ok((parts[0], parts[2], parts[3]))
}

fn zip_library(archive: &mut zip::ZipArchive<File>, name: &str) -> Result<Vec<u8>> {
    ensure!(
        archive.file_names().filter(|n| *n == name).count() == 1,
        "Native 归档条目缺失或重复：{name}"
    );
    let entry = archive.by_name(name)?;
    ensure!(entry.size() <= LIBRARY_LIMIT, "Native 库超过 512 MiB");
    bounded_read(entry, LIBRARY_LIMIT)
}

fn workspace_library(
    entry: &str,
    apk: &Path,
    external: Option<&Path>,
) -> Result<std::path::PathBuf> {
    let (module, _, _) = validate_entry(entry)?;
    Ok(if module == "base" {
        apk.join(entry.strip_prefix("base/").unwrap())
    } else {
        external
            .context("APK 不支持非 base 模块 Native 证据")?
            .join(entry)
    })
}

pub(crate) fn load_evidence(
    list: Option<&Path>,
    input: &Path,
    external: Option<&Path>,
    excluded: &[String],
) -> Result<Vec<NativeRecord>> {
    let Some(list) = list else {
        return Ok(Vec::new());
    };
    let text = String::from_utf8(bounded_read(
        File::open(list).context("读取 Native 证据清单失败")?,
        1024 * 1024,
    )?)?;
    let mut archive = crate::protection_report::checked_archive(input)?;
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();
    let mut report_bytes = 0;
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let (entry, report) = line
            .split_once('\t')
            .context("Native 证据清单需要 条目<TAB>报告路径")?;
        let (module, abi, library) = validate_entry(entry)?;
        ensure!(
            !excluded.iter().any(|value| value == abi),
            "不能排除必验 Native 库的 ABI：{abi}"
        );
        ensure!(
            seen.insert(entry.to_owned()) && seen.len() <= 1024,
            "Native 证据条目重复或超过预算"
        );
        let report_path = list.parent().unwrap_or(Path::new(".")).join(report);
        let receipt = bounded_read(
            File::open(report_path).context("读取 Native 构建报告失败")?,
            16 * 1024 * 1024,
        )?;
        report_bytes += receipt.len();
        ensure!(
            report_bytes <= 64 * 1024 * 1024,
            "Native 构建报告总量超过 64 MiB"
        );
        let evidence: Value = serde_json::from_slice(&receipt)?;
        ensure!(
            evidence["schema_version"] == 2
                && evidence["status"] == "linked_verified"
                && evidence["execution"] == "not_recorded",
            "需要 Native SDK schema 2 链接报告，请重新生成构建证据"
        );
        ensure!(
            evidence["library"] == library,
            "Native 证据库名不匹配：{entry}"
        );
        let functions = evidence["functions"]
            .as_array()
            .context("Native 证据缺少函数列表")?;
        ensure!(
            !functions.is_empty()
                && functions
                    .iter()
                    .all(|f| f["linked_dispatch_verified"] == true
                        && f["symbol"].as_str().is_some_and(|s| !s.is_empty())),
            "Native 函数未全部通过链接核验"
        );
        let bytes = if module == "base" {
            zip_library(&mut archive, entry.strip_prefix("base/").unwrap())?
        } else {
            bounded_read(
                File::open(workspace_library(entry, Path::new(""), external)?)?,
                LIBRARY_LIMIT,
            )?
        };
        let (class, machine) = match abi {
            "arm64-v8a" => (2, 183),
            "armeabi-v7a" => (1, 40),
            "x86" => (1, 3),
            _ => (2, 62),
        };
        ensure!(
            bytes.get(4) == Some(&class)
                && word(&bytes, 18, 2)? == machine
                && evidence["elf_class"] == class
                && evidence["machine"] == machine,
            "Native 证据 ABI 不匹配：{entry}"
        );
        let fingerprint = load_fingerprint(&bytes)?;
        ensure!(
            evidence["load_image"]["sha256"].as_str() == Some(&fingerprint),
            "Native 输入库与构建证据不一致：{entry}"
        );
        records.push(NativeRecord {
            entry: entry.into(),
            input_sha256: sha256(&bytes),
            output_sha256: String::new(),
            postprocess: "unchanged".into(),
            key_table_sha256: None,
            evidence_sha256: sha256(&receipt),
            evidence,
        });
    }
    ensure!(!records.is_empty(), "Native 证据清单为空");
    Ok(records)
}

pub(crate) fn capture_outputs(
    records: &mut [NativeRecord],
    apk: &Path,
    external: Option<&Path>,
    transitions: &BTreeMap<String, NativeTransition>,
) -> Result<()> {
    for row in records {
        row.output_sha256 = file_sha256(&workspace_library(&row.entry, apk, external)?)?;
        if row.output_sha256 == row.input_sha256 {
            continue;
        }
        let key = row.entry.split_once("/lib/").unwrap().1;
        let transition = transitions
            .get(key)
            .context("Native 库被改写但没有 PSO2 还原核验记录")?;
        ensure!(
            transition.roundtrip_verified
                && transition.input_sha256 == row.input_sha256
                && transition.output_sha256 == row.output_sha256,
            "Native PSO2 输入/输出链路不一致：{}",
            row.entry
        );
        row.postprocess = "pso2_roundtrip_verified".into();
        row.key_table_sha256 = Some(file_sha256(
            &apk.join("assets/protector/mocika-sokeys.bin"),
        )?);
    }
    Ok(())
}

pub(crate) fn verify_packaged(records: &[NativeRecord], artifact: &Path, aab: bool) -> Result<()> {
    if records.is_empty() {
        return Ok(());
    }
    let mut archive = crate::protection_report::checked_archive(artifact)?;
    for row in records {
        validate_entry(&row.entry)?;
        if let Some(expected) = &row.key_table_sha256 {
            let entry = if aab {
                "base/assets/protector/mocika-sokeys.bin"
            } else {
                "assets/protector/mocika-sokeys.bin"
            };
            ensure!(
                &sha256(&zip_library(&mut archive, entry)?) == expected,
                "PSO2 认证密钥表在打包或签名期间改变"
            );
        }
        let name = if aab {
            row.entry.as_str()
        } else if let Some(name) = row.entry.strip_prefix("base/") {
            name
        } else {
            continue;
        };
        ensure!(
            sha256(&zip_library(&mut archive, name)?) == row.output_sha256,
            "最终安装包 Native 库与验证产物不一致：{name}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn elf(class: u8, machine: u16) -> Vec<u8> {
        let (header, ph, phoff, phsize, phcount, width) = if class == 2 {
            (64, 56, 32, 54, 56, 8)
        } else {
            (52, 32, 28, 42, 44, 4)
        };
        let mut bytes = vec![0u8; header + ph + 16];
        bytes[..6].copy_from_slice(&[127, b'E', b'L', b'F', class, 1]);
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[phoff..phoff + width].copy_from_slice(&(header as u64).to_le_bytes()[..width]);
        bytes[phsize..phsize + 2].copy_from_slice(&(ph as u16).to_le_bytes());
        bytes[phcount..phcount + 2].copy_from_slice(&1u16.to_le_bytes());
        bytes[header..header + 4].copy_from_slice(&1u32.to_le_bytes());
        let size_at = header + if class == 2 { 32 } else { 16 };
        let size = bytes.len() as u64;
        bytes[size_at..size_at + width].copy_from_slice(&size.to_le_bytes()[..width]);
        bytes
    }

    fn zip(path: &Path, entries: &[(&str, &[u8])]) {
        let mut archive = zip::ZipWriter::new(File::create(path).unwrap());
        for (name, bytes) in entries {
            archive
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            archive.write_all(bytes).unwrap();
        }
        archive.finish().unwrap();
    }

    #[test]
    fn 四种架构输入证据与最终库绑定() {
        for (abi, class, machine) in [
            ("arm64-v8a", 2, 183),
            ("armeabi-v7a", 1, 40),
            ("x86", 1, 3),
            ("x86_64", 2, 62),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let bytes = elf(class, machine);
            let fingerprint = load_fingerprint(&bytes).unwrap();
            let mut stripped = bytes.clone();
            stripped[if class == 2 { 40 } else { 32 }] = 0x55;
            assert_eq!(load_fingerprint(&stripped).unwrap(), fingerprint);
            let mut altered = bytes.clone();
            altered[24] ^= 1;
            assert_ne!(load_fingerprint(&altered).unwrap(), fingerprint);
            for end in 0..bytes.len() {
                assert!(load_fingerprint(&bytes[..end]).is_err());
            }
            let library = format!("lib/{abi}/libsample.so");
            let entry = format!("base/{library}");
            let report = serde_json::json!({"schema_version":2,"library":"libsample.so", "elf_class":class, "machine":machine,
                "status":"linked_verified","execution":"not_recorded", "load_image":{"sha256":fingerprint},
                "functions":[{"symbol":"sample","linked_dispatch_verified":true}]});
            fs::write(dir.path().join("build.json"), report.to_string()).unwrap();
            let list = dir.path().join("evidence.tsv");
            fs::write(&list, format!("{entry}\tbuild.json\n")).unwrap();
            let apk = dir.path().join("input.apk");
            zip(&apk, &[(&library, &stripped)]);
            let mut records = load_evidence(Some(&list), &apk, None, &[]).unwrap();
            assert_eq!(records.len(), 1);
            assert!(load_evidence(Some(&list), &apk, None, &[abi.into()]).is_err());
            assert!(verify_packaged(&records, &apk, false).is_err());
            let plain = dir.path().join("workspace");
            fs::create_dir_all(plain.join(format!("lib/{abi}"))).unwrap();
            fs::write(plain.join(&library), &stripped).unwrap();
            capture_outputs(&mut records, &plain, None, &BTreeMap::new()).unwrap();
            verify_packaged(&records, &apk, false).unwrap();
            let aab = dir.path().join("output.aab");
            zip(&aab, &[(&entry, &stripped)]);
            verify_packaged(&records, &aab, true).unwrap();
            zip(&aab, &[(&entry, &altered)]);
            assert!(verify_packaged(&records, &aab, true).is_err());
            fs::write(plain.join(&library), &altered).unwrap();
            assert!(capture_outputs(&mut records, &plain, None, &BTreeMap::new()).is_err());
            let transitions = BTreeMap::from([(
                format!("{abi}/libsample.so"),
                NativeTransition {
                    input_sha256: sha256(&stripped),
                    output_sha256: sha256(&altered),
                    roundtrip_verified: true,
                },
            )]);
            fs::create_dir_all(plain.join("assets/protector")).unwrap();
            fs::write(
                plain.join("assets/protector/mocika-sokeys.bin"),
                b"test-key-table",
            )
            .unwrap();
            capture_outputs(&mut records, &plain, None, &transitions).unwrap();
            assert_eq!(records[0].postprocess, "pso2_roundtrip_verified");
            assert!(verify_packaged(&records, &aab, true).is_err());
            zip(
                &aab,
                &[
                    (&entry, &altered),
                    ("base/assets/protector/mocika-sokeys.bin", b"test-key-table"),
                ],
            );
            verify_packaged(&records, &aab, true).unwrap();
            zip(&apk, &[(&library, &altered)]);
            assert!(load_evidence(Some(&list), &apk, None, &[]).is_err());
            for bad in [
                "../lib/arm64-v8a/libsample.so\tbuild.json",
                "base/lib/mips/libsample.so\tbuild.json",
                "",
                "base/lib/arm64-v8a/libsample.so build.json",
            ] {
                fs::write(&list, bad).unwrap();
                assert!(load_evidence(Some(&list), &apk, None, &[]).is_err());
            }
        }
    }

    #[test]
    fn 中央目录重复条目不能被索引去重掩盖() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("duplicate.apk");
        zip(&path, &[("one.so", b"first"), ("two.so", b"second")]);
        let mut data = fs::read(&path).unwrap();
        for at in 0..data.len() - 6 {
            if &data[at..at + 6] == b"two.so" {
                data[at..at + 6].copy_from_slice(b"one.so");
            }
        }
        fs::write(&path, data).unwrap();
        assert_eq!(
            zip::ZipArchive::new(File::open(&path).unwrap())
                .unwrap()
                .len(),
            1
        );
        assert!(crate::protection_report::checked_archive(&path).is_err());
        assert!(crate::runtime_ui::apk_index(&path).is_err());
    }
}
